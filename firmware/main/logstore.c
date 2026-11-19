// Log-structured record store. See logstore.h for the idea and SPEC 5 for the on-flash format.
#include "logstore.h"

#include <stdlib.h>
#include <string.h>

#define SEG_MAGIC 0x47535754u  // "TWSG"
#define REC_MAGIC 0x31525754u  // "TWR1"
#define FMT_VERSION 1u
#define FLAG_COPY 0x0001u      // written by GC; not a user change

enum { SEG_FREE = 0, SEG_ACTIVE = 1, SEG_SEALED = 2, SEG_DIRTY = 3 };

typedef struct {
    uint32_t magic, seq, time;
    uint8_t kind, op;
    uint16_t flags;
    uint8_t id[16];
    uint32_t len, crc;
} rec_hdr_t;  // 40 bytes on flash, little-endian (both ESP32 and the host test are little-endian)

typedef struct {
    uint32_t magic, seg_seq, version, crc;
} seg_hdr_t;  // 16 bytes

_Static_assert(sizeof(rec_hdr_t) == LS_REC_HDR, "record header size");
_Static_assert(sizeof(seg_hdr_t) == LS_SEG_HDR, "segment header size");

struct ls_store {
    ls_flash_t fl;
    uint32_t nseg;
    uint8_t *state;
    uint32_t *seg_seq, *live, *used;  // used: bytes consumed in the segment (whole segment once sealed)
    int active;
    uint32_t wp;  // write pointer inside the active segment
    ls_entry_t *ent;
    uint32_t nent, cap;
    uint32_t next_seq, next_seg_seq;
    ls_change_t recent[LS_RECENT_N];
    int nrecent;
    uint32_t gc_runs, torn;
    uint8_t *buf;  // LS_SEG_SIZE scratch for assembling and copying records
};

// ---------- small helpers ----------

static uint32_t crc32_update(uint32_t crc, const void *data, size_t len)
{
    static uint32_t table[256];
    static bool init;
    if (!init) {
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (int k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320u ^ (c >> 1) : c >> 1;
            table[i] = c;
        }
        init = true;
    }
    const uint8_t *p = data;
    crc = ~crc;
    while (len--) crc = table[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    return ~crc;
}

static uint32_t rec_crc(const rec_hdr_t *h, const void *payload)
{
    uint32_t c = crc32_update(0, h, offsetof(rec_hdr_t, crc));
    return crc32_update(c, payload, h->len);
}

static uint32_t seg_crc(const seg_hdr_t *h)
{
    return crc32_update(0, h, offsetof(seg_hdr_t, crc));
}

uint32_t ls_record_size(uint32_t len)
{
    return LS_REC_HDR + ((len + 3u) & ~3u);
}

static uint32_t seg_base(uint32_t s)
{
    return s * LS_SEG_SIZE;
}

static uint32_t seg_of(uint32_t off)
{
    return off / LS_SEG_SIZE;
}

static uint32_t capacity(const ls_store_t *ls)
{
    return (ls->nseg - LS_RESERVE_SEGS) * (LS_SEG_SIZE - LS_SEG_HDR);
}

static uint32_t total_live(const ls_store_t *ls)
{
    uint32_t t = 0;
    for (uint32_t s = 0; s < ls->nseg; s++) t += ls->live[s];
    return t;
}

static uint32_t count_free(const ls_store_t *ls)
{
    uint32_t n = 0;
    for (uint32_t s = 0; s < ls->nseg; s++) n += ls->state[s] == SEG_FREE;
    return n;
}

static bool region_erased(ls_store_t *ls, uint32_t off, uint32_t len)
{
    uint8_t tmp[256];
    while (len) {
        uint32_t n = len < sizeof(tmp) ? len : sizeof(tmp);
        if (ls->fl.read(ls->fl.ctx, off, tmp, n)) return false;
        for (uint32_t i = 0; i < n; i++) {
            if (tmp[i] != 0xff) return false;
        }
        off += n;
        len -= n;
    }
    return true;
}

static void push_recent(ls_store_t *ls, const rec_hdr_t *h)
{
    // keep newest first; during mount records arrive in any order
    int pos = ls->nrecent;
    while (pos > 0 && ls->recent[pos - 1].seq < h->seq) pos--;
    if (pos >= LS_RECENT_N) return;
    int last = ls->nrecent < LS_RECENT_N ? ls->nrecent : LS_RECENT_N - 1;
    memmove(&ls->recent[pos + 1], &ls->recent[pos], (size_t)(last - pos) * sizeof(ls_change_t));
    ls->recent[pos] = (ls_change_t){.seq = h->seq, .time = h->time, .kind = h->kind, .op = h->op};
    memcpy(ls->recent[pos].id, h->id, 16);
    if (ls->nrecent < LS_RECENT_N) ls->nrecent++;
}

// ---------- index ----------

static ls_entry_t *find(ls_store_t *ls, uint8_t kind, const uint8_t id[16])
{
    for (uint32_t i = 0; i < ls->nent; i++) {
        ls_entry_t *e = &ls->ent[i];
        if (e->kind == kind && memcmp(e->id, id, 16) == 0) return e;
    }
    return NULL;
}

static ls_entry_t *add_entry(ls_store_t *ls)
{
    if (ls->nent == ls->cap) {
        uint32_t nc = ls->cap ? ls->cap * 2 : 256;
        ls_entry_t *n = realloc(ls->ent, nc * sizeof(ls_entry_t));
        if (!n) return NULL;
        ls->ent = n;
        ls->cap = nc;
    }
    ls_entry_t *e = &ls->ent[ls->nent++];
    memset(e, 0, sizeof(*e));
    return e;
}

static void drop_entry(ls_store_t *ls, ls_entry_t *e)
{
    ls->live[seg_of(e->off)] -= ls_record_size(e->len);
    *e = ls->ent[--ls->nent];
}

// A tombstone is needed only while an older version of its key still exists on flash
static void drop_dead_tombstones(ls_store_t *ls)
{
    for (uint32_t i = 0; i < ls->nent;) {
        ls_entry_t *e = &ls->ent[i];
        if (e->deleted && e->stale == 0) {
            drop_entry(ls, e);  // moves the last entry into slot i
        } else {
            i++;
        }
    }
}

// Applies a record found at mount or just written. Returns false on out of memory.
static bool apply(ls_store_t *ls, uint32_t off, const rec_hdr_t *h)
{
    uint32_t size = ls_record_size(h->len);
    ls_entry_t *e = find(ls, h->kind, h->id);
    if (!e) {
        e = add_entry(ls);
        if (!e) return false;
        e->kind = h->kind;
        memcpy(e->id, h->id, 16);
    } else if (h->seq > e->seq) {
        // The indexed record becomes an old version. Only old puts are counted: they are what a
        // tombstone has to keep hidden. Old tombstones can be dropped at any time.
        if (!e->deleted) e->stale++;
        ls->live[seg_of(e->off)] -= ls_record_size(e->len);
    } else {
        if (h->op == LS_OP_PUT) e->stale++;  // an older version than the one indexed
        return true;
    }
    e->off = off;
    e->len = h->len;
    e->seq = h->seq;
    e->time = h->time;
    e->deleted = h->op == LS_OP_DEL;
    ls->live[seg_of(off)] += size;
    return true;
}

// ---------- segments ----------

static int erase_seg(ls_store_t *ls, uint32_t s)
{
    // Last sector first: if power fails midway, the segment header survives until the very end, so the
    // segment never looks free while it still holds bytes
    for (int k = (int)(LS_SEG_SIZE / LS_SECTOR) - 1; k >= 0; k--) {
        if (ls->fl.erase(ls->fl.ctx, seg_base(s) + (uint32_t)k * LS_SECTOR, LS_SECTOR)) return LS_ERR_IO;
    }
    ls->state[s] = SEG_FREE;
    ls->live[s] = 0;
    ls->used[s] = 0;
    return LS_OK;
}

static void seal(ls_store_t *ls, int s)
{
    if (s < 0) return;
    ls->state[s] = SEG_SEALED;
    ls->used[s] = LS_SEG_SIZE;  // the unwritten tail is waste until GC
    if (ls->active == s) ls->active = -1;
}

static int open_new(ls_store_t *ls)
{
    for (uint32_t s = 0; s < ls->nseg; s++) {
        if (ls->state[s] != SEG_FREE) continue;
        seg_hdr_t h = {.magic = SEG_MAGIC, .seg_seq = ls->next_seg_seq++, .version = FMT_VERSION};
        h.crc = seg_crc(&h);
        if (ls->fl.write(ls->fl.ctx, seg_base(s), &h, sizeof(h))) {
            ls->state[s] = SEG_DIRTY;
            return LS_ERR_IO;
        }
        ls->state[s] = SEG_ACTIVE;
        ls->seg_seq[s] = h.seg_seq;
        ls->live[s] = 0;
        ls->used[s] = LS_SEG_HDR;
        ls->active = (int)s;
        ls->wp = LS_SEG_HDR;
        return LS_OK;
    }
    return LS_ERR_NOSPACE;
}

// Writes ls->buf (header already filled except seq/crc, payload at buf + LS_REC_HDR) at the write pointer.
// The caller guarantees the active segment has room.
static int write_buf(ls_store_t *ls, uint32_t *out_off)
{
    rec_hdr_t *h = (rec_hdr_t *)ls->buf;
    uint32_t size = ls_record_size(h->len);
    memset(ls->buf + LS_REC_HDR + h->len, 0, size - LS_REC_HDR - h->len);  // padding
    h->magic = REC_MAGIC;
    h->seq = ls->next_seq++;
    h->crc = rec_crc(h, ls->buf + LS_REC_HDR);
    uint32_t off = seg_base((uint32_t)ls->active) + ls->wp;
    int err = ls->fl.write(ls->fl.ctx, off, ls->buf, size);
    // Read back: a write that did not take is caught now rather than at the next mount
    uint8_t tmp[256];
    for (uint32_t done = 0; !err && done < size; done += sizeof(tmp)) {
        uint32_t n = size - done < sizeof(tmp) ? size - done : sizeof(tmp);
        err = ls->fl.read(ls->fl.ctx, off + done, tmp, n) || memcmp(tmp, ls->buf + done, n) != 0;
    }
    if (err) {
        seal(ls, ls->active);  // nothing may follow a bad record in a segment
        return LS_ERR_IO;
    }
    ls->wp += size;
    ls->used[ls->active] = ls->wp;
    *out_off = off;
    return LS_OK;
}

static int gc_one(ls_store_t *ls);

// Makes the active segment able to take `size` more bytes, opening segments and collecting garbage
static int ensure_space(ls_store_t *ls, uint32_t size)
{
    for (uint32_t guard = 0; guard < 4 * ls->nseg + 4; guard++) {
        if (ls->active >= 0 && LS_SEG_SIZE - ls->wp >= size) return LS_OK;
        if (count_free(ls) > 1) {  // the last free segment is kept for GC
            seal(ls, ls->active);
            int err = open_new(ls);
            if (err) return err;
            continue;
        }
        int err = gc_one(ls);
        if (err) return err;
    }
    return LS_ERR_NOSPACE;
}

// Moves the live records of the segment with the least live data, then erases it
static int gc_one(ls_store_t *ls)
{
    int victim = -1;
    for (uint32_t s = 0; s < ls->nseg; s++) {
        if (ls->state[s] == SEG_SEALED && (victim < 0 || ls->live[s] < ls->live[victim])) victim = (int)s;
    }
    if (victim < 0) {
        // Only the active segment holds data: seal it so it can be collected next round
        if (ls->active >= 0 && ls->live[ls->active] < ls->used[ls->active] - LS_SEG_HDR && count_free(ls) > 0) {
            seal(ls, ls->active);
            return LS_OK;
        }
        return LS_ERR_NOSPACE;
    }
    uint32_t need = ls->live[victim];
    if (need > 0 && (ls->active < 0 || LS_SEG_SIZE - ls->wp < need)) {
        if (count_free(ls) == 0) return LS_ERR_NOSPACE;
        seal(ls, ls->active);
        int err = open_new(ls);  // may take the reserved segment: the victim's data always fits in one
        if (err) return err;
    }
    // Old puts in the victim are only forgotten after the erase has finished. An erase runs sector by
    // sector, so if power fails midway an old put may survive while a tombstone in a later sector is
    // gone; deciding about tombstones before the erase completes could bring deleted items back.
    typedef struct {
        uint8_t kind, id[16];
    } key_t;
    key_t *old_puts = malloc(sizeof(key_t) * ((LS_SEG_SIZE - LS_SEG_HDR) / LS_REC_HDR));
    if (!old_puts) return LS_ERR_NOMEM;
    uint32_t n_old = 0;
    uint32_t off = LS_SEG_HDR;
    while (off + LS_REC_HDR <= LS_SEG_SIZE) {
        rec_hdr_t h;
        uint32_t abs = seg_base((uint32_t)victim) + off;
        if (ls->fl.read(ls->fl.ctx, abs, &h, sizeof(h))) {
            free(old_puts);
            return LS_ERR_IO;
        }
        if (h.magic != REC_MAGIC || h.len > LS_MAX_PAYLOAD) break;  // end of data (or a torn tail)
        uint32_t size = ls_record_size(h.len);
        ls_entry_t *e = find(ls, h.kind, h.id);
        if (e && e->off == abs) {
            // Newest version: copy it, unless it is a tombstone with no old put left anywhere
            if (e->deleted && e->stale == 0) {
                drop_entry(ls, e);
            } else {
                memcpy(ls->buf, &h, sizeof(h));
                int err = ls->fl.read(ls->fl.ctx, abs + LS_REC_HDR, ls->buf + LS_REC_HDR, h.len) ? LS_ERR_IO
                          : rec_crc(&h, ls->buf + LS_REC_HDR) != h.crc                     ? LS_ERR_IO
                                                                                           : LS_OK;
                rec_hdr_t *nh = (rec_hdr_t *)ls->buf;
                nh->flags |= FLAG_COPY;
                uint32_t noff;
                if (!err) err = write_buf(ls, &noff);
                if (err) {
                    free(old_puts);
                    return err;
                }
                ls->live[victim] -= size;
                ls->live[ls->active] += size;
                e->off = noff;
                e->seq = nh->seq;
            }
        } else if (e && h.op == LS_OP_PUT) {
            old_puts[n_old].kind = h.kind;
            memcpy(old_puts[n_old].id, h.id, 16);
            n_old++;
        }
        off += size;
    }
    int err = erase_seg(ls, (uint32_t)victim);
    if (!err) {
        for (uint32_t i = 0; i < n_old; i++) {
            ls_entry_t *e = find(ls, old_puts[i].kind, old_puts[i].id);
            if (e && e->stale) e->stale--;  // old tombstones are not counted, so only puts come here
        }
        drop_dead_tombstones(ls);
    }
    free(old_puts);
    if (err) return err;
    ls->gc_runs++;
    return LS_OK;
}

static int append(ls_store_t *ls, uint8_t kind, uint8_t op, const uint8_t id[16], const void *data, uint32_t len)
{
    uint32_t size = ls_record_size(len);
    for (int attempt = 0; attempt < 2; attempt++) {
        int err = ensure_space(ls, size);
        if (err) return err;
        rec_hdr_t *h = (rec_hdr_t *)ls->buf;
        memset(h, 0, sizeof(*h));
        h->time = ls->fl.now ? ls->fl.now(ls->fl.ctx) : 0;
        h->kind = kind;
        h->op = op;
        memcpy(h->id, id, 16);
        h->len = len;
        if (len) memcpy(ls->buf + LS_REC_HDR, data, len);
        uint32_t off;
        err = write_buf(ls, &off);
        if (err == LS_ERR_IO) continue;  // segment sealed; try once more in a fresh one
        if (err) return err;
        if (!apply(ls, off, h)) return LS_ERR_NOMEM;
        push_recent(ls, h);
        return LS_OK;
    }
    return LS_ERR_IO;
}

// ---------- public API ----------

static int alloc_store(ls_store_t **out, const ls_flash_t *flash)
{
    if (!flash || flash->size % LS_SEG_SIZE || flash->size / LS_SEG_SIZE <= LS_RESERVE_SEGS + 1) return LS_ERR_ARG;
    ls_store_t *ls = calloc(1, sizeof(*ls));
    if (!ls) return LS_ERR_NOMEM;
    ls->fl = *flash;
    ls->nseg = flash->size / LS_SEG_SIZE;
    ls->state = calloc(ls->nseg, 1);
    ls->seg_seq = calloc(ls->nseg, sizeof(uint32_t));
    ls->live = calloc(ls->nseg, sizeof(uint32_t));
    ls->used = calloc(ls->nseg, sizeof(uint32_t));
    ls->buf = malloc(LS_SEG_SIZE);
    ls->active = -1;
    ls->next_seq = 1;
    ls->next_seg_seq = 1;
    if (!ls->state || !ls->seg_seq || !ls->live || !ls->used || !ls->buf) {
        ls_unmount(ls);
        return LS_ERR_NOMEM;
    }
    *out = ls;
    return LS_OK;
}

void ls_unmount(ls_store_t *ls)
{
    if (!ls) return;
    free(ls->state);
    free(ls->seg_seq);
    free(ls->live);
    free(ls->used);
    free(ls->buf);
    free(ls->ent);
    free(ls);
}

int ls_mount(ls_store_t **out, const ls_flash_t *flash)
{
    ls_store_t *ls;
    int err = alloc_store(&ls, flash);
    if (err) return err;
    uint8_t *sealed_by_tear = calloc(ls->nseg, 1);
    uint32_t *end = calloc(ls->nseg, sizeof(uint32_t));
    if (!sealed_by_tear || !end) {
        free(sealed_by_tear);
        free(end);
        ls_unmount(ls);
        return LS_ERR_NOMEM;
    }
    uint32_t max_seq = 0, max_seg_seq = 0;
    for (uint32_t s = 0; s < ls->nseg && !err; s++) {
        seg_hdr_t sh;
        if (ls->fl.read(ls->fl.ctx, seg_base(s), &sh, sizeof(sh))) {
            err = LS_ERR_IO;
            break;
        }
        if (sh.magic == 0xffffffffu) {
            ls->state[s] = region_erased(ls, seg_base(s), LS_SEG_SIZE) ? SEG_FREE : SEG_DIRTY;
            continue;
        }
        if (sh.magic != SEG_MAGIC || sh.crc != seg_crc(&sh) || sh.version != FMT_VERSION) {
            ls->state[s] = SEG_DIRTY;
            continue;
        }
        ls->state[s] = SEG_SEALED;
        ls->seg_seq[s] = sh.seg_seq;
        if (sh.seg_seq > max_seg_seq) max_seg_seq = sh.seg_seq;
        uint32_t off = LS_SEG_HDR;
        while (off + LS_REC_HDR <= LS_SEG_SIZE) {
            rec_hdr_t *h = (rec_hdr_t *)ls->buf;
            if (ls->fl.read(ls->fl.ctx, seg_base(s) + off, h, LS_REC_HDR)) {
                err = LS_ERR_IO;
                break;
            }
            if (h->magic == 0xffffffffu) break;  // clean end of the written part
            bool ok = h->magic == REC_MAGIC && h->len <= LS_MAX_PAYLOAD &&
                      off + ls_record_size(h->len) <= LS_SEG_SIZE && h->kind >= LS_KIND_USER &&
                      h->kind <= LS_KIND_TEST && (h->op == LS_OP_PUT || h->op == LS_OP_DEL);
            ok = ok && ls->fl.read(ls->fl.ctx, seg_base(s) + off + LS_REC_HDR, ls->buf + LS_REC_HDR, h->len) == 0;
            ok = ok && rec_crc(h, ls->buf + LS_REC_HDR) == h->crc;
            if (!ok) {
                // A write cut short by power loss: everything before it is good, nothing may follow it
                sealed_by_tear[s] = 1;
                ls->torn++;
                break;
            }
            if (!apply(ls, seg_base(s) + off, h)) {
                err = LS_ERR_NOMEM;
                break;
            }
            if (!(h->flags & FLAG_COPY)) push_recent(ls, h);
            if (h->seq > max_seq) max_seq = h->seq;
            off += ls_record_size(h->len);
        }
        end[s] = off;
        ls->used[s] = LS_SEG_SIZE;
    }
    if (!err) {
        drop_dead_tombstones(ls);
        ls->next_seq = max_seq + 1;
        ls->next_seg_seq = max_seg_seq + 1;
        // Half-erased or never-finished segments: erase them so they can be reused
        for (uint32_t s = 0; s < ls->nseg && !err; s++) {
            if (ls->state[s] == SEG_DIRTY) err = erase_seg(ls, s);
        }
        // Keep appending to the newest segment if its tail is still clean
        int best = -1;
        for (uint32_t s = 0; s < ls->nseg; s++) {
            if (ls->state[s] == SEG_SEALED && !sealed_by_tear[s] && (best < 0 || ls->seg_seq[s] > ls->seg_seq[best])) {
                best = (int)s;
            }
        }
        if (best >= 0 && region_erased(ls, seg_base((uint32_t)best) + end[best], LS_SEG_SIZE - end[best])) {
            ls->state[best] = SEG_ACTIVE;
            ls->active = best;
            ls->wp = end[best];
            ls->used[best] = end[best];
        }
    }
    free(sealed_by_tear);
    free(end);
    if (err) {
        ls_unmount(ls);
        return err;
    }
    *out = ls;
    return LS_OK;
}

int ls_format(ls_store_t *ls)
{
    for (uint32_t s = 0; s < ls->nseg; s++) {
        int err = erase_seg(ls, s);
        if (err) return err;
    }
    ls->active = -1;
    ls->nent = 0;
    ls->nrecent = 0;
    ls->next_seq = 1;
    ls->next_seg_seq = 1;
    return LS_OK;
}

bool ls_fits(ls_store_t *ls, uint32_t extra)
{
    return (uint64_t)total_live(ls) + extra <= capacity(ls);
}

int ls_put(ls_store_t *ls, uint8_t kind, const uint8_t id[16], const void *data, uint32_t len)
{
    if (len > LS_MAX_PAYLOAD) return LS_ERR_TOOBIG;
    uint32_t size = ls_record_size(len);
    ls_entry_t *e = find(ls, kind, id);
    uint32_t replaced = e ? ls_record_size(e->len) : 0;  // becomes stale once the new version is written
    if ((uint64_t)total_live(ls) - replaced + size > capacity(ls)) return LS_ERR_NOSPACE;
    return append(ls, kind, LS_OP_PUT, id, data, len);
}

int ls_del(ls_store_t *ls, uint8_t kind, const uint8_t id[16])
{
    ls_entry_t *e = find(ls, kind, id);
    if (!e || e->deleted) return LS_ERR_NOTFOUND;
    return append(ls, kind, LS_OP_DEL, id, NULL, 0);  // a tombstone is smaller than any put, so it fits
}

bool ls_exists(ls_store_t *ls, uint8_t kind, const uint8_t id[16])
{
    ls_entry_t *e = find(ls, kind, id);
    return e && !e->deleted;
}

static int read_entry(ls_store_t *ls, const ls_entry_t *e, char *out)
{
    rec_hdr_t h;
    if (ls->fl.read(ls->fl.ctx, e->off, &h, sizeof(h))) return LS_ERR_IO;
    if (ls->fl.read(ls->fl.ctx, e->off + LS_REC_HDR, out, e->len)) return LS_ERR_IO;
    if (h.magic != REC_MAGIC || h.len != e->len || rec_crc(&h, out) != h.crc) return LS_ERR_IO;  // bit rot
    out[e->len] = '\0';
    return LS_OK;
}

int ls_get(ls_store_t *ls, uint8_t kind, const uint8_t id[16], char **data, uint32_t *len)
{
    ls_entry_t *e = find(ls, kind, id);
    if (!e || e->deleted) return LS_ERR_NOTFOUND;
    char *out = malloc(e->len + 1);
    if (!out) return LS_ERR_NOMEM;
    int err = read_entry(ls, e, out);
    if (err) {
        free(out);
        return err;
    }
    *data = out;
    if (len) *len = e->len;
    return LS_OK;
}

int ls_foreach(ls_store_t *ls, uint8_t kind, ls_visit_cb cb, void *ctx)
{
    char *buf = malloc(LS_MAX_PAYLOAD + 1);
    if (!buf) return LS_ERR_NOMEM;
    int ret = LS_OK;
    for (uint32_t i = 0; i < ls->nent && ret == LS_OK; i++) {
        ls_entry_t e = ls->ent[i];  // copy: cb must not modify the store, but be safe about the slot
        if (e.kind != kind || e.deleted) continue;
        ret = read_entry(ls, &e, buf);
        if (ret == LS_OK) ret = cb(e.kind, e.id, buf, e.len, ctx);
    }
    free(buf);
    return ret;
}

void ls_get_stats(ls_store_t *ls, ls_stats_t *st)
{
    memset(st, 0, sizeof(*st));
    st->capacity = capacity(ls);
    st->live_bytes = total_live(ls);
    st->free_bytes = st->capacity > st->live_bytes ? st->capacity - st->live_bytes : 0;
    uint32_t used = 0;
    for (uint32_t s = 0; s < ls->nseg; s++) {
        if (ls->state[s] == SEG_FREE) {
            st->segs_free++;
        } else {
            st->segs_used++;
            used += ls->used[s] > LS_SEG_HDR ? ls->used[s] - LS_SEG_HDR : 0;
        }
    }
    st->stale_bytes = used > st->live_bytes ? used - st->live_bytes : 0;
    st->segs_total = (uint16_t)ls->nseg;
    for (uint32_t i = 0; i < ls->nent; i++) {
        if (!ls->ent[i].deleted && ls->ent[i].kind < 5) st->count[ls->ent[i].kind]++;
    }
    st->gc_runs = ls->gc_runs;
    st->torn_records = ls->torn;
}

int ls_recent(ls_store_t *ls, ls_change_t *out, int max)
{
    int n = ls->nrecent < max ? ls->nrecent : max;
    memcpy(out, ls->recent, (size_t)n * sizeof(ls_change_t));
    return n;
}
