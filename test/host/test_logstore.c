// Host test for firmware/main/logstore.c: NOR flash simulation, random operations against a model,
// remounts, and power cuts at random byte positions during writes and erases.
//
//   cc -std=c11 -O2 -Wall -Wextra -I../../firmware/main ../../firmware/main/logstore.c test_logstore.c -o t && ./t
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "logstore.h"

// ---------- simulated NOR flash ----------

typedef struct {
    uint8_t *mem;
    uint32_t size;
    long budget;  // bytes that may still be written/erased before the "power cut"; <0 = unlimited
    uint64_t erases, writes;
} sim_t;

static jmp_buf g_cut;

static void spend(sim_t *s, uint32_t n, uint32_t *allowed)
{
    *allowed = n;
    if (s->budget < 0) return;
    if ((long)n > s->budget) *allowed = (uint32_t)s->budget;
    s->budget -= *allowed;
}

static int sim_read(void *ctx, uint32_t off, void *buf, uint32_t len)
{
    sim_t *s = ctx;
    if (off + len > s->size) return -1;
    memcpy(buf, s->mem + off, len);
    return 0;
}

static int sim_write(void *ctx, uint32_t off, const void *buf, uint32_t len)
{
    sim_t *s = ctx;
    if (off + len > s->size) return -1;
    uint32_t ok;
    spend(s, len, &ok);
    const uint8_t *b = buf;
    for (uint32_t i = 0; i < ok; i++) s->mem[off + i] &= b[i];  // NOR: bits only go 1 -> 0
    if (ok < len) {
        // the byte being written when power dies ends up with random bits cleared
        s->mem[off + ok] &= (uint8_t)(b[ok] | (rand() & 0xff));
        longjmp(g_cut, 1);
    }
    s->writes++;
    return 0;
}

static int sim_erase(void *ctx, uint32_t off, uint32_t len)
{
    sim_t *s = ctx;
    if (off % LS_SECTOR || len % LS_SECTOR || off + len > s->size) return -1;
    uint32_t ok;
    spend(s, len, &ok);
    memset(s->mem + off, 0xff, ok);
    if (ok < len) {
        // an interrupted erase leaves the rest of the sector in a mixed state
        for (uint32_t i = ok; i < len; i++) s->mem[off + i] |= (uint8_t)(rand() & 0xff);
        longjmp(g_cut, 1);
    }
    s->erases++;
    return 0;
}

static uint32_t sim_now(void *ctx)
{
    (void)ctx;
    return 1700000000u;
}

// ---------- model ----------

#define MAXKEYS 400
typedef struct {
    bool present;
    uint32_t len;
    uint8_t *data;
} slot_t;

static slot_t model[MAXKEYS];

static void key_id(int k, uint8_t id[16])
{
    memset(id, 0, 16);
    id[0] = (uint8_t)k;
    id[1] = (uint8_t)(k >> 8);
    id[15] = 0xA5;
}

static void make_payload(uint8_t *buf, uint32_t len, int k, uint32_t ver)
{
    for (uint32_t i = 0; i < len; i++) buf[i] = (uint8_t)('a' + (k * 7 + ver * 13 + i) % 26);
}

static int failures;
#define CHECK(cond, ...)                                    \
    do {                                                    \
        if (!(cond)) {                                      \
            printf("FAIL %s:%d: ", __FILE__, __LINE__);     \
            printf(__VA_ARGS__);                            \
            printf("\n");                                   \
            failures++;                                     \
            if (failures > 20) exit(1);                     \
        }                                                   \
    } while (0)

static void verify(ls_store_t *ls, int nkeys, int pending_key, const slot_t *pending_new)
{
    for (int k = 0; k < nkeys; k++) {
        uint8_t id[16];
        key_id(k, id);
        char *d = NULL;
        uint32_t len = 0;
        int r = ls_get(ls, LS_KIND_CIPHER, id, &d, &len);
        bool got = r == LS_OK;
        bool match_old = got == model[k].present &&
                         (!got || (len == model[k].len && memcmp(d, model[k].data, len) == 0));
        bool match_new = false;
        if (k == pending_key && pending_new) {
            match_new = got == pending_new->present &&
                        (!got || (len == pending_new->len && memcmp(d, pending_new->data, len) == 0));
        }
        CHECK(match_old || match_new, "key %d: got=%d len=%u model.present=%d model.len=%u (r=%d)", k, got,
              (unsigned)len, model[k].present, (unsigned)model[k].len, r);
        free(d);
    }
    // foreach must see exactly the live keys
    int n = 0;
    ls_stats_t st;
    ls_get_stats(ls, &st);
    for (int k = 0; k < nkeys; k++) n += model[k].present;
    if (pending_key < 0) CHECK((int)st.count[LS_KIND_CIPHER] == n, "count %u vs model %d", st.count[LS_KIND_CIPHER], n);
}

static void set_model(int k, bool present, const uint8_t *data, uint32_t len)
{
    free(model[k].data);
    model[k].data = NULL;
    model[k].present = present;
    model[k].len = present ? len : 0;
    if (present) {
        model[k].data = malloc(len ? len : 1);
        memcpy(model[k].data, data, len);
    }
}

static ls_flash_t flash_for(sim_t *s)
{
    return (ls_flash_t){.read = sim_read, .write = sim_write, .erase = sim_erase, .now = sim_now, .ctx = s, .size = s->size};
}

// ---------- tests ----------

static void test_basic(void)
{
    sim_t s = {.size = 8 * LS_SEG_SIZE, .budget = -1};
    s.mem = malloc(s.size);
    memset(s.mem, 0xff, s.size);
    ls_flash_t f = flash_for(&s);
    ls_store_t *ls;
    CHECK(ls_mount(&ls, &f) == LS_OK, "mount empty");
    uint8_t id[16];
    key_id(1, id);
    CHECK(!ls_exists(ls, LS_KIND_CIPHER, id), "absent");
    CHECK(ls_put(ls, LS_KIND_CIPHER, id, "hello", 5) == LS_OK, "put");
    CHECK(ls_put(ls, LS_KIND_CIPHER, id, "hello world", 11) == LS_OK, "update");
    char *d;
    uint32_t len;
    CHECK(ls_get(ls, LS_KIND_CIPHER, id, &d, &len) == LS_OK && len == 11 && strcmp(d, "hello world") == 0, "get");
    free(d);
    uint8_t uid[16] = {0};
    CHECK(ls_put(ls, LS_KIND_USER, uid, "{\"u\":1}", 7) == LS_OK, "user");
    CHECK(ls_del(ls, LS_KIND_CIPHER, id) == LS_OK, "del");
    CHECK(!ls_exists(ls, LS_KIND_CIPHER, id), "deleted");
    CHECK(ls_del(ls, LS_KIND_CIPHER, id) == LS_ERR_NOTFOUND, "del twice");
    ls_unmount(ls);
    CHECK(ls_mount(&ls, &f) == LS_OK, "remount");
    CHECK(!ls_exists(ls, LS_KIND_CIPHER, id), "still deleted after remount");
    CHECK(ls_exists(ls, LS_KIND_USER, uid), "user after remount");
    ls_change_t ch[8];
    int n = ls_recent(ls, ch, 8);
    CHECK(n == 4 && ch[0].op == LS_OP_DEL && ch[0].kind == LS_KIND_CIPHER, "recent: n=%d", n);
    ls_unmount(ls);
    free(s.mem);
    printf("basic: ok\n");
}

// Random puts/updates/deletes near capacity with remounts; no power cuts
static void test_random(int nsegs, int nkeys, int ops, uint32_t maxlen, unsigned seed)
{
    srand(seed);
    sim_t s = {.size = (uint32_t)nsegs * LS_SEG_SIZE, .budget = -1};
    s.mem = malloc(s.size);
    memset(s.mem, 0xff, s.size);
    memset(model, 0, sizeof(model));
    ls_flash_t f = flash_for(&s);
    ls_store_t *ls;
    CHECK(ls_mount(&ls, &f) == LS_OK, "mount");
    uint8_t *buf = malloc(LS_MAX_PAYLOAD);
    int nospace = 0, gc = 0;
    for (int i = 0; i < ops; i++) {
        int k = rand() % nkeys;
        uint8_t id[16];
        key_id(k, id);
        if (rand() % 5 == 0 && model[k].present) {
            CHECK(ls_del(ls, LS_KIND_CIPHER, id) == LS_OK, "del %d", k);
            set_model(k, false, NULL, 0);
        } else {
            uint32_t len = (uint32_t)(rand() % (int)maxlen);
            if (rand() % 50 == 0) len = (uint32_t)(rand() % 20000);  // occasional big record
            make_payload(buf, len, k, (uint32_t)i);
            int r = ls_put(ls, LS_KIND_CIPHER, id, buf, len);
            if (r == LS_ERR_NOSPACE) {
                nospace++;
            } else {
                CHECK(r == LS_OK, "put %d len %u -> %d", k, (unsigned)len, r);
                if (r == LS_OK) set_model(k, true, buf, len);
            }
        }
        if (i % 997 == 0) {
            ls_stats_t st;
            ls_get_stats(ls, &st);
            gc += (int)st.gc_runs;
            ls_unmount(ls);
            CHECK(ls_mount(&ls, &f) == LS_OK, "remount");
            verify(ls, nkeys, -1, NULL);
        }
    }
    verify(ls, nkeys, -1, NULL);
    ls_stats_t st;
    ls_get_stats(ls, &st);
    printf("random(%d segs, %d keys, %d ops): ok  live %u / cap %u, stale %u, nospace %d, gc %d, erases %llu\n", nsegs,
           nkeys, ops, st.live_bytes, st.capacity, st.stale_bytes, nospace, gc + (int)st.gc_runs,
           (unsigned long long)s.erases);
    ls_unmount(ls);
    free(buf);
    free(s.mem);
    for (int k = 0; k < MAXKEYS; k++) free(model[k].data);
    memset(model, 0, sizeof(model));
}

// Power cut at a random byte during some operation, then remount and check nothing committed was lost
static void test_power_cuts(int rounds, unsigned seed)
{
    srand(seed);
    const int nsegs = 6, nkeys = 60;
    sim_t s = {.size = nsegs * LS_SEG_SIZE, .budget = -1};
    s.mem = malloc(s.size);
    memset(s.mem, 0xff, s.size);
    memset(model, 0, sizeof(model));
    ls_flash_t f = flash_for(&s);
    uint8_t *buf = malloc(LS_MAX_PAYLOAD);
    ls_store_t *volatile ls = NULL;
    ls_store_t *tmp;
    CHECK(ls_mount(&tmp, &f) == LS_OK, "mount");
    ls = tmp;
    int cuts = 0, torn = 0;
    for (int r = 0; r < rounds; r++) {
        // a few normal ops
        volatile int k = rand() % nkeys;
        volatile bool is_del = rand() % 5 == 0 && model[k].present;
        uint32_t len = (uint32_t)(rand() % 6000);
        make_payload(buf, len, k, (uint32_t)r);
        slot_t pending = {.present = !is_del, .len = is_del ? 0 : len, .data = buf};
        uint8_t id[16];
        key_id(k, id);
        bool cut_now = rand() % 3 == 0;
        // cut inside the record write most of the time, sometimes later (inside GC copies or erases)
        s.budget = cut_now ? (rand() % 2 ? rand() % 8000 : rand() % 400000) : -1;
        if (setjmp(g_cut) == 0) {
            int res = is_del ? ls_del(ls, LS_KIND_CIPHER, id) : ls_put(ls, LS_KIND_CIPHER, id, buf, len);
            s.budget = -1;
            if (res == LS_OK) {
                set_model(k, !is_del, buf, len);
            } else {
                CHECK(res == LS_ERR_NOSPACE, "op failed %d", res);
            }
        } else {
            // power died inside the operation: memory state is gone, flash is whatever it is
            s.budget = -1;
            cuts++;
            ls_store_t *old = ls;
            (void)old;  // leaked on purpose: a real power cut does not free anything
            CHECK(ls_mount(&tmp, &f) == LS_OK, "mount after cut");
            ls = tmp;
            ls_stats_t st;
            ls_get_stats(ls, &st);
            torn += (int)st.torn_records;
            verify(ls, nkeys, k, &pending);
            // adopt whatever survived for the in-flight key
            char *d = NULL;
            uint32_t dl = 0;
            if (ls_get(ls, LS_KIND_CIPHER, id, &d, &dl) == LS_OK) {
                set_model(k, true, (uint8_t *)d, dl);
                free(d);
            } else {
                set_model(k, false, NULL, 0);
            }
        }
        if (r % 50 == 0) {
            ls_unmount(ls);
            CHECK(ls_mount(&tmp, &f) == LS_OK, "periodic remount");
            ls = tmp;
            verify(ls, nkeys, -1, NULL);
        }
    }
    printf("power cuts: ok  %d rounds, %d cuts, %d torn records seen\n", rounds, cuts, torn);
    free(buf);
    free(s.mem);
    for (int k = 0; k < MAXKEYS; k++) free(model[k].data);
    memset(model, 0, sizeof(model));
}

// Fill like a real vault: about 800 items of ~2 KB in the real partition size, then edit for a "year"
static void test_vault(void)
{
    srand(42);
    const int nsegs = 0x2F0000 / LS_SEG_SIZE;
    sim_t s = {.size = nsegs * LS_SEG_SIZE, .budget = -1};
    s.mem = malloc(s.size);
    memset(s.mem, 0xff, s.size);
    memset(model, 0, sizeof(model));
    ls_flash_t f = flash_for(&s);
    ls_store_t *ls;
    CHECK(ls_mount(&ls, &f) == LS_OK, "mount");
    uint8_t *buf = malloc(LS_MAX_PAYLOAD);
    const int n = 400 > MAXKEYS ? MAXKEYS : 400;  // model size limit; scaled check below
    for (int k = 0; k < n; k++) {
        uint32_t len = 1500 + (uint32_t)(rand() % 1200);
        make_payload(buf, len, k, 0);
        uint8_t id[16];
        key_id(k, id);
        CHECK(ls_put(ls, LS_KIND_CIPHER, id, buf, len) == LS_OK, "fill %d", k);
        set_model(k, true, buf, len);
    }
    uint64_t e0 = s.erases;
    for (int i = 0; i < 120 * 10; i++) {  // 10 years of 10 edits a month
        int k = rand() % n;
        uint32_t len = 1500 + (uint32_t)(rand() % 1200);
        make_payload(buf, len, k, (uint32_t)i + 1);
        uint8_t id[16];
        key_id(k, id);
        CHECK(ls_put(ls, LS_KIND_CIPHER, id, buf, len) == LS_OK, "edit");
        set_model(k, true, buf, len);
    }
    ls_unmount(ls);
    CHECK(ls_mount(&ls, &f) == LS_OK, "remount");
    verify(ls, n, -1, NULL);
    ls_stats_t st;
    ls_get_stats(ls, &st);
    printf("vault: ok  %d items, live %u KB of %u KB, 1200 edits caused %llu sector erases\n", n,
           st.live_bytes / 1024, st.capacity / 1024, (unsigned long long)(s.erases - e0));
    ls_unmount(ls);
    free(buf);
    free(s.mem);
    for (int k = 0; k < MAXKEYS; k++) free(model[k].data);
    memset(model, 0, sizeof(model));
}

int main(int argc, char **argv)
{
    if (argc > 1) {  // ./t <seeds>: power-cut soak only
        int n = atoi(argv[1]);
        for (int i = 0; i < n; i++) test_power_cuts(3000, 100u + (unsigned)i);
        printf(failures ? "FAILED (%d)\n" : "ALL PASSED\n", failures);
        return failures ? 1 : 0;
    }
    test_basic();
    test_random(8, 200, 20000, 3000, 1);
    test_random(6, 300, 30000, 2500, 2);   // tight: forces GC constantly and NOSPACE at the limit
    test_random(47, 400, 20000, 4000, 3);  // real partition size
    test_power_cuts(3000, 7);
    test_power_cuts(3000, 8);
    test_vault();
    printf(failures ? "FAILED (%d)\n" : "ALL PASSED\n", failures);
    return failures ? 1 : 0;
}
