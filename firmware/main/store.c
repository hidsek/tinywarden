// Vault storage: the log-structured store (logstore.c) on the raw "storage" partition (SPEC 5).
// Callers keep using path-like names; they map to (kind, id) keys:
//   /tw/head.json            -> account header, plaintext (KDF settings, wrapped keys)
//   /tw/user.json            -> user
//   /tw/f/<uuid>.json        -> folder
//   /tw/c/[<x>/]<uuid>.json  -> cipher
//   /tw/t/[<x>/]<uuid>.json  -> development self-test records
//
// Everything except the header is sealed (SPEC 5.4): on flash a record is
//   kind SEALED, id = HMAC(id key, kind || real id)[0..16], time 0,
//   payload = nonce(12) || AES-256-GCM(enc key, plain, aad = that id) || tag(16)
//   plain   = kind(1) || real id(16) || time(4) || json length(4) || json || zero padding
// so a copy of the flash shows neither what a record is, nor its id, nor when it was written. The padding
// rounds every record up to PAD_MIN, then to PAD_STEP, so sizes say little about the content.
// The keys come from the storage key, which exists only in RAM after a login (tw_store_unlock).
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_partition.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "logstore.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "tw.h"

static const char *TAG = "store";
static const esp_partition_t *s_part;
static ls_store_t *s_ls;
static SemaphoreHandle_t s_lock;
static uint32_t s_mount_ms;

#define LOCK() xSemaphoreTakeRecursive(s_lock, portMAX_DELAY)
#define UNLOCK() xSemaphoreGiveRecursive(s_lock)

// Inner kinds (inside the sealed payload)
enum { K_USER = 1, K_FOLDER = 2, K_CIPHER = 3, K_TEST = 4, K_N = 5 };

#define NONCE_LEN 12
#define TAG_LEN 16
#define INNER_HDR 25  // kind 1, id 16, time 4, length 4
#define PAD_MIN 1024u
#define PAD_STEP 512u
#define MAX_PLAIN (LS_MAX_PAYLOAD - NONCE_LEN - TAG_LEN)

static bool s_unlocked;
static uint8_t s_enc_key[32], s_id_key[32];
static uint32_t s_count[K_N];   // live sealed records per inner kind, counted at unlock
static uint32_t s_unreadable;   // sealed records the current key cannot open (left over from an old account)

// Inner kind of each live sealed record, by its opaque id (RAM, filled at unlock). Lets a pass over one
// kind skip the others without opening them: sync walks folders, then items.
typedef struct {
    uint8_t opq[16];
    uint8_t kind;
} kind_ent_t;
static kind_ent_t *s_kinds;
static uint32_t s_nkinds, s_capkinds;

static kind_ent_t *kinds_find(const uint8_t opq[16])
{
    for (uint32_t i = 0; i < s_nkinds; i++) {
        if (memcmp(s_kinds[i].opq, opq, 16) == 0) return &s_kinds[i];
    }
    return NULL;
}

static uint8_t kinds_get(const uint8_t opq[16])
{
    kind_ent_t *e = kinds_find(opq);
    return e ? e->kind : 0;  // 0: not known, open it to see
}

static void kinds_set(const uint8_t opq[16], uint8_t kind)
{
    kind_ent_t *e = kinds_find(opq);
    if (e) {
        e->kind = kind;
        return;
    }
    if (s_nkinds == s_capkinds) {
        uint32_t nc = s_capkinds ? s_capkinds * 2 : 256;
        void *p = realloc(s_kinds, nc * sizeof(kind_ent_t));
        if (!p) return;  // only a shortcut: without it the record is opened to find its kind
        s_kinds = p;
        s_capkinds = nc;
    }
    memcpy(s_kinds[s_nkinds].opq, opq, 16);
    s_kinds[s_nkinds++].kind = kind;
}

static void kinds_del(const uint8_t opq[16])
{
    kind_ent_t *e = kinds_find(opq);
    if (e) *e = s_kinds[--s_nkinds];
}

static void kinds_clear(void)
{
    free(s_kinds);
    s_kinds = NULL;
    s_nkinds = s_capkinds = 0;
}

// ---------- flash adapter ----------

static int fl_read(void *ctx, uint32_t off, void *buf, uint32_t len)
{
    return esp_partition_read(ctx, off, buf, len) == ESP_OK ? 0 : -1;
}

static int fl_write(void *ctx, uint32_t off, const void *buf, uint32_t len)
{
    return esp_partition_write(ctx, off, buf, len) == ESP_OK ? 0 : -1;
}

static int fl_erase(void *ctx, uint32_t off, uint32_t len)
{
    return esp_partition_erase_range(ctx, off, len) == ESP_OK ? 0 : -1;
}

// Record headers carry no time: the real one is inside the sealed payload
static uint32_t fl_now(void *ctx)
{
    (void)ctx;
    return 0;
}

static esp_err_t to_esp(int r)
{
    switch (r) {
    case LS_OK: return ESP_OK;
    case LS_ERR_NOMEM: return ESP_ERR_NO_MEM;
    case LS_ERR_NOSPACE: return ESP_ERR_NO_MEM;
    case LS_ERR_TOOBIG: return ESP_ERR_INVALID_SIZE;
    case LS_ERR_NOTFOUND: return ESP_ERR_NOT_FOUND;
    case LS_ERR_ARG: return ESP_ERR_INVALID_ARG;
    default: return ESP_FAIL;
    }
}

esp_err_t tw_store_init(void)
{
    s_lock = xSemaphoreCreateRecursiveMutex();
    s_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, "storage");
    if (!s_part) {
        ESP_LOGE(TAG, "no storage partition");
        return ESP_ERR_NOT_FOUND;
    }
    const ls_flash_t fl = {
        .read = fl_read, .write = fl_write, .erase = fl_erase, .now = fl_now,
        .ctx = (void *)s_part, .size = (uint32_t)(s_part->size / LS_SEG_SIZE * LS_SEG_SIZE),
    };
    int64_t t0 = esp_timer_get_time();
    int r = ls_mount(&s_ls, &fl);
    s_mount_ms = (uint32_t)((esp_timer_get_time() - t0) / 1000);
    if (r != LS_OK) {
        ESP_LOGE(TAG, "mount failed: %d", r);
        return to_esp(r);
    }
    ls_stats_t st;
    ls_get_stats(s_ls, &st);
    ESP_LOGI(TAG, "mounted in %u ms: %u sealed records, %u KB live, %u torn", (unsigned)s_mount_ms,
             (unsigned)st.count[LS_KIND_SEALED], (unsigned)(st.live_bytes / 1024), (unsigned)st.torn_records);
    return ESP_OK;
}

// ---------- sealing ----------

static void hmac(const uint8_t key[32], const void *in, size_t len, uint8_t out[32])
{
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, 32, in, len, out);
}

static void opaque_id(uint8_t kind, const uint8_t id[16], uint8_t out[16])
{
    uint8_t in[17], mac[32];
    in[0] = kind;
    memcpy(in + 1, id, 16);
    hmac(s_id_key, in, sizeof(in), mac);
    memcpy(out, mac, 16);
}

// Padded plaintext length for a JSON of len bytes; 0 if it cannot fit in one record
static uint32_t plain_len(size_t len)
{
    if (len > MAX_PLAIN - INNER_HDR) return 0;
    uint32_t p = (uint32_t)len + INNER_HDR;
    p = p < PAD_MIN ? PAD_MIN : (p + PAD_STEP - 1) / PAD_STEP * PAD_STEP;
    return p > MAX_PLAIN ? MAX_PLAIN : p;
}

static void put_u32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)v, p[1] = (uint8_t)(v >> 8), p[2] = (uint8_t)(v >> 16), p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_u32(const uint8_t *p)
{
    return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

// Returns a malloc'd payload of *out_len bytes, or NULL
static uint8_t *seal(uint8_t kind, const uint8_t id[16], const uint8_t opq[16], const char *json, size_t len,
                     uint32_t *out_len)
{
    uint32_t pl = plain_len(len);
    if (!pl) return NULL;
    uint8_t *buf = calloc(1, NONCE_LEN + pl + TAG_LEN);
    if (!buf) return NULL;
    uint8_t *plain = buf + NONCE_LEN;
    plain[0] = kind;
    memcpy(plain + 1, id, 16);
    put_u32(plain + 17, (uint32_t)(tw_now_ms() / 1000));
    put_u32(plain + 21, (uint32_t)len);
    memcpy(plain + INNER_HDR, json, len);
    tw_random(buf, NONCE_LEN);
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    int r = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, s_enc_key, 256);
    if (r == 0) {
        r = mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, pl, buf, NONCE_LEN, opq, 16, plain, plain, TAG_LEN,
                                      plain + pl);
    }
    mbedtls_gcm_free(&g);
    if (r != 0) {
        free(buf);
        return NULL;
    }
    *out_len = NONCE_LEN + pl + TAG_LEN;
    return buf;
}

typedef struct {
    uint8_t kind;
    uint8_t id[16];
    uint32_t time;
    const char *json;  // inside buf, NUL-terminated
    uint32_t len;
    uint8_t *buf;      // caller frees
} opened_t;

static bool unseal(const uint8_t opq[16], const void *data, uint32_t len, opened_t *o)
{
    memset(o, 0, sizeof(*o));
    if (len < NONCE_LEN + INNER_HDR + TAG_LEN) return false;
    const uint8_t *d = data;
    uint32_t pl = len - NONCE_LEN - TAG_LEN;
    uint8_t *plain = malloc(pl + 1);
    if (!plain) return false;
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    int r = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, s_enc_key, 256);
    if (r == 0) {
        r = mbedtls_gcm_auth_decrypt(&g, pl, d, NONCE_LEN, opq, 16, d + NONCE_LEN + pl, TAG_LEN, d + NONCE_LEN, plain);
    }
    mbedtls_gcm_free(&g);
    uint32_t jl = r == 0 ? get_u32(plain + 21) : 0;
    if (r != 0 || jl > pl - INNER_HDR) {
        free(plain);
        return false;
    }
    o->kind = plain[0];
    memcpy(o->id, plain + 1, 16);
    o->time = get_u32(plain + 17);
    plain[INNER_HDR + jl] = '\0';
    o->json = (const char *)plain + INNER_HDR;
    o->len = jl;
    o->buf = plain;
    return true;
}

// ---------- unlocking ----------

typedef struct {
    uint32_t count[K_N], bad;
} scan_t;

static int scan_one(uint8_t kind, const uint8_t id[16], const char *data, uint32_t len, void *arg)
{
    (void)kind;
    scan_t *s = arg;
    opened_t o;
    if (unseal(id, data, len, &o)) {
        if (o.kind < K_N) s->count[o.kind]++;
        kinds_set(id, o.kind);
        free(o.buf);
    } else {
        s->bad++;
    }
    return LS_OK;
}

esp_err_t tw_store_unlock(const uint8_t key[32])
{
    uint8_t enc[32], idk[32];
    hmac(key, "tinywarden enc", 14, enc);
    hmac(key, "tinywarden id", 13, idk);
    LOCK();
    if (s_unlocked && tw_ct_equal(enc, s_enc_key, 32)) {
        UNLOCK();
        return ESP_OK;
    }
    memcpy(s_enc_key, enc, 32);
    memcpy(s_id_key, idk, 32);
    kinds_clear();
    scan_t sc = {0};
    int64_t t0 = esp_timer_get_time();
    int r = ls_foreach(s_ls, LS_KIND_SEALED, scan_one, &sc);
    memcpy(s_count, sc.count, sizeof(s_count));
    s_unreadable = sc.bad;
    s_unlocked = r == LS_OK;
    UNLOCK();
    memset(enc, 0, sizeof(enc));
    memset(idk, 0, sizeof(idk));
    ESP_LOGI(TAG, "unlocked in %u ms: %u items, %u folders, %u unreadable",
             (unsigned)((esp_timer_get_time() - t0) / 1000), (unsigned)sc.count[K_CIPHER],
             (unsigned)sc.count[K_FOLDER], (unsigned)sc.bad);
    return to_esp(r);
}

static void lock_now(void)
{
    s_unlocked = false;
    memset(s_enc_key, 0, sizeof(s_enc_key));
    memset(s_id_key, 0, sizeof(s_id_key));
    memset(s_count, 0, sizeof(s_count));
    s_unreadable = 0;
    kinds_clear();
}

bool tw_store_unlocked(void)
{
    LOCK();
    bool r = s_unlocked;
    UNLOCK();
    return r;
}

// ---------- names ----------

static bool parse_uuid(const char *s, uint8_t out[16])
{
    int n = 0;
    for (; *s && n < 32; s++) {
        if (*s == '-') continue;
        if (!isxdigit((unsigned char)*s)) return false;
        int v = isdigit((unsigned char)*s) ? *s - '0' : tolower((unsigned char)*s) - 'a' + 10;
        if (n % 2 == 0) out[n / 2] = (uint8_t)(v << 4);
        else out[n / 2] |= (uint8_t)v;
        n++;
    }
    return n == 32 && strcmp(s, ".json") == 0;
}

static void format_uuid(const uint8_t id[16], char out[37])
{
    snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x", id[0], id[1], id[2],
             id[3], id[4], id[5], id[6], id[7], id[8], id[9], id[10], id[11], id[12], id[13], id[14], id[15]);
}

// "<dir>/<uuid>.json" or "<dir>/<x>/<uuid>.json"
static bool parse_in_dir(const char *path, const char *dir, uint8_t id[16])
{
    size_t n = strlen(dir);
    if (strncmp(path, dir, n) != 0 || path[n] != '/') return false;
    const char *p = path + n + 1;
    if (p[0] && p[1] == '/') p += 2;  // 16-way subdirectory form, still accepted
    return parse_uuid(p, id);
}

// Inner kind and id for a path. The header is not sealed: *kind = 0.
static bool parse_path(const char *path, uint8_t *kind, uint8_t id[16])
{
    memset(id, 0, 16);
    if (strcmp(path, TW_HEAD_PATH) == 0) {
        *kind = 0;
        return true;
    }
    if (strcmp(path, TW_USER_PATH) == 0) {
        *kind = K_USER;
        return true;
    }
    if (parse_in_dir(path, TW_FOLDER_DIR, id)) {
        *kind = K_FOLDER;
        return true;
    }
    if (parse_in_dir(path, TW_CIPHER_DIR, id)) {
        *kind = K_CIPHER;
        return true;
    }
    if (parse_in_dir(path, TW_TEST_DIR, id)) {
        *kind = K_TEST;
        return true;
    }
    ESP_LOGW(TAG, "unknown path %s", path);
    return false;
}

static bool parse_dir(const char *dir, uint8_t *kind)
{
    if (strcmp(dir, TW_FOLDER_DIR) == 0) *kind = K_FOLDER;
    else if (strcmp(dir, TW_CIPHER_DIR) == 0) *kind = K_CIPHER;
    else if (strcmp(dir, TW_TEST_DIR) == 0) *kind = K_TEST;
    else return false;
    return true;
}

static const uint8_t HEAD_ID[16] = {0};

// ---------- API used by auth.c / api.c ----------
// Sealed paths need the store unlocked: reads find nothing and writes fail with ESP_ERR_INVALID_STATE.

bool tw_store_exists(const char *path)
{
    uint8_t kind, id[16], opq[16];
    if (!parse_path(path, &kind, id)) return false;
    LOCK();
    bool r;
    if (!kind) {
        r = ls_exists(s_ls, LS_KIND_USER, HEAD_ID);
    } else if (!s_unlocked) {
        r = false;
    } else {
        opaque_id(kind, id, opq);
        r = ls_exists(s_ls, LS_KIND_SEALED, opq);
    }
    UNLOCK();
    return r;
}

cJSON *tw_store_read(const char *path)
{
    uint8_t kind, id[16], opq[16];
    if (!parse_path(path, &kind, id)) return NULL;
    char *data = NULL;
    uint32_t len = 0;
    LOCK();
    if (kind && !s_unlocked) {
        UNLOCK();
        return NULL;
    }
    if (kind) opaque_id(kind, id, opq);
    int r = kind ? ls_get(s_ls, LS_KIND_SEALED, opq, &data, &len) : ls_get(s_ls, LS_KIND_USER, HEAD_ID, &data, &len);
    opened_t o = {0};
    bool ok = r == LS_OK && (!kind || unseal(opq, data, len, &o));
    UNLOCK();
    if (r != LS_OK) {
        if (r != LS_ERR_NOTFOUND) ESP_LOGE(TAG, "read %s: %d", path, r);
        return NULL;
    }
    cJSON *obj = NULL;
    if (!ok) {
        ESP_LOGE(TAG, "read %s: does not open with this key", path);
    } else if (kind) {
        obj = cJSON_ParseWithLength(o.json, o.len);
    } else {
        obj = cJSON_ParseWithLength(data, len);
    }
    free(o.buf);
    free(data);
    return obj;
}

esp_err_t tw_store_write(const char *path, const cJSON *obj)
{
    uint8_t kind, id[16], opq[16];
    if (!parse_path(path, &kind, id)) return ESP_ERR_INVALID_ARG;
    char *text = cJSON_PrintUnformatted(obj);
    if (!text) return ESP_ERR_NO_MEM;
    size_t tl = strlen(text);
    LOCK();
    int r;
    if (!kind) {
        r = ls_put(s_ls, LS_KIND_USER, HEAD_ID, text, (uint32_t)tl);
    } else if (!s_unlocked) {
        UNLOCK();
        free(text);
        return ESP_ERR_INVALID_STATE;
    } else {
        opaque_id(kind, id, opq);
        uint32_t sl = 0;
        uint8_t *sealed = seal(kind, id, opq, text, tl, &sl);
        if (!sealed) {
            r = plain_len(tl) ? LS_ERR_NOMEM : LS_ERR_TOOBIG;
        } else {
            bool existed = ls_exists(s_ls, LS_KIND_SEALED, opq);
            r = ls_put(s_ls, LS_KIND_SEALED, opq, sealed, sl);
            if (r == LS_OK && !existed) s_count[kind]++;
            if (r == LS_OK) kinds_set(opq, kind);
            free(sealed);
        }
    }
    UNLOCK();
    free(text);
    if (r != LS_OK) ESP_LOGE(TAG, "write %s: %d", path, r);
    return to_esp(r);
}

esp_err_t tw_store_write_new(const char *path, const cJSON *obj)
{
    return tw_store_write(path, obj);  // every write is an append now
}

esp_err_t tw_store_remove(const char *path)
{
    uint8_t kind, id[16], opq[16];
    if (!parse_path(path, &kind, id)) return ESP_ERR_INVALID_ARG;
    LOCK();
    int r;
    if (!kind) {
        r = ls_del(s_ls, LS_KIND_USER, HEAD_ID);
    } else if (!s_unlocked) {
        r = LS_ERR_ARG;
    } else {
        opaque_id(kind, id, opq);
        r = ls_del(s_ls, LS_KIND_SEALED, opq);
        if (r == LS_OK && s_count[kind]) s_count[kind]--;
        if (r == LS_OK) kinds_del(opq);
    }
    UNLOCK();
    return to_esp(r);
}

typedef struct {
    uint8_t kind;
    const char *dir;
    tw_rec_cb cb;
    void *ctx;
    esp_err_t err;
} visit_t;

static int visit(uint8_t kind, const uint8_t opq[16], const char *data, uint32_t len, void *arg)
{
    (void)kind;
    visit_t *v = arg;
    uint8_t known = kinds_get(opq);
    if (known && known != v->kind) return LS_OK;  // another kind: no need to open it
    opened_t o;
    if (!unseal(opq, data, len, &o)) return LS_OK;  // left over from an old account
    if (o.kind == v->kind) {
        char uuid[37], path[96];
        format_uuid(o.id, uuid);
        if (o.kind == K_CIPHER) snprintf(path, sizeof(path), "%s/%c/%s.json", v->dir, uuid[0], uuid);
        else snprintf(path, sizeof(path), "%s/%s.json", v->dir, uuid);
        v->err = v->cb(path, o.json, o.len, v->ctx);
    }
    free(o.buf);
    return v->err == ESP_OK ? LS_OK : LS_ERR_ARG;
}

esp_err_t tw_store_foreach(const char *dir, tw_rec_cb cb, void *ctx)
{
    uint8_t kind;
    if (!parse_dir(dir, &kind)) return ESP_ERR_INVALID_ARG;
    visit_t v = {.kind = kind, .dir = dir, .cb = cb, .ctx = ctx, .err = ESP_OK};
    LOCK();
    if (!s_unlocked) {
        UNLOCK();
        return ESP_ERR_INVALID_STATE;
    }
    int r = ls_foreach(s_ls, LS_KIND_SEALED, visit, &v);
    UNLOCK();
    return v.err != ESP_OK ? v.err : to_esp(r);
}

int tw_store_count(const char *dir)
{
    uint8_t kind;
    if (!parse_dir(dir, &kind)) return 0;
    LOCK();
    int n = s_unlocked ? (int)s_count[kind] : 0;
    UNLOCK();
    return n;
}

typedef struct {
    uint8_t kind;
    uint8_t (*ids)[16];  // opaque ids
    int n, cap;
} idlist_t;

static int collect(uint8_t kind, const uint8_t opq[16], const char *data, uint32_t len, void *arg)
{
    (void)kind;
    idlist_t *l = arg;
    uint8_t known = kinds_get(opq);
    if (known && known != l->kind) return LS_OK;
    opened_t o;
    if (!unseal(opq, data, len, &o)) return LS_OK;
    bool match = o.kind == l->kind;
    free(o.buf);
    if (!match) return LS_OK;
    if (l->n == l->cap) {
        int nc = l->cap ? l->cap * 2 : 64;
        void *p = realloc(l->ids, (size_t)nc * 16);
        if (!p) return LS_ERR_NOMEM;
        l->ids = p;
        l->cap = nc;
    }
    memcpy(l->ids[l->n++], opq, 16);
    return LS_OK;
}

esp_err_t tw_store_delete_all(const char *dir)
{
    uint8_t kind;
    if (!parse_dir(dir, &kind)) return ESP_ERR_INVALID_ARG;
    idlist_t l = {.kind = kind};
    LOCK();
    if (!s_unlocked) {
        UNLOCK();
        return ESP_ERR_INVALID_STATE;
    }
    int r = ls_foreach(s_ls, LS_KIND_SEALED, collect, &l);
    for (int i = 0; r == LS_OK && i < l.n; i++) {
        r = ls_del(s_ls, LS_KIND_SEALED, l.ids[i]);
        if (r == LS_OK && s_count[kind]) s_count[kind]--;
        if (r == LS_OK) kinds_del(l.ids[i]);
    }
    UNLOCK();
    free(l.ids);
    return to_esp(r);
}

// Erase the whole partition, not just the records (SPEC 6), and forget the key
esp_err_t tw_store_wipe(void)
{
    ESP_LOGW(TAG, "wiping storage");
    LOCK();
    int r = ls_format(s_ls);
    lock_now();
    UNLOCK();
    return to_esp(r);
}

// ---------- capacity and status ----------

uint32_t tw_store_record_bytes(size_t payload_len)
{
    uint32_t pl = plain_len(payload_len);
    return ls_record_size(pl ? NONCE_LEN + pl + TAG_LEN : LS_MAX_PAYLOAD);
}

bool tw_store_fits(uint32_t record_bytes)
{
    LOCK();
    bool r = ls_fits(s_ls, record_bytes);
    UNLOCK();
    return r;
}

void tw_store_stats(tw_store_stats_t *out)
{
    ls_stats_t st;
    LOCK();
    ls_get_stats(s_ls, &st);
    out->unlocked = s_unlocked;
    out->ciphers = s_unlocked ? s_count[K_CIPHER] : 0;
    out->folders = s_unlocked ? s_count[K_FOLDER] : 0;
    out->unreadable = s_unlocked ? s_unreadable : 0;
    UNLOCK();
    out->records = st.count[LS_KIND_SEALED];
    out->capacity = st.capacity;
    out->live_bytes = st.live_bytes;
    out->stale_bytes = st.stale_bytes;
    out->free_bytes = st.free_bytes;
    out->segs_total = st.segs_total;
    out->segs_free = st.segs_free;
    out->gc_runs = st.gc_runs;
    out->torn_records = st.torn_records;
    out->mount_ms = s_mount_ms;
}

// Only while unlocked: the change list on flash holds opaque ids, so each one is looked up and opened.
// A record that was changed again later shows its newest version; a deleted one shows no kind or id.
int tw_store_recent(tw_store_change_t *out, int max)
{
    ls_change_t ch[LS_RECENT_N];
    LOCK();
    if (!s_unlocked) {
        UNLOCK();
        return 0;
    }
    int n = ls_recent(s_ls, ch, max < LS_RECENT_N ? max : LS_RECENT_N);
    for (int i = 0; i < n; i++) {
        tw_store_change_t *c = &out[i];
        memset(c, 0, sizeof(*c));
        c->seq = ch[i].seq;
        c->op = ch[i].op == LS_OP_DEL ? "delete" : "save";
        c->kind = "?";
        if (ch[i].kind == LS_KIND_USER) {
            c->kind = "account";
            continue;
        }
        bool newest = true;  // the first (newest) change of this key in the list
        for (int k = 0; k < i; k++) newest = newest && memcmp(ch[k].id, ch[i].id, 16) != 0;
        char *data = NULL;
        uint32_t len = 0;
        opened_t o;
        if (ls_get(s_ls, LS_KIND_SEALED, ch[i].id, &data, &len) == LS_OK && unseal(ch[i].id, data, len, &o)) {
            c->kind = o.kind == K_USER ? "user" : o.kind == K_FOLDER ? "folder" : o.kind == K_CIPHER ? "item" : "test";
            format_uuid(o.id, c->id);
            if (newest && ch[i].op == LS_OP_PUT) c->time = o.time;
            free(o.buf);
        }
        free(data);
    }
    UNLOCK();
    return n;
}
