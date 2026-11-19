// Vault storage: the log-structured store (logstore.c) on the raw "storage" partition (SPEC 5).
// Callers keep using path-like names; they map to (kind, id) keys:
//   /tw/user.json            -> user
//   /tw/f/<uuid>.json        -> folder
//   /tw/c/[<x>/]<uuid>.json  -> cipher
//   /tw/t/[<x>/]<uuid>.json  -> development self-test records
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
#include "tw.h"

static const char *TAG = "store";
static const esp_partition_t *s_part;
static ls_store_t *s_ls;
static SemaphoreHandle_t s_lock;
static uint32_t s_mount_ms;

#define LOCK() xSemaphoreTakeRecursive(s_lock, portMAX_DELAY)
#define UNLOCK() xSemaphoreGiveRecursive(s_lock)

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

static uint32_t fl_now(void *ctx)
{
    (void)ctx;
    return (uint32_t)(tw_now_ms() / 1000);
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
    ESP_LOGI(TAG, "mounted in %u ms: %u ciphers, %u folders, %u KB live, %u torn", (unsigned)s_mount_ms,
             (unsigned)st.count[LS_KIND_CIPHER], (unsigned)st.count[LS_KIND_FOLDER], (unsigned)(st.live_bytes / 1024),
             (unsigned)st.torn_records);
    return ESP_OK;
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

static bool parse_path(const char *path, uint8_t *kind, uint8_t id[16])
{
    memset(id, 0, 16);
    if (strcmp(path, TW_USER_PATH) == 0) {
        *kind = LS_KIND_USER;
        return true;
    }
    if (parse_in_dir(path, TW_FOLDER_DIR, id)) {
        *kind = LS_KIND_FOLDER;
        return true;
    }
    if (parse_in_dir(path, TW_CIPHER_DIR, id)) {
        *kind = LS_KIND_CIPHER;
        return true;
    }
    if (parse_in_dir(path, TW_TEST_DIR, id)) {
        *kind = LS_KIND_TEST;
        return true;
    }
    ESP_LOGW(TAG, "unknown path %s", path);
    return false;
}

static bool parse_dir(const char *dir, uint8_t *kind)
{
    if (strcmp(dir, TW_FOLDER_DIR) == 0) *kind = LS_KIND_FOLDER;
    else if (strcmp(dir, TW_CIPHER_DIR) == 0) *kind = LS_KIND_CIPHER;
    else if (strcmp(dir, TW_TEST_DIR) == 0) *kind = LS_KIND_TEST;
    else return false;
    return true;
}

// ---------- API used by auth.c / api.c ----------

bool tw_store_exists(const char *path)
{
    uint8_t kind, id[16];
    if (!parse_path(path, &kind, id)) return false;
    LOCK();
    bool r = ls_exists(s_ls, kind, id);
    UNLOCK();
    return r;
}

cJSON *tw_store_read(const char *path)
{
    uint8_t kind, id[16];
    if (!parse_path(path, &kind, id)) return NULL;
    char *data = NULL;
    uint32_t len = 0;
    LOCK();
    int r = ls_get(s_ls, kind, id, &data, &len);
    UNLOCK();
    if (r != LS_OK) {
        if (r != LS_ERR_NOTFOUND) ESP_LOGE(TAG, "read %s: %d", path, r);
        return NULL;
    }
    cJSON *obj = cJSON_ParseWithLength(data, len);
    free(data);
    return obj;
}

esp_err_t tw_store_write(const char *path, const cJSON *obj)
{
    uint8_t kind, id[16];
    if (!parse_path(path, &kind, id)) return ESP_ERR_INVALID_ARG;
    char *text = cJSON_PrintUnformatted(obj);
    if (!text) return ESP_ERR_NO_MEM;
    LOCK();
    int r = ls_put(s_ls, kind, id, text, (uint32_t)strlen(text));
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
    uint8_t kind, id[16];
    if (!parse_path(path, &kind, id)) return ESP_ERR_INVALID_ARG;
    LOCK();
    int r = ls_del(s_ls, kind, id);
    UNLOCK();
    return to_esp(r);
}

typedef struct {
    const char *dir;
    tw_rec_cb cb;
    void *ctx;
    esp_err_t err;
} visit_t;

static int visit(uint8_t kind, const uint8_t id[16], const char *data, uint32_t len, void *arg)
{
    visit_t *v = arg;
    char uuid[37], path[96];
    format_uuid(id, uuid);
    if (kind == LS_KIND_CIPHER) snprintf(path, sizeof(path), "%s/%c/%s.json", v->dir, uuid[0], uuid);
    else snprintf(path, sizeof(path), "%s/%s.json", v->dir, uuid);
    v->err = v->cb(path, data, len, v->ctx);
    return v->err == ESP_OK ? LS_OK : LS_ERR_ARG;
}

esp_err_t tw_store_foreach(const char *dir, tw_rec_cb cb, void *ctx)
{
    uint8_t kind;
    if (!parse_dir(dir, &kind)) return ESP_ERR_INVALID_ARG;
    visit_t v = {.dir = dir, .cb = cb, .ctx = ctx, .err = ESP_OK};
    LOCK();
    int r = ls_foreach(s_ls, kind, visit, &v);
    UNLOCK();
    return v.err != ESP_OK ? v.err : to_esp(r);
}

int tw_store_count(const char *dir)
{
    uint8_t kind;
    if (!parse_dir(dir, &kind)) return 0;
    ls_stats_t st;
    LOCK();
    ls_get_stats(s_ls, &st);
    UNLOCK();
    return (int)st.count[kind];
}

typedef struct {
    uint8_t (*ids)[16];
    int n, cap;
} idlist_t;

static int collect(uint8_t kind, const uint8_t id[16], const char *data, uint32_t len, void *arg)
{
    (void)kind, (void)data, (void)len;
    idlist_t *l = arg;
    if (l->n == l->cap) {
        int nc = l->cap ? l->cap * 2 : 64;
        void *p = realloc(l->ids, (size_t)nc * 16);
        if (!p) return LS_ERR_NOMEM;
        l->ids = p;
        l->cap = nc;
    }
    memcpy(l->ids[l->n++], id, 16);
    return LS_OK;
}

esp_err_t tw_store_delete_all(const char *dir)
{
    uint8_t kind;
    if (!parse_dir(dir, &kind)) return ESP_ERR_INVALID_ARG;
    idlist_t l = {0};
    LOCK();
    int r = ls_foreach(s_ls, kind, collect, &l);
    for (int i = 0; r == LS_OK && i < l.n; i++) r = ls_del(s_ls, kind, l.ids[i]);
    UNLOCK();
    free(l.ids);
    return to_esp(r);
}

// Erase the whole partition, not just the records (SPEC 6)
esp_err_t tw_store_wipe(void)
{
    ESP_LOGW(TAG, "wiping storage");
    LOCK();
    int r = ls_format(s_ls);
    UNLOCK();
    return to_esp(r);
}

// ---------- capacity and status ----------

uint32_t tw_store_record_bytes(size_t payload_len)
{
    return ls_record_size((uint32_t)payload_len);
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
    UNLOCK();
    out->capacity = st.capacity;
    out->live_bytes = st.live_bytes;
    out->stale_bytes = st.stale_bytes;
    out->free_bytes = st.free_bytes;
    out->segs_total = st.segs_total;
    out->segs_free = st.segs_free;
    out->ciphers = st.count[LS_KIND_CIPHER];
    out->folders = st.count[LS_KIND_FOLDER];
    out->gc_runs = st.gc_runs;
    out->torn_records = st.torn_records;
    out->mount_ms = s_mount_ms;
}

int tw_store_recent(tw_store_change_t *out, int max)
{
    ls_change_t ch[LS_RECENT_N];
    LOCK();
    int n = ls_recent(s_ls, ch, max < LS_RECENT_N ? max : LS_RECENT_N);
    UNLOCK();
    for (int i = 0; i < n; i++) {
        out[i].time = ch[i].time;
        out[i].seq = ch[i].seq;
        out[i].kind = ch[i].kind == LS_KIND_USER     ? "user"
                      : ch[i].kind == LS_KIND_FOLDER ? "folder"
                      : ch[i].kind == LS_KIND_CIPHER ? "item"
                                                     : "test";
        out[i].op = ch[i].op == LS_OP_DEL ? "delete" : "save";
        format_uuid(ch[i].id, out[i].id);
    }
    return n;
}
