// HTTPS API that the Bitwarden browser extension talks to (SPEC 7).
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_https_server.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "mbedtls/sha256.h"
#include "mbedtls/pem.h"
#include "mbedtls/x509_crt.h"
#include "esp_log.h"
#include "tw.h"

static const char *TAG = "api";

static const char *const ALLOWED_ORIGINS[] = {
    "chrome-extension://nngceckbapebfimnlniiiahkandclblb",  // Chrome / Brave
};

// ---------- request log (status page; no console over USB) ----------

#define REQ_LOG_N 20
typedef struct {
    uint32_t uptime_s;
    char method[8];
    char path[56];  // query string dropped
    char status[4];
    char note[72];  // error message, if any
    char client[40];  // "<Bitwarden-Client-Name> <Bitwarden-Client-Version>", if sent
} req_log_t;
static req_log_t s_req_log[REQ_LOG_N];
static int s_req_log_next;
static const char *s_next_note;  // set by send_error just before the response is logged

// Apps seen since boot (TODO: "拡張機能やアプリの更新" — when an update breaks login, this shows
// which version did it). RAM only.
#define CLIENTS_N 6
typedef struct {
    char name[20];
    char version[20];
    char device_type[4];
    uint32_t first_s, last_s, count;
    uint32_t last_fail_s;  // 0: no failed login since boot
    char last_fail[140];
} client_seen_t;
static client_seen_t s_clients[CLIENTS_N];

// Header values are untrusted and end up in HTML: keep only harmless characters
static void hdr_safe(httpd_req_t *req, const char *name, char *out, size_t len)
{
    out[0] = '\0';
    if (httpd_req_get_hdr_value_str(req, name, out, len) != ESP_OK) {
        out[0] = '\0';
        return;
    }
    for (char *c = out; *c; c++) {
        if (!isalnum((unsigned char)*c) && !strchr(" ._-+()", *c)) *c = '?';
    }
}

static void note_client(httpd_req_t *req, req_log_t *e)
{
    char name[20], ver[20], dt[4];
    hdr_safe(req, "Bitwarden-Client-Name", name, sizeof(name));
    hdr_safe(req, "Bitwarden-Client-Version", ver, sizeof(ver));
    hdr_safe(req, "Device-Type", dt, sizeof(dt));
    snprintf(e->client, sizeof(e->client), "%s%s%s", name, name[0] && ver[0] ? " " : "", ver);
    if (!name[0] && !ver[0] && !dt[0]) {
        return;
    }
    client_seen_t *slot = NULL;
    for (int i = 0; i < CLIENTS_N && !slot; i++) {  // same app and version seen before
        client_seen_t *c = &s_clients[i];
        if (c->count && !strcmp(c->name, name) && !strcmp(c->version, ver) && !strcmp(c->device_type, dt)) slot = c;
    }
    if (!slot) {  // else an empty slot, else the one seen longest ago
        slot = &s_clients[0];
        for (int i = 0; i < CLIENTS_N; i++) {
            client_seen_t *c = &s_clients[i];
            if (!c->count) {
                slot = c;
                break;
            }
            if (c->last_s < slot->last_s) slot = c;
        }
        memset(slot, 0, sizeof(*slot));
        snprintf(slot->name, sizeof(slot->name), "%s", name);
        snprintf(slot->version, sizeof(slot->version), "%s", ver);
        snprintf(slot->device_type, sizeof(slot->device_type), "%s", dt);
        slot->first_s = e->uptime_s;
    }
    slot->last_s = e->uptime_s;
    slot->count++;
    if (e->status[0] != '2' && strncmp(e->path, "/identity/", 10) == 0) {
        slot->last_fail_s = e->uptime_s ? e->uptime_s : 1;
        snprintf(slot->last_fail, sizeof(slot->last_fail), "%s → %s %s", e->path, e->status, e->note);
    }
}

static void log_req(httpd_req_t *req, const char *status)
{
    req_log_t *e = &s_req_log[s_req_log_next];
    s_req_log_next = (s_req_log_next + 1) % REQ_LOG_N;
    e->uptime_s = (uint32_t)(esp_timer_get_time() / 1000000);
    snprintf(e->method, sizeof(e->method), "%s", http_method_str(req->method));
    size_t n = strcspn(req->uri, "?");
    if (n >= sizeof(e->path)) n = sizeof(e->path) - 1;
    memcpy(e->path, req->uri, n);
    e->path[n] = '\0';
    for (char *c = e->path; *c; c++) {  // shown in HTML
        if (*c == '<' || *c == '>' || *c == '&' || *c == '"' || *c == '\'') *c = '?';
    }
    snprintf(e->status, sizeof(e->status), "%.3s", status);
    snprintf(e->note, sizeof(e->note), "%s", s_next_note ? s_next_note : "");
    s_next_note = NULL;
    note_client(req, e);
}

static const char *device_type_str(const char *dt)
{
    // Bitwarden's DeviceType enum (Core/Enums/DeviceType.cs); only the ones that matter here
    static const char *names[] = {"Android", "iOS", "Chrome拡張", "Firefox拡張", "Opera拡張", "Edge拡張",
                                  "Windows版", "macOS版", "Linux版"};
    char *end;
    long v = strtol(dt, &end, 10);
    if (!dt[0] || *end || v < 0 || v >= (long)(sizeof(names) / sizeof(names[0]))) return "";
    return names[v];
}

// ---------- response helpers ----------

static void add_cors(httpd_req_t *req)
{
    static char origin[128];
    if (httpd_req_get_hdr_value_str(req, "Origin", origin, sizeof(origin)) != ESP_OK) {
        return;
    }
    for (size_t i = 0; i < sizeof(ALLOWED_ORIGINS) / sizeof(ALLOWED_ORIGINS[0]); i++) {
        if (strcmp(origin, ALLOWED_ORIGINS[i]) == 0) {
            httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", ALLOWED_ORIGINS[i]);
            httpd_resp_set_hdr(req, "Access-Control-Allow-Credentials", "true");
            httpd_resp_set_hdr(req, "Vary", "Origin");
            return;
        }
    }
}

static esp_err_t send_json(httpd_req_t *req, const char *status, cJSON *obj)
{
    log_req(req, status);
    add_cors(req);
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    char *text = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    if (!text) {
        return httpd_resp_send_500(req);
    }
    esp_err_t err = httpd_resp_sendstr(req, text);
    free(text);
    return err;
}

static esp_err_t send_raw(httpd_req_t *req, const char *status, const char *json)
{
    log_req(req, status);
    add_cors(req);
    httpd_resp_set_status(req, status);
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    return httpd_resp_sendstr(req, json);
}

// Error body in the shape Vaultwarden sends, so the extension shows the message
static esp_err_t send_error_ex(httpd_req_t *req, const char *status, const char *msg, bool validation)
{
    s_next_note = msg;
    cJSON *e = cJSON_CreateObject();
    cJSON_AddStringToObject(e, "message", msg);
    cJSON_AddStringToObject(e, "error", "");
    cJSON_AddStringToObject(e, "error_description", "");
    if (validation) {
        cJSON *ve = cJSON_AddObjectToObject(e, "validationErrors");
        cJSON *arr = cJSON_AddArrayToObject(ve, "");
        cJSON_AddItemToArray(arr, cJSON_CreateString(msg));
    } else {
        cJSON_AddNullToObject(e, "validationErrors");
    }
    cJSON *em = cJSON_AddObjectToObject(e, "ErrorModel");
    cJSON_AddStringToObject(em, "Message", msg);
    cJSON_AddStringToObject(em, "Object", "error");
    cJSON_AddStringToObject(e, "Object", "error");
    return send_json(req, status, e);
}

static esp_err_t send_error(httpd_req_t *req, const char *status, const char *msg)
{
    return send_error_ex(req, status, msg, true);
}

// The import page reads validationErrors keys as "<type>[<index>]" and crashes on anything else,
// so import errors carry only the message
static esp_err_t send_import_error(httpd_req_t *req, const char *status, const char *msg)
{
    return send_error_ex(req, status, msg, false);
}

static char *read_body(httpd_req_t *req)
{
    if (req->content_len > TW_MAX_BODY) {
        return NULL;
    }
    char *buf = malloc(req->content_len + 1);
    if (!buf) {
        return NULL;
    }
    size_t got = 0;
    while (got < req->content_len) {
        int r = httpd_req_recv(req, buf + got, req->content_len - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) {
            continue;
        }
        if (r <= 0) {
            free(buf);
            return NULL;
        }
        got += r;
    }
    buf[got] = '\0';
    return buf;
}

static cJSON *read_json(httpd_req_t *req)
{
    char *body = read_body(req);
    if (!body) {
        return NULL;
    }
    cJSON *obj = cJSON_Parse(body);
    free(body);
    return obj;
}

// "/api/ciphers/<id>/delete?x=1" -> id="<id>", action="delete"
static bool split_id(const char *uri, const char *prefix, char id[37], char *action, size_t action_len)
{
    size_t pl = strlen(prefix);
    if (strncmp(uri, prefix, pl) != 0) {
        return false;
    }
    const char *p = uri + pl;
    const char *q = strchr(p, '?');
    size_t len = q ? (size_t)(q - p) : strlen(p);
    if (len < 36) {
        return false;
    }
    memcpy(id, p, 36);
    id[36] = '\0';
    if (!tw_is_uuid(id)) {
        return false;
    }
    action[0] = '\0';
    if (len > 37 && p[36] == '/') {
        size_t al = len - 37;
        if (al >= action_len) al = action_len - 1;
        memcpy(action, p + 37, al);
        action[al] = '\0';
    } else if (len != 36) {
        return false;
    }
    return true;
}

static bool path_is(httpd_req_t *req, const char *path)
{
    size_t n = strlen(path);
    return strncmp(req->uri, path, n) == 0 && (req->uri[n] == '\0' || req->uri[n] == '?');
}

#define OLD_FORMAT_MSG "Old format. Erase the device and set it up again"

#define REQUIRE_AUTH(req)                                              \
    do {                                                               \
        if (!tw_auth_check_bearer(req)) {                              \
            return send_error(req, "401 Unauthorized", "Unauthorized"); \
        }                                                              \
    } while (0)

// ---------- status page session (cookie "sid", RAM only) ----------
// The status page and its tools need the vault's username and master password (POST /s/unlock, checked
// like a login: button, failure counter). Before that, / shows only device information and nothing on
// the device answers to the tools' URLs (404), so a stranger at the USB link cannot tell what it is.
#define SESS_N 2
#define SESS_MS (30 * 60 * 1000)
static char s_sess[SESS_N][48];
static int64_t s_sess_until[SESS_N];
static int s_sess_next;

bool tw_status_session_ok(httpd_req_t *req)
{
    char ck[256];
    if (httpd_req_get_hdr_value_str(req, "Cookie", ck, sizeof(ck)) != ESP_OK) return false;
    char *p = ck;
    while ((p = strstr(p, "sid=")) && p != ck && p[-1] != ' ' && p[-1] != ';') p += 4;
    if (!p) return false;
    p += 4;
    size_t n = strcspn(p, "; ");
    int64_t now = esp_timer_get_time() / 1000;
    for (int i = 0; i < SESS_N; i++) {
        if (s_sess[i][0] && strlen(s_sess[i]) == n && tw_ct_equal((const uint8_t *)p, (const uint8_t *)s_sess[i], n) &&
            now < s_sess_until[i]) {
            return true;
        }
    }
    return false;
}

static void sessions_clear(void)
{
    memset(s_sess, 0, sizeof(s_sess));
}

#define REQUIRE_SESSION(req)                                   \
    do {                                                       \
        if (!tw_status_session_ok(req)) {                      \
            httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not found"); \
            return ESP_OK;                                     \
        }                                                      \
    } while (0)

static void bump_revision(void)
{
    tw_clock_persist();
}

// ---------- JSON builders ----------

static cJSON *dup_or_null(const cJSON *o, const char *k)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    return v ? cJSON_Duplicate(v, true) : cJSON_CreateNull();
}

static cJSON *account_keys_json(const cJSON *user)
{
    const cJSON *stored = cJSON_GetObjectItemCaseSensitive(user, "accountKeys");
    if (stored && !cJSON_IsNull(stored)) {
        return cJSON_Duplicate(stored, true);
    }
    const cJSON *priv = cJSON_GetObjectItemCaseSensitive(user, "privateKey");
    if (!cJSON_IsString(priv)) {
        return cJSON_CreateNull();
    }
    cJSON *ak = cJSON_CreateObject();
    cJSON *pk = cJSON_AddObjectToObject(ak, "publicKeyEncryptionKeyPair");
    cJSON_AddItemToObject(pk, "wrappedPrivateKey", dup_or_null(user, "privateKey"));
    cJSON_AddItemToObject(pk, "publicKey", dup_or_null(user, "publicKey"));
    cJSON_AddNullToObject(pk, "signedPublicKey");
    cJSON_AddStringToObject(pk, "object", "publicKeyEncryptionKeyPair");
    cJSON_AddNullToObject(ak, "securityState");
    cJSON_AddNullToObject(ak, "signatureKeyPair");
    cJSON_AddStringToObject(ak, "object", "privateKeys");
    return ak;
}

// email: the session's username (from its token), or NULL (backup: nothing that names the owner)
static cJSON *profile_json(const cJSON *user, const char *email)
{
    cJSON *p = cJSON_CreateObject();
    cJSON_AddNumberToObject(p, "_status", 0);
    cJSON_AddItemToObject(p, "accountKeys", account_keys_json(user));
    cJSON_AddItemToObject(p, "id", dup_or_null(user, "id"));
    cJSON_AddItemToObject(p, "name", dup_or_null(user, "name"));
    cJSON_AddItemToObject(p, "email", email ? cJSON_CreateString(email) : cJSON_CreateNull());
    cJSON_AddBoolToObject(p, "emailVerified", true);
    cJSON_AddBoolToObject(p, "premium", true);
    cJSON_AddBoolToObject(p, "premiumFromOrganization", false);
    cJSON_AddStringToObject(p, "culture", "en-US");
    cJSON_AddBoolToObject(p, "twoFactorEnabled", false);
    cJSON_AddItemToObject(p, "key", dup_or_null(user, "key"));
    cJSON_AddItemToObject(p, "privateKey", dup_or_null(user, "privateKey"));
    cJSON_AddItemToObject(p, "securityStamp", dup_or_null(user, "securityStamp"));
    cJSON_AddArrayToObject(p, "organizations");
    cJSON_AddArrayToObject(p, "organizationsNew");
    cJSON_AddArrayToObject(p, "providers");
    cJSON_AddArrayToObject(p, "providerOrganizations");
    cJSON_AddBoolToObject(p, "forcePasswordReset", false);
    cJSON_AddNullToObject(p, "avatarColor");
    cJSON_AddBoolToObject(p, "usesKeyConnector", false);
    cJSON_AddItemToObject(p, "creationDate", dup_or_null(user, "creationDate"));
    cJSON_AddStringToObject(p, "object", "profile");
    return p;
}

// camel=true for sync ("kdfType"), false for connect/token ("KdfType") - the two differ upstream.
// The salt of the master key is the username, which only the session knows (NULL: null).
static cJSON *mp_unlock_json(const cJSON *user, const char *email, bool camel)
{
    cJSON *u = cJSON_CreateObject();
    cJSON *k = cJSON_AddObjectToObject(u, camel ? "kdf" : "Kdf");
    cJSON_AddItemToObject(k, camel ? "kdfType" : "KdfType", dup_or_null(user, "kdf"));
    cJSON_AddItemToObject(k, camel ? "iterations" : "Iterations", dup_or_null(user, "kdfIterations"));
    cJSON_AddItemToObject(k, camel ? "memory" : "Memory", dup_or_null(user, "kdfMemory"));
    cJSON_AddItemToObject(k, camel ? "parallelism" : "Parallelism", dup_or_null(user, "kdfParallelism"));
    cJSON_AddItemToObject(u, camel ? "masterKeyEncryptedUserKey" : "MasterKeyEncryptedUserKey", dup_or_null(user, "key"));
    cJSON_AddItemToObject(u, camel ? "masterKeyWrappedUserKey" : "MasterKeyWrappedUserKey", dup_or_null(user, "key"));
    if (email) {
        char em[256];
        tw_email_norm(email, em, sizeof(em));
        cJSON_AddStringToObject(u, camel ? "salt" : "Salt", em);
    } else {
        cJSON_AddNullToObject(u, camel ? "salt" : "Salt");
    }
    if (camel) {
        cJSON_AddItemToObject(u, "containedKeyId", dup_or_null(user, "userKeyId"));
    }
    return u;
}

// ---------- handlers: no auth ----------

static esp_err_t h_options(httpd_req_t *req)
{
    add_cors(req);
    char buf[256];
    if (httpd_req_get_hdr_value_str(req, "Access-Control-Request-Headers", buf, sizeof(buf)) == ESP_OK) {
        httpd_resp_set_hdr(req, "Access-Control-Allow-Headers", buf);
    }
    httpd_resp_set_hdr(req, "Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    httpd_resp_set_hdr(req, "Access-Control-Max-Age", "600");
    return httpd_resp_send(req, NULL, 0);
}

// Result of starting the port-80 server, reported on /alive because there is no console over USB
static esp_err_t s_http_err = ESP_ERR_INVALID_STATE;  // not tried yet
static char s_diag[96];

static esp_err_t h_alive(httpd_req_t *req)
{
    snprintf(s_diag, sizeof(s_diag), "http80=%s heap_int=%u largest_int=%u",
             esp_err_to_name(s_http_err),
             (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
             (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
    httpd_resp_set_hdr(req, "X-Diag", s_diag);
    char iso[32], out[40];
    tw_now_iso(iso);
    snprintf(out, sizeof(out), "\"%s\"", iso);
    return send_raw(req, "200 OK", out);
}

static esp_err_t h_config(httpd_req_t *req)
{
    cJSON *c = cJSON_CreateObject();
    cJSON_AddStringToObject(c, "version", "2026.6.0");
    cJSON_AddNullToObject(c, "gitHash");
    cJSON *srv = cJSON_AddObjectToObject(c, "server");
    cJSON_AddStringToObject(srv, "name", "local");
    cJSON_AddStringToObject(srv, "url", "https://github.com/");
    cJSON *set = cJSON_AddObjectToObject(c, "settings");
    cJSON_AddBoolToObject(set, "disableUserRegistration", tw_user_exists());
    cJSON *env = cJSON_AddObjectToObject(c, "environment");
    cJSON_AddStringToObject(env, "vault", TW_ORIGIN);
    cJSON_AddStringToObject(env, "api", TW_ORIGIN "/api");
    cJSON_AddStringToObject(env, "identity", TW_ORIGIN "/identity");
    cJSON_AddStringToObject(env, "notifications", TW_ORIGIN "/notifications");
    cJSON_AddStringToObject(env, "sso", "");
    cJSON_AddNullToObject(env, "cloudRegion");
    cJSON *push = cJSON_AddObjectToObject(c, "push");
    cJSON_AddNumberToObject(push, "pushTechnology", 0);
    cJSON_AddNullToObject(push, "vapidPublicKey");
    cJSON_AddObjectToObject(c, "featureStates");
    cJSON_AddStringToObject(c, "object", "config");
    return send_json(req, "200 OK", c);
}

static esp_err_t h_prelogin(httpd_req_t *req)
{
    // The same answer for any username: the board does not know which one is right (SPEC 6)
    cJSON *body = read_json(req);
    cJSON *user = tw_head_load();
    bool match = user != NULL;

    cJSON *r = cJSON_CreateObject();
    cJSON *kdf = match ? dup_or_null(user, "kdf") : cJSON_CreateNumber(0);
    cJSON *it = match ? dup_or_null(user, "kdfIterations") : cJSON_CreateNumber(600000);
    cJSON *mem = match ? dup_or_null(user, "kdfMemory") : cJSON_CreateNull();
    cJSON *par = match ? dup_or_null(user, "kdfParallelism") : cJSON_CreateNull();
    cJSON *ks = cJSON_CreateObject();
    cJSON_AddItemToObject(ks, "iterations", cJSON_Duplicate(it, true));
    cJSON_AddItemToObject(ks, "kdfType", cJSON_Duplicate(kdf, true));
    cJSON_AddItemToObject(ks, "memory", cJSON_Duplicate(mem, true));
    cJSON_AddItemToObject(ks, "parallelism", cJSON_Duplicate(par, true));
    cJSON_AddItemToObject(r, "kdf", kdf);
    cJSON_AddItemToObject(r, "kdfIterations", it);
    cJSON_AddItemToObject(r, "kdfMemory", mem);
    cJSON_AddItemToObject(r, "kdfParallelism", par);
    cJSON_AddItemToObject(r, "kdfSettings", ks);
    cJSON_AddNullToObject(r, "salt");
    cJSON_Delete(body);
    cJSON_Delete(user);
    return send_json(req, "200 OK", r);
}

static esp_err_t h_register_email(httpd_req_t *req)
{
    cJSON *body = read_json(req);
    const cJSON *email = body ? cJSON_GetObjectItemCaseSensitive(body, "email") : NULL;
    if (tw_user_exists() || !cJSON_IsString(email)) {
        cJSON_Delete(body);
        return send_error(req, "400 Bad Request", "Registration not allowed or user already exists");
    }
    const cJSON *name = cJSON_GetObjectItemCaseSensitive(body, "name");
    const char *token = tw_auth_pending_register_token(cJSON_IsString(name) ? name->valuestring : NULL);
    cJSON_Delete(body);

    char accept[128] = "";
    httpd_req_get_hdr_value_str(req, "Accept", accept, sizeof(accept));
    log_req(req, "200");
    add_cors(req);
    if (strstr(accept, "application/json")) {
        char out[64];
        snprintf(out, sizeof(out), "\"%s\"", token);
        httpd_resp_set_type(req, "application/json; charset=utf-8");
        return httpd_resp_sendstr(req, out);
    }
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    return httpd_resp_sendstr(req, token);
}

static esp_err_t h_register_finish(httpd_req_t *req)
{
    cJSON *body = read_json(req);
    if (!body) {
        return send_error(req, "400 Bad Request", "Invalid body");
    }
    esp_err_t err = tw_auth_register(body);
    cJSON_Delete(body);
    switch (err) {
    case ESP_OK: {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddStringToObject(r, "object", "registerFinish");
        return send_json(req, "200 OK", r);
    }
    case ESP_ERR_INVALID_STATE:
        return send_error(req, "400 Bad Request", "This device already has a user");
    case ESP_ERR_TIMEOUT:
        return send_error(req, "400 Bad Request", "Press the button on the device within 30 seconds");
    default:
        return send_error(req, "400 Bad Request", "Registration failed");
    }
}

static void remember_device(const char *device_id)
{
    if (!device_id || !device_id[0]) {
        return;
    }
    cJSON *user = tw_user_load();
    if (!user) {
        return;
    }
    cJSON *devs = cJSON_GetObjectItemCaseSensitive(user, "devices");
    if (!cJSON_IsArray(devs)) {
        devs = cJSON_AddArrayToObject(user, "devices");
    }
    const cJSON *d;
    cJSON_ArrayForEach(d, devs) {
        if (cJSON_IsString(d) && strcmp(d->valuestring, device_id) == 0) {
            cJSON_Delete(user);
            return;
        }
    }
    cJSON_AddItemToArray(devs, cJSON_CreateString(device_id));
    tw_user_save(user);
    cJSON_Delete(user);
}

static esp_err_t token_response(httpd_req_t *req, const char *email, const char *device_id, const char *device_type)
{
    cJSON *user = tw_user_load();
    if (!user) {
        return send_error(req, "400 Bad Request", "No user");
    }
    char *access = tw_auth_issue_access(user, email, device_id, device_type);
    char *refresh = tw_auth_issue_refresh(email);
    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "access_token", access ? access : "");
    cJSON_AddNumberToObject(r, "expires_in", 7200);
    cJSON_AddStringToObject(r, "token_type", "Bearer");
    cJSON_AddStringToObject(r, "refresh_token", refresh ? refresh : "");
    cJSON_AddItemToObject(r, "PrivateKey", dup_or_null(user, "privateKey"));
    cJSON_AddItemToObject(r, "Key", dup_or_null(user, "key"));
    cJSON_AddItemToObject(r, "Kdf", dup_or_null(user, "kdf"));
    cJSON_AddItemToObject(r, "KdfIterations", dup_or_null(user, "kdfIterations"));
    cJSON_AddItemToObject(r, "KdfMemory", dup_or_null(user, "kdfMemory"));
    cJSON_AddItemToObject(r, "KdfParallelism", dup_or_null(user, "kdfParallelism"));
    cJSON_AddBoolToObject(r, "ForcePasswordReset", false);
    cJSON *mpp = cJSON_AddObjectToObject(r, "MasterPasswordPolicy");
    cJSON_AddStringToObject(mpp, "object", "masterPasswordPolicy");
    cJSON_AddStringToObject(r, "scope", "api offline_access");
    cJSON_AddItemToObject(r, "AccountKeys", account_keys_json(user));
    cJSON *udo = cJSON_AddObjectToObject(r, "UserDecryptionOptions");
    cJSON_AddBoolToObject(udo, "HasMasterPassword", true);
    cJSON_AddItemToObject(udo, "MasterPasswordUnlock", mp_unlock_json(user, email, false));
    cJSON_AddStringToObject(udo, "Object", "userDecryptionOptions");
    free(access);
    free(refresh);
    cJSON_Delete(user);
    return send_json(req, "200 OK", r);
}

static esp_err_t token_error(httpd_req_t *req, const char *msg)
{
    cJSON *e = cJSON_CreateObject();
    cJSON_AddStringToObject(e, "error", "invalid_grant");
    cJSON_AddStringToObject(e, "error_description", "invalid_username_or_password");
    cJSON *em = cJSON_AddObjectToObject(e, "ErrorModel");
    cJSON_AddStringToObject(em, "Message", msg);
    cJSON_AddStringToObject(em, "Object", "error");
    return send_json(req, "400 Bad Request", e);
}

static esp_err_t h_token(httpd_req_t *req)
{
    char *body = read_body(req);
    if (!body) {
        return token_error(req, "Invalid body");
    }
    char grant[32] = "", device_id[64] = "", device_type[16] = "";
    tw_form_get(body, "grant_type", grant, sizeof(grant));
    tw_form_get(body, "deviceIdentifier", device_id, sizeof(device_id));
    tw_form_get(body, "deviceType", device_type, sizeof(device_type));

    esp_err_t err;
    if (strcmp(grant, "password") == 0) {
        char *email = calloc(1, 256), *hash = calloc(1, 512);
        if (!email || !hash) {
            free(email);
            free(hash);
            free(body);
            return httpd_resp_send_500(req);
        }
        tw_form_get(body, "username", email, 256);
        tw_form_get(body, "password", hash, 512);
        tw_login_result_t res = tw_auth_check_password(hash);
        free(hash);
        switch (res) {
        case TW_LOGIN_OK:
            remember_device(device_id);
            err = token_response(req, email, device_id, device_type);
            break;
        case TW_LOGIN_OLD_FORMAT:
            err = token_error(req, OLD_FORMAT_MSG);
            break;
        case TW_LOGIN_NO_BUTTON:
            err = token_error(req, "Press the button on the device within 30 seconds");
            break;
        case TW_LOGIN_WIPED:
            err = token_error(req, "Too many failed attempts. The device has been erased");
            break;
        default:
            err = token_error(req, "Username or password is incorrect. Try again");
        }
        free(email);
    } else if (strcmp(grant, "refresh_token") == 0) {
        char tok[64] = "", email[256] = "";
        tw_form_get(body, "refresh_token", tok, sizeof(tok));
        err = tw_auth_use_refresh(tok, email, sizeof(email)) ? token_response(req, email, device_id, device_type)
                                                             : token_error(req, "Invalid refresh token");
    } else {
        err = token_error(req, "Unsupported grant type");
    }
    free(body);
    return err;
}

static esp_err_t h_known_device(httpd_req_t *req)
{
    // By device id only (the username is not stored). The device list is sealed, so until someone logs in
    // after a restart every device is "new", which only changes what the login screen offers.
    char dev[64] = "";
    httpd_req_get_hdr_value_str(req, "X-Device-Identifier", dev, sizeof(dev));

    bool known = false;
    cJSON *user = tw_store_unlocked() ? tw_user_load() : NULL;
    if (user) {
        const cJSON *d;
        cJSON_ArrayForEach(d, cJSON_GetObjectItemCaseSensitive(user, "devices")) {
            if (cJSON_IsString(d) && strcmp(d->valuestring, dev) == 0) known = true;
        }
    }
    cJSON_Delete(user);
    return send_raw(req, "200 OK", known ? "true" : "false");
}

// ---------- handlers: account ----------

static esp_err_t h_profile(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    char email[256];
    tw_auth_bearer_email(req, email, sizeof(email));
    cJSON *user = tw_user_load();
    if (!user) {
        return send_error(req, "400 Bad Request", "No user");
    }
    cJSON *p = profile_json(user, email);
    cJSON_Delete(user);
    return send_json(req, "200 OK", p);
}

// Always "now", so the extension syncs on every check (SPEC 4)
static esp_err_t h_revision_date(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    char out[24];
    snprintf(out, sizeof(out), "%lld", (long long)tw_now_ms());
    return send_raw(req, "200 OK", out);
}

static esp_err_t h_user_key_id(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    cJSON *body = read_json(req);
    cJSON *user = tw_user_load();
    const cJSON *kid = body ? cJSON_GetObjectItemCaseSensitive(body, "keyId") : NULL;
    if (user && cJSON_IsString(kid)) {
        cJSON_ReplaceItemInObjectCaseSensitive(user, "userKeyId", cJSON_CreateString(kid->valuestring));
        tw_user_save(user);
    }
    cJSON_Delete(body);
    cJSON_Delete(user);
    add_cors(req);
    return httpd_resp_send(req, NULL, 0);
}

static esp_err_t h_auth_pending(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    return send_raw(req, "200 OK", "{\"data\":[],\"continuationToken\":null,\"object\":\"list\"}");
}

// ---------- sync (streamed from flash) ----------

typedef struct {
    httpd_req_t *req;
    bool first;
    char *buf;  // batches small records into fewer TLS records and HTTP chunks
    size_t len;
    esp_err_t err;
} stream_ctx_t;

#define STREAM_BUF 8192

static esp_err_t stream_flush(stream_ctx_t *ctx)
{
    if (ctx->len && ctx->err == ESP_OK) ctx->err = httpd_resp_send_chunk(ctx->req, ctx->buf, ctx->len);
    ctx->len = 0;
    return ctx->err;
}

static esp_err_t stream_put(stream_ctx_t *ctx, const char *data, size_t len)
{
    if (!ctx->buf) return httpd_resp_send_chunk(ctx->req, data, len);
    if (ctx->len + len > STREAM_BUF) stream_flush(ctx);
    if (len > STREAM_BUF) return ctx->err == ESP_OK ? (ctx->err = httpd_resp_send_chunk(ctx->req, data, len)) : ctx->err;
    memcpy(ctx->buf + ctx->len, data, len);
    ctx->len += len;
    return ctx->err;
}

static esp_err_t stream_file(const char *path, const char *data, size_t len, void *arg)
{
    (void)path;
    stream_ctx_t *ctx = arg;
    if (!ctx->first) {
        stream_put(ctx, ",", 1);
    }
    ctx->first = false;
    return stream_put(ctx, data, len);
}

static esp_err_t send_chunk_json(httpd_req_t *req, cJSON *obj)
{
    char *text = cJSON_PrintUnformatted(obj);
    cJSON_Delete(obj);
    if (!text) return ESP_ERR_NO_MEM;
    esp_err_t err = httpd_resp_send_chunk(req, text, strlen(text));
    free(text);
    return err;
}

// The sync object, streamed. Also the "sync" part of a backup (h_backup, email NULL).
static void stream_sync(httpd_req_t *req, cJSON *user, const char *email)
{
    httpd_resp_sendstr_chunk(req, "{\"profile\":");
    send_chunk_json(req, profile_json(user, email));
    httpd_resp_sendstr_chunk(req, ",\"folders\":[");
    stream_ctx_t ctx = {.req = req, .first = true, .buf = malloc(STREAM_BUF)};
    tw_store_foreach(TW_FOLDER_DIR, stream_file, &ctx);
    const char *mid = "],\"collections\":[],\"policies\":[],\"policiesNew\":[],\"ciphers\":[";
    stream_put(&ctx, mid, strlen(mid));
    ctx.first = true;
    tw_store_foreach(TW_CIPHER_DIR, stream_file, &ctx);
    stream_flush(&ctx);
    free(ctx.buf);
    httpd_resp_sendstr_chunk(req, "],\"domains\":null,\"sends\":[],\"userDecryption\":");
    cJSON *ud = cJSON_CreateObject();
    cJSON_AddItemToObject(ud, "masterPasswordUnlock", mp_unlock_json(user, email, true));
    const cJSON *kid = cJSON_GetObjectItemCaseSensitive(user, "userKeyId");
    if (cJSON_IsString(kid)) {
        cJSON_AddStringToObject(ud, "userKeyId", kid->valuestring);
    }
    send_chunk_json(req, ud);
    httpd_resp_sendstr_chunk(req, ",\"object\":\"sync\"}");
}

static esp_err_t h_sync(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    char email[256];
    tw_auth_bearer_email(req, email, sizeof(email));
    cJSON *user = tw_user_load();
    if (!user) {
        return send_error(req, "400 Bad Request", "No user");
    }
    log_req(req, "200");
    add_cors(req);
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    stream_sync(req, user, email);
    cJSON_Delete(user);
    return httpd_resp_send_chunk(req, NULL, 0);
}

// POST /s/backup from the status page: the whole vault, still encrypted, in the format of
// tools/tw_backup.py fetch (so its decrypt reads it). Needs the master password (as the login hash,
// computed in the page; the password itself never reaches the board) and the BOOT button, checked
// exactly like a login: failures count toward the wipe (SPEC 6).
static esp_err_t h_backup(httpd_req_t *req)
{
    REQUIRE_SESSION(req);
    char confirm[16] = "";
    httpd_req_get_hdr_value_str(req, "X-Confirm", confirm, sizeof(confirm));
    if (strcmp(confirm, "backup") != 0) {
        return send_error(req, "400 Bad Request", "Missing confirmation");
    }
    cJSON *body = read_json(req);
    const cJSON *mph = body ? cJSON_GetObjectItemCaseSensitive(body, "masterPasswordHash") : NULL;
    if (!cJSON_IsString(mph)) {
        cJSON_Delete(body);
        return send_error(req, "400 Bad Request", "Username and master password are required");
    }
    tw_login_result_t res = tw_auth_check_password(mph->valuestring);
    cJSON_Delete(body);
    switch (res) {
    case TW_LOGIN_OK:
        break;
    case TW_LOGIN_OLD_FORMAT:
        return send_error(req, "400 Bad Request", OLD_FORMAT_MSG);
    case TW_LOGIN_NO_BUTTON:
        return send_error(req, "400 Bad Request", "Button not pressed within 30 seconds");
    case TW_LOGIN_WIPED:
        return send_error(req, "400 Bad Request", "Too many failed attempts. The device has been erased");
    default:
        return send_error(req, "400 Bad Request", "Username or master password is incorrect");
    }
    cJSON *user = tw_user_load();
    if (!user) {
        return send_error(req, "400 Bad Request", "No user");
    }
    log_req(req, "200");
    httpd_resp_set_type(req, "application/json; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    cJSON *head = cJSON_CreateObject();
    char iso[32];
    tw_now_iso(iso);
    // Version 2: no email. Opening it needs the username, typed in (tools/tw_backup.py, the merge page).
    cJSON_AddNumberToObject(head, "tinywarden_backup", 2);
    cJSON_AddStringToObject(head, "saved", iso);
    cJSON *pre = cJSON_AddObjectToObject(head, "prelogin");
    cJSON_AddItemToObject(pre, "kdf", dup_or_null(user, "kdf"));
    cJSON_AddItemToObject(pre, "kdfIterations", dup_or_null(user, "kdfIterations"));
    cJSON_AddItemToObject(pre, "kdfMemory", dup_or_null(user, "kdfMemory"));
    cJSON_AddItemToObject(pre, "kdfParallelism", dup_or_null(user, "kdfParallelism"));
    char *h = cJSON_PrintUnformatted(head);
    cJSON_Delete(head);
    if (!h) {
        cJSON_Delete(user);
        return httpd_resp_send_500(req);
    }
    h[strlen(h) - 1] = '\0';  // drop the closing brace, "sync" follows
    httpd_resp_sendstr_chunk(req, h);
    free(h);
    httpd_resp_sendstr_chunk(req, ",\"sync\":");
    stream_sync(req, user, NULL);
    httpd_resp_sendstr_chunk(req, "}");
    cJSON_Delete(user);
    return httpd_resp_send_chunk(req, NULL, 0);
}

// ---------- changing the KDF (status page) ----------
// Two steps under one BOOT press. 1: POST /s/kdf/key checks the current password (button, failure
// counter) and returns the user key as it is now wrapped, with a one-time token. The page unwraps it
// with the old master key, derives the new one and wraps it again, then 2: POST /s/kdf with the token
// stores the new wrapping, KDF settings and login hash (tw_auth_set_master). The board never sees the
// password or the user key.
#define KDF_TOKEN_MS (120 * 1000)
static char s_kdf_token[48];
static int64_t s_kdf_token_until;

static bool kdf_settings_ok(const cJSON *b)
{
    const cJSON *t = cJSON_GetObjectItemCaseSensitive(b, "kdf");
    const cJSON *i = cJSON_GetObjectItemCaseSensitive(b, "kdfIterations");
    const cJSON *m = cJSON_GetObjectItemCaseSensitive(b, "kdfMemory");
    const cJSON *p = cJSON_GetObjectItemCaseSensitive(b, "kdfParallelism");
    if (!cJSON_IsNumber(t) || !cJSON_IsNumber(i)) return false;
    if (t->valueint == 0) return i->valueint >= 600000 && i->valueint <= 2000000;
    // Argon2id: the clients' own limits (iterations 2-10, memory 16-1024 MiB, parallelism 1-16)
    return t->valueint == 1 && cJSON_IsNumber(m) && cJSON_IsNumber(p) && i->valueint >= 2 && i->valueint <= 10 &&
           m->valueint >= 16 && m->valueint <= 1024 && p->valueint >= 1 && p->valueint <= 16;
}

// "2.<iv>|<ct>|<mac>" with base64 parts (EncString type 2)
static bool is_enc2(const char *s)
{
    if (!s || strncmp(s, "2.", 2) != 0 || strlen(s) > 512) return false;
    int bars = 0;
    for (const char *c = s + 2; *c; c++) {
        if (*c == '|') bars++;
        else if (!isalnum((unsigned char)*c) && *c != '+' && *c != '/' && *c != '=') return false;
    }
    return bars == 2;
}

static esp_err_t h_kdf_key(httpd_req_t *req)
{
    REQUIRE_SESSION(req);
    char confirm[16] = "";
    httpd_req_get_hdr_value_str(req, "X-Confirm", confirm, sizeof(confirm));
    if (strcmp(confirm, "kdf") != 0) {
        return send_error(req, "400 Bad Request", "Missing confirmation");
    }
    cJSON *body = read_json(req);
    const cJSON *mph = body ? cJSON_GetObjectItemCaseSensitive(body, "masterPasswordHash") : NULL;
    if (!cJSON_IsString(mph)) {
        cJSON_Delete(body);
        return send_error(req, "400 Bad Request", "Username and master password are required");
    }
    tw_login_result_t res = tw_auth_check_password(mph->valuestring);
    cJSON_Delete(body);
    switch (res) {
    case TW_LOGIN_OK:
        break;
    case TW_LOGIN_OLD_FORMAT:
        return send_error(req, "400 Bad Request", OLD_FORMAT_MSG);
    case TW_LOGIN_NO_BUTTON:
        return send_error(req, "400 Bad Request", "Button not pressed within 30 seconds");
    case TW_LOGIN_WIPED:
        return send_error(req, "400 Bad Request", "Too many failed attempts. The device has been erased");
    default:
        return send_error(req, "400 Bad Request", "Username or master password is incorrect");
    }
    cJSON *user = tw_user_load();
    if (!user) {
        return send_error(req, "400 Bad Request", "No user");
    }
    uint8_t raw[32];
    tw_random(raw, sizeof(raw));
    tw_b64url_encode(raw, sizeof(raw), s_kdf_token, sizeof(s_kdf_token));
    s_kdf_token_until = esp_timer_get_time() / 1000 + KDF_TOKEN_MS;
    cJSON *r = cJSON_CreateObject();
    cJSON_AddItemToObject(r, "key", dup_or_null(user, "key"));
    cJSON_AddItemToObject(r, "kdf", dup_or_null(user, "kdf"));
    cJSON_AddItemToObject(r, "kdfIterations", dup_or_null(user, "kdfIterations"));
    cJSON_AddItemToObject(r, "kdfMemory", dup_or_null(user, "kdfMemory"));
    cJSON_AddItemToObject(r, "kdfParallelism", dup_or_null(user, "kdfParallelism"));
    cJSON_AddStringToObject(r, "token", s_kdf_token);
    cJSON_Delete(user);
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return send_json(req, "200 OK", r);
}

static esp_err_t h_kdf(httpd_req_t *req)
{
    REQUIRE_SESSION(req);
    char confirm[16] = "";
    httpd_req_get_hdr_value_str(req, "X-Confirm", confirm, sizeof(confirm));
    if (strcmp(confirm, "kdf") != 0) {
        return send_error(req, "400 Bad Request", "Missing confirmation");
    }
    cJSON *body = read_json(req);
    const cJSON *tok = body ? cJSON_GetObjectItemCaseSensitive(body, "token") : NULL;
    bool tok_ok = s_kdf_token[0] && cJSON_IsString(tok) && strlen(tok->valuestring) == strlen(s_kdf_token) &&
                  tw_ct_equal((const uint8_t *)tok->valuestring, (const uint8_t *)s_kdf_token, strlen(s_kdf_token)) &&
                  esp_timer_get_time() / 1000 < s_kdf_token_until;
    s_kdf_token[0] = '\0';  // one attempt per BOOT press
    if (!tok_ok) {
        cJSON_Delete(body);
        return send_error(req, "400 Bad Request", "Start again: the confirmation expired (2 minutes) or was used");
    }
    const cJSON *mph = cJSON_GetObjectItemCaseSensitive(body, "masterPasswordHash");
    const cJSON *key = cJSON_GetObjectItemCaseSensitive(body, "key");
    if (!cJSON_IsString(mph) || strlen(mph->valuestring) != 44 || !cJSON_IsString(key) || !is_enc2(key->valuestring) ||
        !kdf_settings_ok(body)) {
        cJSON_Delete(body);
        return send_error(req, "400 Bad Request", "Invalid KDF settings, key or hash");
    }
    esp_err_t err = tw_auth_set_master(mph->valuestring, key->valuestring, body);
    cJSON_Delete(body);
    if (err != ESP_OK) {
        return send_error(req, "500 Internal Server Error", "Could not save");
    }
    cJSON *r = cJSON_CreateObject();
    cJSON_AddBoolToObject(r, "ok", true);
    return send_json(req, "200 OK", r);
}

// ---------- stale-update check ----------
// "2026-11-19T01:02:03.456Z" (also without fraction or with +00:00) -> ms since 1970; -1 if unreadable
static int64_t iso_to_ms(const char *s)
{
    int y, mo, d, h, mi, sec, n = 0;
    if (!s || sscanf(s, "%4d-%2d-%2dT%2d:%2d:%2d%n", &y, &mo, &d, &h, &mi, &sec, &n) != 6) return -1;
    int ms = 0;
    if (s[n] == '.') {
        int digits = 0;
        for (const char *p = s + n + 1; isdigit((unsigned char)*p); p++, digits++) {
            if (digits < 3) ms = ms * 10 + (*p - '0');
        }
        for (; digits < 3; digits++) ms *= 10;
    }
    // days from civil (Howard Hinnant), no time zone involved
    y -= mo <= 2;
    int era = (y >= 0 ? y : y - 399) / 400;
    int yoe = y - era * 400;
    int doy = (153 * (mo + (mo > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    int64_t days = (int64_t)era * 146097 + doe - 719468;
    return ((days * 86400 + h * 3600 + mi * 60 + sec) * 1000) + ms;
}

// Like Bitwarden and Vaultwarden: an update made from a copy older than what is stored (another
// client changed the item in between) is refused, instead of silently overwriting that change.
static bool is_stale_update(const cJSON *body, const cJSON *old)
{
    const cJSON *lk = cJSON_GetObjectItemCaseSensitive(body, "lastKnownRevisionDate");
    const cJSON *rv = cJSON_GetObjectItemCaseSensitive(old, "revisionDate");
    if (!cJSON_IsString(lk) || !cJSON_IsString(rv)) return false;  // clients that do not send it
    int64_t known = iso_to_ms(lk->valuestring), stored = iso_to_ms(rv->valuestring);
    return known >= 0 && stored >= 0 && stored - known > 1000;  // 1 s of slack, as Vaultwarden
}

#define STALE_MSG "The client copy of this cipher is out of date. Resync the client and try again."

// ---------- ciphers ----------

static void cipher_path(const char *id, char out[64])
{
    snprintf(out, 64, TW_CIPHER_DIR "/%c/%s.json", tolower((unsigned char)id[0]), id);  // 16 subdirectories, see store.c
}

static void set_item(cJSON *o, const char *k, cJSON *v)
{
    if (cJSON_GetObjectItemCaseSensitive(o, k)) {
        cJSON_ReplaceItemInObjectCaseSensitive(o, k, v);
    } else {
        cJSON_AddItemToObject(o, k, v);
    }
}

// Missing or null -> v. The Android app treats favorite and reprompt as non-null.
static void default_item(cJSON *o, const char *k, cJSON *v)
{
    const cJSON *cur = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!cur) {
        cJSON_AddItemToObject(o, k, v);
    } else if (cJSON_IsNull(cur)) {
        cJSON_ReplaceItemInObjectCaseSensitive(o, k, v);
    } else {
        cJSON_Delete(v);
    }
}

// The request body becomes the stored record; only server-owned fields are added (SPEC 7)
static cJSON *cipher_from_request(cJSON *req_body, const char *id, const cJSON *old)
{
    cJSON *c = cJSON_Duplicate(req_body, true);
    char iso[32];
    tw_now_iso(iso);
    cJSON_DeleteItemFromObjectCaseSensitive(c, "lastKnownRevisionDate");
    set_item(c, "object", cJSON_CreateString("cipherDetails"));
    set_item(c, "id", cJSON_CreateString(id));
    set_item(c, "creationDate", old ? dup_or_null(old, "creationDate") : cJSON_CreateString(iso));
    set_item(c, "revisionDate", cJSON_CreateString(iso));
    set_item(c, "deletedDate", old ? dup_or_null(old, "deletedDate") : cJSON_CreateNull());
    set_item(c, "archivedDate", cJSON_CreateNull());
    set_item(c, "organizationId", cJSON_CreateNull());
    set_item(c, "collectionIds", cJSON_CreateArray());
    set_item(c, "attachments", cJSON_CreateNull());
    set_item(c, "organizationUseTotp", cJSON_CreateTrue());
    set_item(c, "edit", cJSON_CreateTrue());
    set_item(c, "viewPassword", cJSON_CreateTrue());
    cJSON *perm = cJSON_CreateObject();
    cJSON_AddBoolToObject(perm, "delete", true);
    cJSON_AddBoolToObject(perm, "restore", true);
    set_item(c, "permissions", perm);
    default_item(c, "folderId", cJSON_CreateNull());
    default_item(c, "favorite", cJSON_CreateFalse());
    default_item(c, "reprompt", cJSON_CreateNumber(0));
    default_item(c, "key", cJSON_CreateNull());
    return c;
}

static esp_err_t save_and_send(httpd_req_t *req, const char *id, cJSON *c)
{
    char path[64];
    cipher_path(id, path);
    if (tw_store_write(path, c) != ESP_OK) {
        cJSON_Delete(c);
        return send_error(req, "500 Internal Server Error", "Could not save");
    }
    bump_revision();
    return send_json(req, "200 OK", c);
}

static esp_err_t h_ciphers_post(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    char id[37], action[16];
    // POST /api/ciphers/<id> is an older form of update
    if (split_id(req->uri, "/api/ciphers/", id, action, sizeof(action)) && action[0] == '\0') {
        cJSON *body = read_json(req);
        char path[64];
        cipher_path(id, path);
        cJSON *old = tw_store_read(path);
        if (!body || !old) {
            cJSON_Delete(body);
            cJSON_Delete(old);
            return send_error(req, "404 Not Found", "Cipher doesn't exist");
        }
        if (is_stale_update(body, old)) {
            cJSON_Delete(body);
            cJSON_Delete(old);
            return send_error(req, "400 Bad Request", STALE_MSG);
        }
        cJSON *c = cipher_from_request(body, id, old);
        cJSON_Delete(body);
        cJSON_Delete(old);
        return save_and_send(req, id, c);
    }
    if (!path_is(req, "/api/ciphers") && !path_is(req, "/api/ciphers/create")) {
        return send_error(req, "404 Not Found", "Not found");
    }
    cJSON *body = read_json(req);
    if (!body) {
        return send_error(req, "400 Bad Request", "Invalid body");
    }
    // /create wraps it as {cipher, collectionIds}
    cJSON *inner = cJSON_GetObjectItemCaseSensitive(body, "cipher");
    char new_id[37];
    tw_uuid(new_id);
    cJSON *c = cipher_from_request(inner ? inner : body, new_id, NULL);
    cJSON_Delete(body);
    return save_and_send(req, new_id, c);
}

static esp_err_t h_ciphers_get(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    char id[37], action[16], path[64];
    if (!split_id(req->uri, "/api/ciphers/", id, action, sizeof(action)) ||
        (action[0] && strcmp(action, "details") != 0)) {
        return send_error(req, "404 Not Found", "Not found");
    }
    cipher_path(id, path);
    cJSON *c = tw_store_read(path);
    if (!c) {
        return send_error(req, "404 Not Found", "Cipher doesn't exist");
    }
    return send_json(req, "200 OK", c);
}

static esp_err_t h_ciphers_put(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    char id[37], action[16], path[64], iso[32];
    if (!split_id(req->uri, "/api/ciphers/", id, action, sizeof(action))) {
        return send_error(req, "404 Not Found", "Not found");
    }
    cipher_path(id, path);
    cJSON *old = tw_store_read(path);
    if (!old) {
        return send_error(req, "404 Not Found", "Cipher doesn't exist");
    }
    tw_now_iso(iso);

    if (action[0] == '\0') {
        cJSON *body = read_json(req);
        if (!body) {
            cJSON_Delete(old);
            return send_error(req, "400 Bad Request", "Invalid body");
        }
        if (is_stale_update(body, old)) {
            cJSON_Delete(body);
            cJSON_Delete(old);
            return send_error(req, "400 Bad Request", STALE_MSG);
        }
        cJSON *c = cipher_from_request(body, id, old);
        cJSON_Delete(body);
        cJSON_Delete(old);
        return save_and_send(req, id, c);
    }
    if (strcmp(action, "delete") == 0 || strcmp(action, "restore") == 0) {
        bool del = action[0] == 'd';
        set_item(old, "deletedDate", del ? cJSON_CreateString(iso) : cJSON_CreateNull());
        set_item(old, "revisionDate", cJSON_CreateString(iso));
        if (del) {
            // Vaultwarden answers soft delete with no body
            esp_err_t e = tw_store_write(path, old);
            cJSON_Delete(old);
            bump_revision();
            if (e != ESP_OK) return send_error(req, "500 Internal Server Error", "Could not save");
            add_cors(req);
            return httpd_resp_send(req, NULL, 0);
        }
        return save_and_send(req, id, old);
    }
    if (strcmp(action, "partial") == 0) {
        cJSON *body = read_json(req);
        if (body) {
            const cJSON *fid = cJSON_GetObjectItemCaseSensitive(body, "folderId");
            const cJSON *fav = cJSON_GetObjectItemCaseSensitive(body, "favorite");
            if (fid) set_item(old, "folderId", cJSON_Duplicate(fid, true));
            if (cJSON_IsBool(fav)) set_item(old, "favorite", cJSON_Duplicate(fav, true));
            cJSON_Delete(body);
        }
        set_item(old, "revisionDate", cJSON_CreateString(iso));
        return save_and_send(req, id, old);
    }
    cJSON_Delete(old);
    return send_error(req, "404 Not Found", "Not found");
}

static esp_err_t h_ciphers_delete(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    char id[37], action[16], path[64];
    if (!split_id(req->uri, "/api/ciphers/", id, action, sizeof(action)) || action[0]) {
        return send_error(req, "404 Not Found", "Not found");
    }
    cipher_path(id, path);
    tw_store_remove(path);
    bump_revision();
    add_cors(req);
    return httpd_resp_send(req, NULL, 0);
}

// ---------- folders ----------

static esp_err_t h_folders(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    char id[37], action[16], path[64], iso[32];
    tw_now_iso(iso);
    bool has_id = split_id(req->uri, "/api/folders/", id, action, sizeof(action)) && !action[0];

    if (req->method == HTTP_DELETE) {
        if (!has_id) return send_error(req, "404 Not Found", "Not found");
        snprintf(path, sizeof(path), TW_FOLDER_DIR "/%s.json", id);
        tw_store_remove(path);
        bump_revision();
        add_cors(req);
        return httpd_resp_send(req, NULL, 0);
    }
    if (req->method == HTTP_POST && !path_is(req, "/api/folders")) {
        return send_error(req, "404 Not Found", "Not found");
    }
    if (req->method == HTTP_PUT && !has_id) {
        return send_error(req, "404 Not Found", "Not found");
    }
    cJSON *body = read_json(req);
    const cJSON *name = body ? cJSON_GetObjectItemCaseSensitive(body, "name") : NULL;
    if (!cJSON_IsString(name)) {
        cJSON_Delete(body);
        return send_error(req, "400 Bad Request", "Invalid body");
    }
    if (req->method == HTTP_POST) {
        tw_uuid(id);
    }
    cJSON *f = cJSON_CreateObject();
    cJSON_AddStringToObject(f, "id", id);
    cJSON_AddStringToObject(f, "revisionDate", iso);
    cJSON_AddStringToObject(f, "name", name->valuestring);
    cJSON_AddStringToObject(f, "object", "folder");
    cJSON_Delete(body);
    snprintf(path, sizeof(path), TW_FOLDER_DIR "/%s.json", id);
    if (tw_store_write(path, f) != ESP_OK) {
        cJSON_Delete(f);
        return send_error(req, "500 Internal Server Error", "Could not save");
    }
    bump_revision();
    return send_json(req, "200 OK", f);
}


// ---------- import (POST /api/ciphers/import) ----------
// Body: {"ciphers":[...], "folders":[{"name", "id"?}], "folderRelationships":[{"key": cipherIdx, "value": folderIdx}]}
// The whole body sits in PSRAM, but only one cipher at a time is parsed, so peak memory stays near the body size.
// Nothing is written unless everything fits: Bitwarden does not de-duplicate, so a half import retried makes doubles.

static const char *json_ws(const char *p)
{
    while (*p == ' ' || *p == '\n' || *p == '\r' || *p == '\t') p++;
    return p;
}

// Returns the end of the JSON value starting at p (after whitespace), or NULL if malformed
static const char *json_skip(const char *p)
{
    p = json_ws(p);
    if (*p == '"') {
        for (p++; *p && *p != '"'; p++) {
            if (*p == '\\' && !*++p) return NULL;
        }
        return *p ? p + 1 : NULL;
    }
    if (*p == '{' || *p == '[') {
        int depth = 0;
        while (*p) {
            if (*p == '"') {
                p = json_skip(p);
                if (!p) return NULL;
                continue;
            }
            if (*p == '{' || *p == '[') depth++;
            else if (*p == '}' || *p == ']') {
                if (--depth == 0) return p + 1;
            }
            p++;
        }
        return NULL;
    }
    const char *start = p;
    while (*p && !strchr(",}] \n\r\t", *p)) p++;
    return p > start ? p : NULL;
}

typedef struct {
    char *start, *end;  // value span inside the body; NULL if the key is absent
} span_t;

static cJSON *parse_span(span_t sp)
{
    if (!sp.start) return NULL;
    char keep = *sp.end;
    *sp.end = '\0';
    cJSON *o = cJSON_Parse(sp.start);
    *sp.end = keep;
    return o;
}

// Calls back for each element of the array span; stops early if cb returns false. Returns count or -1.
typedef bool (*elem_cb)(int idx, span_t el, void *ctx);
static int for_each_elem(span_t arr, elem_cb cb, void *ctx)
{
    if (!arr.start) return 0;
    char *p = (char *)json_ws(arr.start);
    if (*p != '[') return -1;
    p = (char *)json_ws(p + 1);
    int n = 0;
    while (*p != ']') {
        char *e = (char *)json_skip(p);
        if (!e || e > arr.end) return -1;
        if (cb && !cb(n, (span_t){p, e}, ctx)) return n;
        n++;
        p = (char *)json_ws(e);
        if (*p == ',') p = (char *)json_ws(p + 1);
        else if (*p != ']') return -1;
    }
    return n;
}

static uint32_t bytes_for(size_t json_len)
{
    return tw_store_record_bytes(json_len + 640);  // +640: fields the server adds to each cipher
}

static bool sum_bytes(int idx, span_t el, void *ctx)
{
    (void)idx;
    *(uint32_t *)ctx += bytes_for(el.end - el.start);
    return true;
}

// Import progress, read by the port-80 server (a separate task) while the HTTPS task is busy importing
static volatile int s_imp_total = -1;   // -1: no import since boot
static volatile int s_imp_written;
static volatile bool s_imp_running;
static volatile uint32_t s_imp_started_s, s_imp_finished_s;
static char s_imp_result[96];

typedef struct {
    int *folder_of;          // cipher index -> folder index, -1 = none
    char (*folder_ids)[37];  // folder index -> id
    int n_folders;
    int written;
    bool failed;
} import_ctx_t;

static bool import_one(int idx, span_t el, void *arg)
{
    import_ctx_t *ctx = arg;
    cJSON *body = parse_span(el);
    if (!body) {
        ctx->failed = true;
        return false;
    }
    char id[37], path[64];
    tw_uuid(id);
    cJSON *c = cipher_from_request(body, id, NULL);
    cJSON_Delete(body);
    int fi = ctx->folder_of[idx];
    set_item(c, "folderId", fi >= 0 && fi < ctx->n_folders ? cJSON_CreateString(ctx->folder_ids[fi]) : cJSON_CreateNull());
    cipher_path(id, path);
    esp_err_t err = tw_store_write_new(path, c);
    cJSON_Delete(c);
    if (err != ESP_OK) {
        ctx->failed = true;
        return false;
    }
    ctx->written++;
    s_imp_written = ctx->written;
    vTaskDelay(1);  // let other tasks (idle, USB) run during long imports
    return true;
}

// Largest import body that fits in PSRAM right now, leaving headroom for TLS and parsing
static size_t import_limit(void)
{
    size_t block = heap_caps_get_largest_free_block(MALLOC_CAP_SPIRAM);
    return block > TW_IMPORT_HEADROOM ? block - TW_IMPORT_HEADROOM : 0;
}

static esp_err_t h_ciphers_import(httpd_req_t *req)
{
    REQUIRE_AUTH(req);
    size_t limit = import_limit();
    if (req->content_len > limit) {
        char msg[160];
        snprintf(msg, sizeof(msg), "Import file is too large for the device (%u KB, limit %u KB). Split it and import in parts.",
                 (unsigned)(req->content_len / 1024), (unsigned)(limit / 1024));
        return send_import_error(req, "400 Bad Request", msg);
    }
    char *buf = heap_caps_malloc(req->content_len + 1, MALLOC_CAP_SPIRAM);
    if (!buf) {
        return send_import_error(req, "500 Internal Server Error", "Not enough memory for this import");
    }
    size_t got = 0;
    while (got < req->content_len) {
        int r = httpd_req_recv(req, buf + got, req->content_len - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) {
            free(buf);
            return ESP_FAIL;
        }
        got += r;
    }
    buf[got] = '\0';

    // Top-level keys -> value spans
    span_t ciphers = {0}, folders = {0}, rels = {0};
    char *p = (char *)json_ws(buf);
    bool ok = *p == '{';
    if (ok) p = (char *)json_ws(p + 1);
    while (ok && *p != '}') {
        char *k = p;
        char *ke = (char *)json_skip(k);
        if (*k != '"' || !ke) { ok = false; break; }
        p = (char *)json_ws(ke);
        if (*p != ':') { ok = false; break; }
        char *v = (char *)json_ws(p + 1);
        char *ve = (char *)json_skip(v);
        if (!ve) { ok = false; break; }
        size_t kl = ke - k - 2;
        span_t sp = {v, ve};
        if (kl == 7 && strncmp(k + 1, "ciphers", 7) == 0) ciphers = sp;
        else if (kl == 7 && strncmp(k + 1, "folders", 7) == 0) folders = sp;
        else if (kl == 19 && strncmp(k + 1, "folderRelationships", 19) == 0) rels = sp;
        p = (char *)json_ws(ve);
        if (*p == ',') p = (char *)json_ws(p + 1);
        else if (*p != '}') ok = false;
    }
    int n_ciphers = ok ? for_each_elem(ciphers, NULL, NULL) : -1;
    cJSON *jf = parse_span(folders);
    cJSON *jr = parse_span(rels);
    const char *bad = !ok ? "Invalid import body (top level)"
                    : n_ciphers < 0 ? "Invalid import body (ciphers)"
                    : (folders.start && !cJSON_IsArray(jf)) ? "Invalid import body (folders)"
                    : (rels.start && !cJSON_IsArray(jr)) ? "Invalid import body (folderRelationships)"
                    : NULL;
    if (bad) {
        free(buf);
        cJSON_Delete(jf);
        cJSON_Delete(jr);
        return send_import_error(req, "400 Bad Request", bad);
    }

    // Folders: reuse an existing id, otherwise make a new one
    int n_folders = cJSON_GetArraySize(jf);
    import_ctx_t ctx = {
        .folder_of = malloc(sizeof(int) * (n_ciphers > 0 ? n_ciphers : 1)),
        .folder_ids = calloc(n_folders > 0 ? n_folders : 1, 37),
        .n_folders = n_folders,
    };
    bool *folder_new = calloc(n_folders > 0 ? n_folders : 1, sizeof(bool));
    if (!ctx.folder_of || !ctx.folder_ids || !folder_new) {
        free(buf); free(ctx.folder_of); free(ctx.folder_ids); free(folder_new);
        cJSON_Delete(jf); cJSON_Delete(jr);
        return send_import_error(req, "500 Internal Server Error", "Not enough memory for this import");
    }
    for (int i = 0; i < n_ciphers; i++) ctx.folder_of[i] = -1;
    const cJSON *r;
    cJSON_ArrayForEach(r, jr) {
        const cJSON *k = cJSON_GetObjectItemCaseSensitive(r, "key");
        const cJSON *v = cJSON_GetObjectItemCaseSensitive(r, "value");
        if (cJSON_IsNumber(k) && cJSON_IsNumber(v) && k->valueint >= 0 && k->valueint < n_ciphers) {
            ctx.folder_of[k->valueint] = v->valueint;
        }
    }
    uint32_t need = 0;
    for (int i = 0; i < n_folders; i++) {
        const cJSON *f = cJSON_GetArrayItem(jf, i);
        const cJSON *fid = cJSON_GetObjectItemCaseSensitive(f, "id");
        char path[64];
        if (cJSON_IsString(fid) && tw_is_uuid(fid->valuestring)) {
            snprintf(path, sizeof(path), TW_FOLDER_DIR "/%s.json", fid->valuestring);
            if (tw_store_exists(path)) {
                snprintf(ctx.folder_ids[i], 37, "%s", fid->valuestring);
                continue;
            }
        }
        folder_new[i] = true;
        need += tw_store_record_bytes(256);  // a folder record (encrypted name + fields)
    }

    // Capacity check before writing anything
    for_each_elem(ciphers, sum_bytes, &need);
    if (!tw_store_fits(need)) {
        tw_store_stats_t st;
        tw_store_stats(&st);
        char msg[200];
        snprintf(msg, sizeof(msg), "Not enough space on the device: this import needs about %u KB but %u KB are free "
                 "(%d items). Nothing was imported. See https://" TW_IP_STR "/ for capacity.",
                 (unsigned)(need / 1024), (unsigned)(st.free_bytes / 1024), n_ciphers);
        free(buf); free(ctx.folder_of); free(ctx.folder_ids); free(folder_new);
        cJSON_Delete(jf); cJSON_Delete(jr);
        return send_import_error(req, "400 Bad Request", msg);
    }

    // Write new folders, then ciphers
    char iso[32];
    tw_now_iso(iso);
    for (int i = 0; i < n_folders && !ctx.failed; i++) {
        if (!folder_new[i]) continue;
        const cJSON *name = cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(jf, i), "name");
        tw_uuid(ctx.folder_ids[i]);
        cJSON *f = cJSON_CreateObject();
        cJSON_AddStringToObject(f, "id", ctx.folder_ids[i]);
        cJSON_AddStringToObject(f, "revisionDate", iso);
        cJSON_AddStringToObject(f, "name", cJSON_IsString(name) ? name->valuestring : "");
        cJSON_AddStringToObject(f, "object", "folder");
        char path[64];
        snprintf(path, sizeof(path), TW_FOLDER_DIR "/%s.json", ctx.folder_ids[i]);
        if (tw_store_write(path, f) != ESP_OK) ctx.failed = true;
        cJSON_Delete(f);
    }
    cJSON_Delete(jf);
    cJSON_Delete(jr);
    free(folder_new);
    s_imp_written = 0;
    s_imp_total = n_ciphers;
    s_imp_started_s = (uint32_t)(esp_timer_get_time() / 1000000);
    s_imp_running = true;
    if (!ctx.failed) {
        for_each_elem(ciphers, import_one, &ctx);
    }
    s_imp_running = false;
    s_imp_finished_s = (uint32_t)(esp_timer_get_time() / 1000000);
    snprintf(s_imp_result, sizeof(s_imp_result), "%s: %d / %d, %u s", ctx.failed ? "failed" : "done",
             ctx.written, n_ciphers, (unsigned)(s_imp_finished_s - s_imp_started_s));
    free(buf);
    free(ctx.folder_of);
    free(ctx.folder_ids);
    bump_revision();
    ESP_LOGI(TAG, "import: %d of %d items written", ctx.written, n_ciphers);
    if (ctx.failed) {
        char msg[160];
        snprintf(msg, sizeof(msg), "Import stopped after %d of %d items (write error). Check the vault before retrying.",
                 ctx.written, n_ciphers);
        return send_import_error(req, "500 Internal Server Error", msg);
    }
    log_req(req, "200");
    add_cors(req);
    return httpd_resp_send(req, NULL, 0);
}

// POST /s/wipe from the status page. Needs the BOOT button, so nothing on the Mac can wipe it unattended.
// The custom header forces a CORS preflight, which other web origins fail, so a web page cannot start it.
static esp_err_t h_wipe(httpd_req_t *req)
{
    REQUIRE_SESSION(req);
    char confirm[16] = "";
    httpd_req_get_hdr_value_str(req, "X-Confirm", confirm, sizeof(confirm));
    if (strcmp(confirm, "wipe-all") != 0) {
        return send_error(req, "400 Bad Request", "Missing confirmation");
    }
    if (!tw_button_wait(TW_BUTTON_WAIT_MS)) {
        return send_error(req, "400 Bad Request", "Button not pressed within 30 seconds. Nothing was deleted.");
    }
    esp_err_t err = tw_auth_factory_reset();
    if (err != ESP_OK) {
        return send_error(req, "500 Internal Server Error", "Wipe failed");
    }
    s_imp_total = -1;
    sessions_clear();
    return send_raw(req, "200 OK", "{\"wiped\":true}");
}

// POST /s/unlock {"masterPasswordHash"}: the login hash, computed in the locked page (/web/unlock.js).
// Before an account exists: {"setupCode"}, the one-time code the flasher showed.
static esp_err_t h_unlock(httpd_req_t *req)
{
    char confirm[16] = "";
    httpd_req_get_hdr_value_str(req, "X-Confirm", confirm, sizeof(confirm));
    if (strcmp(confirm, "unlock") != 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not found");
        return ESP_OK;
    }
    cJSON *body = read_json(req);
    const cJSON *mph = body ? cJSON_GetObjectItemCaseSensitive(body, "masterPasswordHash") : NULL;
    const cJSON *code = body ? cJSON_GetObjectItemCaseSensitive(body, "setupCode") : NULL;
    tw_login_result_t res = cJSON_IsString(mph)    ? tw_auth_check_password(mph->valuestring)
                            : cJSON_IsString(code) ? tw_auth_check_setup(code->valuestring)
                                                   : TW_LOGIN_BAD;
    cJSON_Delete(body);
    switch (res) {
    case TW_LOGIN_OK:
        break;
    case TW_LOGIN_OLD_FORMAT:
        return send_error(req, "400 Bad Request", OLD_FORMAT_MSG);
    case TW_LOGIN_NO_BUTTON:
        return send_error(req, "400 Bad Request", "Button not pressed within 30 seconds");
    case TW_LOGIN_WIPED:
        return send_error(req, "400 Bad Request", "Too many failed attempts. The device has been erased");
    default:
        return send_error(req, "400 Bad Request", "Username or master password is incorrect");
    }
    uint8_t raw[32];
    tw_random(raw, sizeof(raw));
    char *tok = s_sess[s_sess_next];
    tw_b64url_encode(raw, sizeof(raw), tok, sizeof(s_sess[0]));
    s_sess_until[s_sess_next] = esp_timer_get_time() / 1000 + SESS_MS;
    s_sess_next = (s_sess_next + 1) % SESS_N;
    char cookie[128];
    snprintf(cookie, sizeof(cookie), "sid=%s; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=%d", tok, SESS_MS / 1000);
    httpd_resp_set_hdr(req, "Set-Cookie", cookie);
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return send_raw(req, "200 OK", "{\"ok\":true}");
}

// POST /s/lock: end this session (the page's lock button)
static esp_err_t h_lock(httpd_req_t *req)
{
    char ck[256];
    if (tw_status_session_ok(req) && httpd_req_get_hdr_value_str(req, "Cookie", ck, sizeof(ck)) == ESP_OK) {
        for (int i = 0; i < SESS_N; i++) {
            if (s_sess[i][0] && strstr(ck, s_sess[i])) s_sess[i][0] = '\0';
        }
    }
    httpd_resp_set_hdr(req, "Set-Cookie", "sid=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0");
    return send_raw(req, "200 OK", "{\"ok\":true}");
}

static const char *reset_reason_str(void)
{
    switch (esp_reset_reason()) {
    case ESP_RST_POWERON: return "power on";
    case ESP_RST_SW: return "software restart";
    case ESP_RST_PANIC: return "PANIC (crash)";
    case ESP_RST_INT_WDT: return "interrupt watchdog";
    case ESP_RST_TASK_WDT: return "task watchdog";
    case ESP_RST_WDT: return "other watchdog";
    case ESP_RST_BROWNOUT: return "BROWNOUT (voltage dip)";
    case ESP_RST_USB: return "USB reset";
    case ESP_RST_JTAG: return "JTAG reset";
    case ESP_RST_DEEPSLEEP: return "deep sleep";
    case ESP_RST_EXT: return "external pin";
    default: return "unknown";
    }
}

// ---------- status page (GET / on HTTPS) ----------
// Needs a session (POST /s/unlock); without one, status_locked. Never vault content (the board does not know
// the email at all). Counts and recent changes need the store unlocked by a login since the last start.

static char s_cert_fp[96];  // SHA-256 of the CA certificate (the one people trust), AA:BB:...

// Hashes the DER inside the PEM without parsing the certificate: mbedTLS would refuse the CA's
// critical nameConstraints extension.
static void compute_cert_fp(const char *pem)
{
    mbedtls_pem_context ctx;
    mbedtls_pem_init(&ctx);
    size_t used;
    if (mbedtls_pem_read_buffer(&ctx, "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----",
                                (const unsigned char *)pem, NULL, 0, &used) == 0) {
        uint8_t h[32];
        mbedtls_sha256(ctx.MBEDTLS_PRIVATE(buf), ctx.MBEDTLS_PRIVATE(buflen), h, 0);
        for (int i = 0; i < 32; i++) {
            snprintf(s_cert_fp + i * 3, 4, i < 31 ? "%02X:" : "%02X", h[i]);
        }
    }
    mbedtls_pem_free(&ctx);
}

static void chunkf(httpd_req_t *req, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void chunkf(httpd_req_t *req, const char *fmt, ...)
{
    char line[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    httpd_resp_sendstr_chunk(req, line);
}

// Before unlocking: device information only, no name, nothing about what it stores
static esp_err_t status_locked(httpd_req_t *req)
{
    uint32_t up = (uint32_t)(esp_timer_get_time() / 1000000);
    const esp_app_desc_t *app = esp_app_get_description();
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "Content-Security-Policy", TW_PAGE_CSP);
    httpd_resp_sendstr_chunk(req,
        "<!doctype html><html lang=ja><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>Device</title><style>"
        ":root{--bg:#fff;--fg:#1a1a1a;--mute:#666;--line:#ddd}"
        "@media(prefers-color-scheme:dark){:root{--bg:#161616;--fg:#eee;--mute:#999;--line:#333}}"
        "body{background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,'Hiragino Sans',sans-serif;max-width:560px;margin:0 auto;padding:16px}"
        "table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px 4px;text-align:left;vertical-align:top}"
        "th{color:var(--mute);font-weight:normal;width:40%}code{font-size:12px;word-break:break-all}input,button{font:inherit}"
        "</style><table>");
    chunkf(req, "<tr><th>チップ</th><td>ESP32-S3</td></tr><tr><th>版</th><td>%s</td></tr>", app->version);
    chunkf(req, "<tr><th>起動してから</th><td>%u 時間 %u 分</td></tr>", (unsigned)(up / 3600), (unsigned)(up / 60 % 60));
    chunkf(req, "<tr><th>空きメモリ</th><td>%u KB</td></tr></table>", (unsigned)(heap_caps_get_free_size(MALLOC_CAP_DEFAULT) / 1024));
    if (tw_user_exists()) {
        httpd_resp_sendstr_chunk(req,
            "<p><label>ユーザー名 <input id=uu type=email autocomplete=username size=24></label><br>"
            "<label>パスワード <input id=up type=password autocomplete=current-password size=24></label><br>");
    } else {
        httpd_resp_sendstr_chunk(req, "<p><label>コード <input id=uc autocomplete=off size=16></label><br>");
    }
    httpd_resp_sendstr_chunk(req, "<button id=ub>解除</button></p><p id=um></p>"
        "<script type=module src=/web/unlock.js></script></html>");
    return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t h_status(httpd_req_t *req)
{
    if (!tw_status_session_ok(req)) {
        return status_locked(req);
    }
    tw_store_stats_t st;
    tw_store_stats(&st);
    uint32_t up = (uint32_t)(esp_timer_get_time() / 1000000);
    const esp_app_desc_t *app = esp_app_get_description();

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    // Scripts only from the board (firmware/web/), no inline script; the page's own <style> is inline
    httpd_resp_set_hdr(req, "Content-Security-Policy", TW_PAGE_CSP);
    httpd_resp_sendstr_chunk(req,
        "<!doctype html><html lang=ja><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        "<title>tinywarden</title><style>"
        ":root{--bg:#fff;--fg:#1a1a1a;--mute:#666;--line:#ddd;--ok:#1a7f37;--ng:#c62828}"
        "@media(prefers-color-scheme:dark){:root{--bg:#161616;--fg:#eee;--mute:#999;--line:#333;--ok:#4caf50;--ng:#ef5350}}"
        "body{background:var(--bg);color:var(--fg);font:15px/1.6 -apple-system,'Hiragino Sans','Hiragino Kaku Gothic ProN',sans-serif;"
        "max-width:720px;margin:0 auto;padding:16px}h1{font-size:20px}h2{font-size:16px;margin-top:24px}"
        "table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px 4px;text-align:left;vertical-align:top}"
        "th{color:var(--mute);font-weight:normal;width:40%}code{font-size:12px;word-break:break-all}"
        ".ok{color:var(--ok)}.ng{color:var(--ng)}.mute{color:var(--mute)}"
        "</style><h1>tinywarden</h1><p><a href=/manual>使い方（マニュアル）</a> · <a href=/manual#en>Manual (English)</a></p>"
        "<p><button id=lb>鍵を掛ける</button> <span class=mute>（30分たつと自動で掛かります）</span></p>");
#if CONFIG_TW_DEV_DOWNLOAD_ENDPOINT
    httpd_resp_sendstr_chunk(req, "<p class=ng><b>開発用ビルド</b>：テスト用の機能が有効です。本物の保管庫には使わないでください。</p>");
#endif
#if CONFIG_TW_DEV_SKIP_BUTTON
    httpd_resp_sendstr_chunk(req, "<p class=ng><b>BOOTボタンの確認を省略中</b>（テスト用）。誰でも登録・ログイン・全消しができます。</p>");
#endif
    httpd_resp_sendstr_chunk(req, "<h2>保管庫</h2><table>");
    chunkf(req, "<tr><th>ユーザー</th><td>%s</td></tr>", tw_user_exists() ? "登録済み" : "<span class=ng>未登録</span>");
    cJSON *ku = tw_user_exists() ? tw_user_load() : NULL;
    if (ku) {
        const cJSON *kt = cJSON_GetObjectItemCaseSensitive(ku, "kdf"), *ki = cJSON_GetObjectItemCaseSensitive(ku, "kdfIterations");
        const cJSON *km = cJSON_GetObjectItemCaseSensitive(ku, "kdfMemory"), *kp = cJSON_GetObjectItemCaseSensitive(ku, "kdfParallelism");
        if (cJSON_IsNumber(kt) && kt->valueint == 1 && cJSON_IsNumber(ki) && cJSON_IsNumber(km) && cJSON_IsNumber(kp)) {
            chunkf(req, "<tr><th>鍵を作る計算（KDF）</th><td>Argon2id <span class=mute>（メモリ %d MB、%d 回、並列 %d）</span></td></tr>",
                   km->valueint, ki->valueint, kp->valueint);
        } else if (cJSON_IsNumber(ki)) {
            chunkf(req, "<tr><th>鍵を作る計算（KDF）</th><td><span class=ng>PBKDF2 %d 回</span> <span class=mute>（アプリは必ずPBKDF2で作る。下の「鍵を作る計算を変える」でArgon2idにすると、総当たりにもっと強くなる）</span></td></tr>",
                   ki->valueint);
        }
        cJSON_Delete(ku);
    }
    if (st.unlocked) {
        chunkf(req, "<tr><th>項目</th><td>%u 件</td></tr><tr><th>フォルダ</th><td>%u 個</td></tr>",
               (unsigned)st.ciphers, (unsigned)st.folders);
        if (st.unreadable) {
            chunkf(req, "<tr><th>開けない記録</th><td>%u 件 <span class=mute>（前のアカウントの残り。全部消すと片付きます）</span></td></tr>",
                   (unsigned)st.unreadable);
        }
    } else if (tw_user_exists()) {
        chunkf(req, "<tr><th>中身</th><td>鍵がかかっています <span class=mute>（記録 %u 件。どれが項目かは、どこかの端末でログインするまで機器にも分かりません）</span></td></tr>",
               (unsigned)st.records);
    }
    chunkf(req, "<tr><th>保存領域</th><td>%u KB 中 %u KB 使用、%u KB 空き</td></tr>",
           (unsigned)(st.capacity / 1024), (unsigned)(st.live_bytes / 1024), (unsigned)(st.free_bytes / 1024));
    chunkf(req, "<tr><th>あと入る件数（目安）</th><td>約 %u 件 <span class=mute>（1件 平均 %d バイトとして。長いメモやパスキーはもっと使う）</span></td></tr>",
           (unsigned)(st.free_bytes / TW_AVG_ITEM_BYTES), TW_AVG_ITEM_BYTES);
    chunkf(req, "<tr><th>古い版（大掃除で回収）</th><td>%u KB <span class=mute>（区画 %u 個中 %u 個が空き。起動後の大掃除 %u 回）</span></td></tr>",
           (unsigned)(st.stale_bytes / 1024), (unsigned)st.segs_total, (unsigned)st.segs_free, (unsigned)st.gc_runs);
    chunkf(req, "<tr><th>起動時の読み込み</th><td>%u ms%s</td></tr>", (unsigned)st.mount_ms,
           st.torn_records ? "<span class=ng>（書きかけの記録を見つけて捨てました。電源が切れた跡です）</span>" : "");
    if (s_imp_total >= 0) {
        chunkf(req, "<tr><th>最後のインポート</th><td>%s</td></tr>", s_imp_result);
    }
    chunkf(req, "<tr><th>インポート1回の上限</th><td>約 %u KB <span class=mute>（拡張機能が送るデータの大きさ。今のPSRAMの空きから計算）</span></td></tr></table>",
           (unsigned)(import_limit() / 1024));

    httpd_resp_sendstr_chunk(req, "<h2>機器</h2><table>");
    time_t built = TW_BUILD_EPOCH;
    struct tm bt;
    gmtime_r(&built, &bt);
    char btxt[32];
    strftime(btxt, sizeof(btxt), "%Y-%m-%d %H:%M UTC", &bt);
    chunkf(req, "<tr><th>ファームウェア</th><td>%s <span class=mute>（ビルド %s）</span></td></tr>", app->version, btxt);
    chunkf(req, "<tr><th>起動してから</th><td>%u 時間 %u 分</td></tr>", (unsigned)(up / 3600), (unsigned)(up / 60 % 60));
    chunkf(req, "<tr><th>HTTP（80番）</th><td>%s</td></tr>",
           s_http_err == ESP_OK ? "<span class=ok>動作中</span>" : "<span class=ng>停止</span>");
    chunkf(req, "<tr><th>前回の再起動の理由</th><td>%s</td></tr>", reset_reason_str());
    chunkf(req, "<tr><th>空きメモリ</th><td>内部 %u KB（起動後の最小 %u KB）/ PSRAM %u KB（最小 %u KB）</td></tr>",
           (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024),
           (unsigned)(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL) / 1024),
           (unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024),
           (unsigned)(heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM) / 1024));
    chunkf(req, "<tr><th>証明書 SHA-256</th><td><code>%s</code><br><a href=/ca.crt>証明書をダウンロード</a></td></tr></table>",
           s_cert_fp);

    httpd_resp_sendstr_chunk(req, "<h2>直近の通信</h2><table><tr><th>起動後（秒）</th><th>内容</th></tr>");
    for (int i = 0; i < REQ_LOG_N; i++) {
        const req_log_t *e = &s_req_log[(s_req_log_next + REQ_LOG_N - 1 - i) % REQ_LOG_N];
        if (!e->method[0]) break;
        chunkf(req, "<tr><td>%u</td><td><code>%s %s</code> → <span class=%s>%s</span>%s%s%s%s</td></tr>",
               (unsigned)e->uptime_s, e->method, e->path, e->status[0] == '2' ? "ok" : "ng", e->status,
               e->note[0] ? "<br><span class=mute>" : "", e->note, e->client[0] ? "<br><span class=mute>" : "",
               e->client);
    }
    httpd_resp_sendstr_chunk(req, "</table><h2>つないできたアプリ（起動後）</h2><table><tr><th>アプリと版</th><th>回数・最後のログイン失敗</th></tr>");
    for (int i = 0; i < CLIENTS_N; i++) {
        const client_seen_t *c = &s_clients[i];
        if (!c->count) continue;
        chunkf(req, "<tr><td><code>%s %s</code><br><span class=mute>%s（Device-Type %s）</span></td>",
               c->name[0] ? c->name : "?", c->version[0] ? c->version : "?", device_type_str(c->device_type),
               c->device_type[0] ? c->device_type : "?");
        chunkf(req, "<td>%u 回（%u〜%u 秒）", (unsigned)c->count, (unsigned)c->first_s, (unsigned)c->last_s);
        if (c->last_fail_s) {
            chunkf(req, "<br><span class=ng>%u 秒: %s</span>", (unsigned)c->last_fail_s, c->last_fail);
        }
        httpd_resp_sendstr_chunk(req, "</td></tr>");
    }
    httpd_resp_sendstr_chunk(req, "</table><h2>最近の変更</h2>");
    if (!st.unlocked) {
        httpd_resp_sendstr_chunk(req, "<p class=mute>ログインするまで出せません（日時も種類も、暗号化して保存しています）。</p><table>");
    } else {
        httpd_resp_sendstr_chunk(req, "<table><tr><th>日時（UTC）</th><th>内容</th></tr>");
    }
    tw_store_change_t ch[20];
    int nch = tw_store_recent(ch, 20);
    for (int i = 0; i < nch; i++) {
        char when[24] = "—";
        if (ch[i].time) {
            time_t t = ch[i].time;
            struct tm tmv;
            gmtime_r(&t, &tmv);
            strftime(when, sizeof(when), "%Y-%m-%d %H:%M", &tmv);
        }
        chunkf(req, "<tr><td>%s</td><td>%s %s <code>%.8s%s</code></td></tr>", when, ch[i].kind, ch[i].op, ch[i].id,
               ch[i].id[0] ? "…" : "");
    }
    httpd_resp_sendstr_chunk(req, "</table><p class=mute>BOOTボタン待ちのあいだ（最大30秒）は、このページも応答しません。</p>"
        "<h2>控えを保存</h2><p>保管庫を<b>暗号化したまま</b>1つのファイルに保存します（アプリは要りません）。"
        "戻すときは <code>tools/tw_backup.py decrypt</code> で、BitwardenやVaultwardenに読み込める形にします。"
        "保存には、ユーザー名（メール）とマスターパスワード、BOOTボタンが要ります（ログインと同じ。間違いは失敗の回数に数え、10回で全部消えます）。"
        "控えのファイルにはユーザー名を書きません。開くときにまた入れます。"
        "マスターパスワードはこのページの中でログイン用のハッシュにしてから送るので、機器には届きません。</p>"
        "<p><label>ユーザー名（メール） <input id=be type=email autocomplete=username size=24></label><br>"
        "<label>マスターパスワード <input id=bp type=password autocomplete=current-password size=24></label><br>"
        "<button id=bb>控えを保存</button></p><p id=bm></p>"
        "<p>控えをインポートできる形に変える、2つの保管庫を比べて1つにまとめる: <a href=/merge>保管庫をまとめる</a>"
        "（すべてブラウザの中で計算します）</p>"
        "<h2>鍵を作る計算を変える</h2><p>マスターパスワードから鍵を作る計算（KDF）を変えます。保管庫の中身はそのままで、"
        "保管庫の鍵の包み方だけが変わります。<b>Argon2id</b>は、盗まれた暗号文を総当たりされるときに、PBKDF2よりずっと時間がかかります。"
        "計算はこのページの中で行い、マスターパスワードと保管庫の鍵は機器に届きません。"
        "変えると、<b>すべての機器がログアウト</b>します。ログインし直してください。先に「控えを保存」で控えを取っておいてください。</p>"
        "<p><label>ユーザー名（メール） <input id=ke type=email autocomplete=username size=24></label><br>"
        "<label>マスターパスワード <input id=kp type=password autocomplete=current-password size=24></label><br>"
        "<label>変えた後 <select id=kt><option value=argon2id>Argon2id（メモリ32MB、6回、並列4。おすすめ）</option>"
        "<option value=pbkdf2>PBKDF2（60万回）</option></select></label><br>"
        "<button id=kb>変える</button></p><p id=km></p>"
        "<h2>全部消す</h2><p>アカウント、すべての項目とフォルダを消して、買ったときの状態に戻します。証明書は残ります。元に戻せません。</p>"
        "<p><label>確認のため <b>消去</b> と入力: <input id=wc autocomplete=off size=6></label> "
        "<button id=wb disabled>全部消す</button></p><p id=wm></p>"
        "<script type=module src=/web/status.js></script></html>");
    return httpd_resp_send_chunk(req, NULL, 0);
}


// ---------- development: reboot into download mode (CONFIG_TW_DEV_DOWNLOAD_ENDPOINT) ----------
#if CONFIG_TW_DEV_DOWNLOAD_ENDPOINT
#include "esp_system.h"
#include "soc/rtc_cntl_reg.h"
#include "hal/wdt_hal.h"
#include "esp_rom_sys.h"

static void reboot_to_download(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(300));  // let the response go out
    // TinyUSB switched the internal USB PHY to USB-OTG; hand it back to USB-Serial-JTAG so the ROM's
    // download mode shows up as /dev/cu.usbmodem* again (RTC registers survive the software reset)
    CLEAR_PERI_REG_MASK(RTC_CNTL_USB_CONF_REG, RTC_CNTL_SW_HW_USB_PHY_SEL);
    REG_WRITE(RTC_CNTL_OPTION1_REG, RTC_CNTL_FORCE_DOWNLOAD_BOOT);
    // Not esp_restart(): it arms the RTC watchdog for 1 s as a safety net, and the ROM download mode never
    // feeds it, so the chip resets again and boots the app. Disarm it and reset the system directly.
    wdt_hal_context_t rtc = RWDT_HAL_CONTEXT_DEFAULT();
    wdt_hal_write_protect_disable(&rtc);
    wdt_hal_disable(&rtc);
    wdt_hal_write_protect_enable(&rtc);
    esp_rom_software_reset_system();
}

static char s_selftest[1536];  // tentative definition; also declared above h_progress
static volatile int s_selftest_n;

// Writes N synthetic ~1.5 KB records through the real store (kind "test"), reporting speed and heap
static void selftest_task(void *arg)
{
    (void)arg;
    int n = s_selftest_n;
    size_t len = snprintf(s_selftest, sizeof(s_selftest), "selftest: writing %d synthetic items (~1.5 KB each) to the log store\n", n);
    char notes[1201];
    int64_t t0 = esp_timer_get_time(), tlast = t0;
    tw_store_stats_t st0;
    tw_store_stats(&st0);
    for (int i = 0; i < n; i++) {
        uint8_t raw[900];
        tw_random(raw, sizeof(raw));
        tw_b64_encode(raw, sizeof(raw), notes, sizeof(notes));
        cJSON *b = cJSON_CreateObject();
        cJSON_AddNumberToObject(b, "type", 1);
        cJSON_AddStringToObject(b, "name", "2.AAAAAAAAAAAAAAAAAAAAAA==|BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB|CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=");
        cJSON_AddStringToObject(b, "notes", notes);
        char id[37], path[64];
        tw_uuid(id);
        cJSON *c = cipher_from_request(b, id, NULL);
        cJSON_Delete(b);
        snprintf(path, sizeof(path), TW_TEST_DIR "/%s.json", id);
        esp_err_t err = tw_store_write(path, c);
        cJSON_Delete(c);
        if (err != ESP_OK) {
            len += snprintf(s_selftest + len, sizeof(s_selftest) - len, "write FAILED at item %d: %s\n", i, esp_err_to_name(err));
            break;
        }
        if ((i + 1) % 100 == 0 && len < sizeof(s_selftest) - 100) {
            int64_t now = esp_timer_get_time();
            len += snprintf(s_selftest + len, sizeof(s_selftest) - len,
                            "%4d items: last 100 took %5u ms (%3u ms/item), heap %u KB min %u KB\n", i + 1,
                            (unsigned)((now - tlast) / 1000), (unsigned)((now - tlast) / 100000),
                            (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024),
                            (unsigned)(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL) / 1024));
            tlast = now;
        }
        vTaskDelay(1);
    }
    tw_store_stats_t st;
    tw_store_stats(&st);
    if (len < sizeof(s_selftest) - 120) {
        snprintf(s_selftest + len, sizeof(s_selftest) - len,
                 "done in %u ms; gc runs %u; live %u KB, stale %u KB. Delete with POST /s/dev/selftest-clean\n",
                 (unsigned)((esp_timer_get_time() - t0) / 1000), (unsigned)(st.gc_runs - st0.gc_runs),
                 (unsigned)(st.live_bytes / 1024), (unsigned)(st.stale_bytes / 1024));
    }
    s_selftest_n = 0;
    vTaskDelete(NULL);
}

static esp_err_t h_dev_selftest(httpd_req_t *req)
{
    if (s_selftest_n) {
        httpd_resp_sendstr(req, "already running\n");
        return ESP_OK;
    }
    char q[48], v[8] = "800";
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        httpd_query_key_value(q, "n", v, sizeof(v));
    }
    s_selftest_n = atoi(v) > 0 ? atoi(v) : 800;
    xTaskCreate(selftest_task, "selftest", 8192, NULL, 4, NULL);
    httpd_resp_sendstr(req, "started; watch http://" TW_IP_STR "/progress\n");
    return ESP_OK;
}

static esp_err_t h_dev_selftest_clean(httpd_req_t *req)
{
    int64_t t0 = esp_timer_get_time();
    esp_err_t err = tw_store_delete_all(TW_TEST_DIR);
    char out[96];
    snprintf(out, sizeof(out), "cleaned (%s) in %u ms\n", esp_err_to_name(err), (unsigned)((esp_timer_get_time() - t0) / 1000));
    httpd_resp_sendstr(req, out);
    return ESP_OK;
}

static void plain_restart(void *arg)
{
    (void)arg;
    vTaskDelay(pdMS_TO_TICKS(300));
    esp_restart();
}

static esp_err_t h_dev_reboot(httpd_req_t *req)
{
    httpd_resp_sendstr(req, "rebooting\n");
    xTaskCreate(plain_restart, "rb", 2048, NULL, 5, NULL);
    return ESP_OK;
}

static esp_err_t h_dev_download(httpd_req_t *req)
{
    log_req(req, "200");
    httpd_resp_sendstr(req, "rebooting into download mode\n");
    xTaskCreate(reboot_to_download, "dl", 2048, NULL, 5, NULL);
    return ESP_OK;
}
#endif

// ---------- Certificate download (HTTPS, only with the status page unlocked) ----------
// Not on port 80: the session cookie is Secure, and a certificate anyone can fetch says what the board is.

static const char *s_cert_pem;

static esp_err_t h_cert(httpd_req_t *req)
{
    REQUIRE_SESSION(req);
    httpd_resp_set_type(req, "application/x-x509-ca-cert");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=\"ca.crt\"");
    return httpd_resp_sendstr(req, s_cert_pem);
}

#if CONFIG_TW_DEV_DOWNLOAD_ENDPOINT
static char s_selftest[1536];
#endif

// Import progress on port 80: answers while the HTTPS task is busy. Counts only, and worded so it does not
// say what the device is (anyone at the USB link can read it).
static esp_err_t h_progress(httpd_req_t *req)
{
    char out[256];
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000000);
    if (s_imp_total < 0) {
        snprintf(out, sizeof(out), "idle\n");
    } else if (s_imp_running) {
        snprintf(out, sizeof(out), "working: %d / %d (%d%%), %u s\n", s_imp_written, s_imp_total,
                 s_imp_total ? s_imp_written * 100 / s_imp_total : 100, (unsigned)(now - s_imp_started_s));
    } else {
        snprintf(out, sizeof(out), "%s\n", s_imp_result);
    }
    size_t n = strlen(out);
    snprintf(out + n, sizeof(out) - n, "uptime %u s, last reset: %s, internal heap %u KB (min %u KB)\n",
             (unsigned)now, reset_reason_str(),
             (unsigned)(heap_caps_get_free_size(MALLOC_CAP_INTERNAL) / 1024),
             (unsigned)(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL) / 1024));
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_set_hdr(req, "Refresh", "2");  // browsers reload every 2 s
    httpd_resp_sendstr_chunk(req, out);
#if CONFIG_TW_DEV_DOWNLOAD_ENDPOINT
    httpd_resp_sendstr_chunk(req, s_selftest);
#endif
    return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t h_http_other(httpd_req_t *req)
{
    httpd_resp_set_status(req, "301 Moved Permanently");
    httpd_resp_set_hdr(req, "Location", TW_ORIGIN "/alive");
    return httpd_resp_send(req, NULL, 0);
}

// ---------- start ----------

esp_err_t tw_api_start(void)
{
    const char *cert, *key, *ca;
    size_t cert_len, key_len;
    ESP_ERROR_CHECK(tw_tls_load_or_create(&cert, &cert_len, &key, &key_len, &ca));
    s_cert_pem = ca;  // GET /ca.crt hands out the CA certificate
    compute_cert_fp(ca);

    httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
    conf.servercert = (const uint8_t *)cert;
    conf.servercert_len = cert_len;
    conf.prvtkey_pem = (const uint8_t *)key;
    conf.prvtkey_len = key_len;
    conf.httpd.uri_match_fn = httpd_uri_match_wildcard;
    conf.httpd.max_uri_handlers = 40;
    conf.httpd.stack_size = 16384;
    conf.httpd.max_open_sockets = 4;
    conf.httpd.lru_purge_enable = true;

    httpd_handle_t https = NULL;
    esp_err_t err = httpd_ssl_start(&https, &conf);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "https start failed: %s", esp_err_to_name(err));
        return err;
    }

    // Order matters: the first wildcard that matches wins
    const httpd_uri_t routes[] = {
        {"/*", HTTP_OPTIONS, h_options, NULL},
        {"/", HTTP_GET, h_status, NULL},
        {"/alive", HTTP_GET, h_alive, NULL},
        {"/web/*", HTTP_GET, tw_web_file, NULL},
        {"/merge", HTTP_GET, tw_web_file, NULL},
        {"/manual", HTTP_GET, tw_web_manual, NULL},
        {"/ca.crt", HTTP_GET, h_cert, NULL},
        {"/s/wipe", HTTP_POST, h_wipe, NULL},
        {"/s/unlock", HTTP_POST, h_unlock, NULL},
        {"/s/lock", HTTP_POST, h_lock, NULL},
        {"/s/backup", HTTP_POST, h_backup, NULL},
        {"/s/kdf/key", HTTP_POST, h_kdf_key, NULL},
        {"/s/kdf", HTTP_POST, h_kdf, NULL},
        {"/api/config", HTTP_GET, h_config, NULL},
        {"/identity/accounts/prelogin*", HTTP_POST, h_prelogin, NULL},
        {"/identity/accounts/register/send-verification-email", HTTP_POST, h_register_email, NULL},
        {"/identity/accounts/register/finish", HTTP_POST, h_register_finish, NULL},
        {"/identity/connect/token", HTTP_POST, h_token, NULL},
        {"/api/devices/knowndevice*", HTTP_GET, h_known_device, NULL},
        {"/api/accounts/profile", HTTP_GET, h_profile, NULL},
        {"/api/accounts/revision-date", HTTP_GET, h_revision_date, NULL},
        {"/api/accounts/key-management/user-key-id", HTTP_POST, h_user_key_id, NULL},
        {"/api/auth-requests/pending*", HTTP_GET, h_auth_pending, NULL},
        {"/api/sync*", HTTP_GET, h_sync, NULL},
        {"/api/ciphers/import", HTTP_POST, h_ciphers_import, NULL},  // before /api/ciphers*
        {"/api/ciphers*", HTTP_POST, h_ciphers_post, NULL},
        {"/api/ciphers/*", HTTP_GET, h_ciphers_get, NULL},
        {"/api/ciphers/*", HTTP_PUT, h_ciphers_put, NULL},
        {"/api/ciphers/*", HTTP_DELETE, h_ciphers_delete, NULL},
        {"/api/folders*", HTTP_POST, h_folders, NULL},
        {"/api/folders/*", HTTP_PUT, h_folders, NULL},
        {"/api/folders/*", HTTP_DELETE, h_folders, NULL},
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        httpd_register_uri_handler(https, &routes[i]);
    }
#if CONFIG_TW_DEV_DOWNLOAD_ENDPOINT
    const httpd_uri_t dev_routes[] = {
        {"/s/dev/download-mode", HTTP_POST, h_dev_download, NULL},
        {"/s/dev/selftest", HTTP_POST, h_dev_selftest, NULL},
        {"/s/dev/reboot", HTTP_POST, h_dev_reboot, NULL},
        {"/s/dev/selftest-clean", HTTP_POST, h_dev_selftest_clean, NULL},
    };
    for (size_t i = 0; i < sizeof(dev_routes) / sizeof(dev_routes[0]); i++) {
        httpd_register_uri_handler(https, &dev_routes[i]);
    }
    ESP_LOGW(TAG, "development build: download-mode endpoint enabled");
#endif

    httpd_config_t hconf = HTTPD_DEFAULT_CONFIG();
    hconf.server_port = 80;
    hconf.ctrl_port = ESP_HTTPD_DEF_CTRL_PORT;  // 32768; HTTPS already uses 32769 (its default)
    hconf.uri_match_fn = httpd_uri_match_wildcard;
    hconf.max_open_sockets = 3;  // only import progress and the redirect to HTTPS
    hconf.lru_purge_enable = true;
    httpd_handle_t http = NULL;
    s_http_err = httpd_start(&http, &hconf);
    if (s_http_err != ESP_OK) {
        ESP_LOGE(TAG, "http start failed: %s", esp_err_to_name(s_http_err));
    } else {
        const httpd_uri_t other = {"/*", HTTP_GET, h_http_other, NULL};
        const httpd_uri_t progress_route = {"/progress", HTTP_GET, h_progress, NULL};
        httpd_register_uri_handler(http, &progress_route);
        httpd_register_uri_handler(http, &other);
    }
    ESP_LOGI(TAG, "listening on " TW_ORIGIN);
    return ESP_OK;
}
