// Registration, login check with fail counter and wipe, JWT (SPEC 4, 6).
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "nvs.h"
#include "tw.h"

static const char *TAG = "auth";

#define REFRESH_SLOTS 8
#define TOKEN_LEN 48  // base64 of 32 bytes is 44 chars; mbedtls also needs room for the NUL

static uint8_t s_jwt_secret[32];               // new every boot: unplugging logs everyone out
static char s_refresh[REFRESH_SLOTS][TOKEN_LEN];
static int s_refresh_next;
static char s_reg_email[256], s_reg_name[128], s_reg_token[TOKEN_LEN];

void tw_auth_init(void)
{
    tw_random(s_jwt_secret, sizeof(s_jwt_secret));
    memset(s_refresh, 0, sizeof(s_refresh));
}

cJSON *tw_user_load(void)
{
    return tw_store_read(TW_USER_PATH);
}

bool tw_user_exists(void)
{
    return tw_store_exists(TW_USER_PATH);
}

static void lower_trim(const char *in, char *out, size_t out_len)
{
    while (*in && isspace((unsigned char)*in)) in++;
    size_t n = 0;
    for (; *in && n + 1 < out_len; in++) out[n++] = (char)tolower((unsigned char)*in);
    while (n > 0 && isspace((unsigned char)out[n - 1])) n--;
    out[n] = '\0';
}

// ---------- fail counter (NVS, written before comparing) ----------

static uint8_t fails_get(void)
{
    uint8_t v = 0;
    nvs_handle_t h;
    if (nvs_open("tw", NVS_READONLY, &h) == ESP_OK) {
        nvs_get_u8(h, "fails", &v);
        nvs_close(h);
    }
    return v;
}

static void fails_set(uint8_t v)
{
    nvs_handle_t h;
    if (nvs_open("tw", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_u8(h, "fails", v);
        nvs_commit(h);
        nvs_close(h);
    }
}

// ---------- server-side hash of the client's masterPasswordHash ----------

static bool pw_derive(const char *client_hash, const uint8_t *salt, size_t salt_len, int iter, uint8_t out[32])
{
    return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)client_hash, strlen(client_hash),
                                         salt, salt_len, iter, 32, out) == 0;
}

// ---------- registration ----------

const char *tw_auth_pending_register_token(const char *email, const char *name)
{
    uint8_t raw[32];
    tw_random(raw, sizeof(raw));
    tw_b64url_encode(raw, sizeof(raw), s_reg_token, sizeof(s_reg_token));
    lower_trim(email, s_reg_email, sizeof(s_reg_email));
    snprintf(s_reg_name, sizeof(s_reg_name), "%s", name ? name : "");
    return s_reg_token;
}

bool tw_auth_check_register_token(const char *token, char *name_out, size_t name_len)
{
    if (!s_reg_token[0] || !token || strcmp(token, s_reg_token) != 0) {
        return false;
    }
    snprintf(name_out, name_len, "%s", s_reg_name);
    return true;
}

static const cJSON *get_any(const cJSON *o, const char *a, const char *b)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, a);
    if (!v && b) v = cJSON_GetObjectItemCaseSensitive(o, b);
    return v;
}

static const char *get_str(const cJSON *o, const char *a, const char *b)
{
    const cJSON *v = get_any(o, a, b);
    return cJSON_IsString(v) ? v->valuestring : NULL;
}

static void copy_kdf(cJSON *user, const cJSON *kdf)
{
    const cJSON *t = get_any(kdf, "kdf", "kdfType");
    const cJSON *i = get_any(kdf, "kdfIterations", "iterations");
    const cJSON *m = get_any(kdf, "kdfMemory", "memory");
    const cJSON *p = get_any(kdf, "kdfParallelism", "parallelism");
    cJSON_AddNumberToObject(user, "kdf", cJSON_IsNumber(t) ? t->valueint : 0);
    cJSON_AddNumberToObject(user, "kdfIterations", cJSON_IsNumber(i) ? i->valueint : 600000);
    cJSON_AddItemToObject(user, "kdfMemory", cJSON_IsNumber(m) ? cJSON_CreateNumber(m->valueint) : cJSON_CreateNull());
    cJSON_AddItemToObject(user, "kdfParallelism", cJSON_IsNumber(p) ? cJSON_CreateNumber(p->valueint) : cJSON_CreateNull());
}

// Accepts both the old flat body and the current masterPasswordAuthentication/Unlock body
// (Vaultwarden RegisterDataCompat).
esp_err_t tw_auth_register(cJSON *body)
{
    if (tw_user_exists()) {
        return ESP_ERR_INVALID_STATE;
    }
    const char *email_in = get_str(body, "email", NULL);
    if (!email_in) {
        return ESP_ERR_INVALID_ARG;
    }
    char email[256];
    lower_trim(email_in, email, sizeof(email));

    char name[128] = "";
    tw_auth_check_register_token(get_str(body, "emailVerificationToken", NULL), name, sizeof(name));

    const cJSON *mpa = get_any(body, "masterPasswordAuthentication", "MasterPasswordAuthentication");
    const cJSON *mpu = get_any(body, "masterPasswordUnlock", "MasterPasswordUnlock");
    const char *client_hash, *akey, *salt = NULL, *key_id = NULL;
    const cJSON *kdf;
    if (mpa && mpu) {
        client_hash = get_str(mpa, "hash", "masterPasswordAuthenticationHash");
        kdf = get_any(mpa, "kdf", "Kdf");
        salt = get_str(mpa, "salt", "Salt");
        akey = get_str(mpu, "key", "masterKeyWrappedUserKey");
        key_id = get_str(mpu, "containedKeyId", NULL);
    } else {
        client_hash = get_str(body, "masterPasswordHash", NULL);
        akey = get_str(body, "key", "userSymmetricKey");
        kdf = body;
    }
    if (!client_hash || !akey || !kdf) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!tw_button_wait(TW_BUTTON_WAIT_MS)) {
        return ESP_ERR_TIMEOUT;
    }

    cJSON *user = cJSON_CreateObject();
    char id[37], iso[32], stamp[37];
    tw_uuid(id);
    tw_uuid(stamp);
    tw_now_iso(iso);
    cJSON_AddStringToObject(user, "id", id);
    cJSON_AddStringToObject(user, "email", email);
    cJSON_AddStringToObject(user, "name", name[0] ? name : email);
    cJSON_AddStringToObject(user, "securityStamp", stamp);
    cJSON_AddStringToObject(user, "creationDate", iso);
    cJSON_AddStringToObject(user, "key", akey);
    copy_kdf(user, kdf);
    cJSON_AddItemToObject(user, "salt", salt ? cJSON_CreateString(salt) : cJSON_CreateNull());
    cJSON_AddItemToObject(user, "userKeyId", key_id ? cJSON_CreateString(key_id) : cJSON_CreateNull());

    const cJSON *keys = get_any(body, "userAsymmetricKeys", "keys");
    const char *priv = keys ? get_str(keys, "encryptedPrivateKey", NULL) : NULL;
    const char *pub = keys ? get_str(keys, "publicKey", NULL) : NULL;
    cJSON_AddItemToObject(user, "privateKey", priv ? cJSON_CreateString(priv) : cJSON_CreateNull());
    cJSON_AddItemToObject(user, "publicKey", pub ? cJSON_CreateString(pub) : cJSON_CreateNull());
    const cJSON *account_keys = cJSON_GetObjectItemCaseSensitive(body, "accountKeys");
    cJSON_AddItemToObject(user, "accountKeys", account_keys ? cJSON_Duplicate(account_keys, true) : cJSON_CreateNull());

    uint8_t pw_salt[16], pw_hash[32];
    char b64[64];
    tw_random(pw_salt, sizeof(pw_salt));
    if (!pw_derive(client_hash, pw_salt, sizeof(pw_salt), TW_PW_ITER, pw_hash)) {
        cJSON_Delete(user);
        return ESP_FAIL;
    }
    tw_b64_encode(pw_salt, sizeof(pw_salt), b64, sizeof(b64));
    cJSON_AddStringToObject(user, "pwSalt", b64);
    cJSON_AddNumberToObject(user, "pwIter", TW_PW_ITER);
    tw_b64_encode(pw_hash, sizeof(pw_hash), b64, sizeof(b64));
    cJSON_AddStringToObject(user, "pwHash", b64);
    cJSON_AddItemToObject(user, "devices", cJSON_CreateArray());

    esp_err_t err = tw_store_write(TW_USER_PATH, user);
    cJSON_Delete(user);
    fails_set(0);
    tw_clock_persist();
    s_reg_token[0] = '\0';
    tw_auth_init();
    ESP_LOGI(TAG, "user created");
    return err;
}

// ---------- changing the KDF (POST /tw/kdf) ----------
// The vault's user key stays the same: only its wrapping by the master key, the KDF settings and the
// server-side hash of the new masterPasswordHash change, in one record write (old or new state after a
// power cut, never a mix). Everyone is logged out afterwards. The caller has checked the old password
// and the button.
esp_err_t tw_auth_set_master(const char *client_hash, const char *key, const cJSON *kdf)
{
    cJSON *user = tw_user_load();
    if (!user) {
        return ESP_ERR_NOT_FOUND;
    }
    static const char *const replaced[] = {"key", "kdf", "kdfIterations", "kdfMemory", "kdfParallelism",
                                           "securityStamp", "pwSalt", "pwIter", "pwHash"};
    for (size_t i = 0; i < sizeof(replaced) / sizeof(replaced[0]); i++) {
        cJSON_DeleteItemFromObjectCaseSensitive(user, replaced[i]);
    }
    char stamp[37];
    tw_uuid(stamp);
    cJSON_AddStringToObject(user, "key", key);
    copy_kdf(user, kdf);
    cJSON_AddStringToObject(user, "securityStamp", stamp);

    uint8_t pw_salt[16], pw_hash[32];
    char b64[64];
    tw_random(pw_salt, sizeof(pw_salt));
    if (!pw_derive(client_hash, pw_salt, sizeof(pw_salt), TW_PW_ITER, pw_hash)) {
        cJSON_Delete(user);
        return ESP_FAIL;
    }
    tw_b64_encode(pw_salt, sizeof(pw_salt), b64, sizeof(b64));
    cJSON_AddStringToObject(user, "pwSalt", b64);
    cJSON_AddNumberToObject(user, "pwIter", TW_PW_ITER);
    tw_b64_encode(pw_hash, sizeof(pw_hash), b64, sizeof(b64));
    cJSON_AddStringToObject(user, "pwHash", b64);

    esp_err_t err = tw_store_write(TW_USER_PATH, user);
    cJSON_Delete(user);
    if (err == ESP_OK) {
        tw_auth_init();  // new token key: every client logs in again and picks up the new KDF
        ESP_LOGI(TAG, "KDF changed");
    }
    return err;
}

// ---------- login ----------

tw_login_result_t tw_auth_check_password(const char *email_in, const char *client_hash)
{
    cJSON *user = tw_user_load();
    if (!user) {
        return TW_LOGIN_BAD;
    }
    // Button first, so an unattended device cannot be brute-forced and a missed press is not a failure
    if (!tw_button_wait(TW_BUTTON_WAIT_MS)) {
        cJSON_Delete(user);
        return TW_LOGIN_NO_BUTTON;
    }

    uint8_t fails = fails_get();
    if (fails >= TW_MAX_FAILS) {
        cJSON_Delete(user);
        tw_store_wipe();
        fails_set(0);
        tw_auth_init();
        return TW_LOGIN_WIPED;
    }
    fails_set(fails + 1);  // before comparing (SPEC 6)

    char email[256];
    lower_trim(email_in ? email_in : "", email, sizeof(email));
    const char *u_email = get_str(user, "email", NULL);
    uint8_t salt[32], want[32], got[32];
    int salt_len = tw_b64_decode(get_str(user, "pwSalt", NULL) ?: "", salt, sizeof(salt));
    int want_len = tw_b64_decode(get_str(user, "pwHash", NULL) ?: "", want, sizeof(want));
    const cJSON *iter = cJSON_GetObjectItemCaseSensitive(user, "pwIter");
    bool ok = u_email && strcmp(u_email, email) == 0 && salt_len > 0 && want_len == 32 && cJSON_IsNumber(iter) &&
              pw_derive(client_hash ? client_hash : "", salt, salt_len, iter->valueint, got) &&
              tw_ct_equal(got, want, 32);
    cJSON_Delete(user);

    if (ok) {
        fails_set(0);
        return TW_LOGIN_OK;
    }
    if (fails + 1 >= TW_MAX_FAILS) {
        tw_store_wipe();
        fails_set(0);
        tw_auth_init();  // tokens of the wiped user must not work for a new one
        return TW_LOGIN_WIPED;
    }
    return TW_LOGIN_BAD;
}

// ---------- JWT (HS256, secret renewed every boot) ----------

static char *jwt_sign(const cJSON *claims)
{
    static const char header[] = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
    char *payload = cJSON_PrintUnformatted(claims);
    if (!payload) {
        return NULL;
    }
    size_t plen = strlen(payload);
    size_t cap = 64 + (plen * 4) / 3 + 64;
    char *out = malloc(cap);
    if (!out) {
        free(payload);
        return NULL;
    }
    size_t n = tw_b64url_encode((const uint8_t *)header, strlen(header), out, cap);
    out[n++] = '.';
    n += tw_b64url_encode((const uint8_t *)payload, plen, out + n, cap - n);
    free(payload);

    uint8_t mac[32];
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), s_jwt_secret, sizeof(s_jwt_secret),
                    (const unsigned char *)out, n, mac);
    out[n++] = '.';
    tw_b64url_encode(mac, sizeof(mac), out + n, cap - n);
    return out;
}

char *tw_auth_issue_access(const cJSON *user, const char *device_id, const char *device_type)
{
    cJSON *c = cJSON_CreateObject();
    cJSON_AddNumberToObject(c, "nbf", (double)(tw_now_ms() / 1000 - 60));
    // 2038-01-19, just under 2^31: the Android app reads exp as a 32-bit Int and crashes on more (SPEC 4)
    cJSON_AddNumberToObject(c, "exp", 2147483000.0);
    cJSON_AddStringToObject(c, "iss", TW_ORIGIN "|login");
    cJSON_AddStringToObject(c, "sub", get_str(user, "id", NULL) ?: "");
    cJSON_AddBoolToObject(c, "premium", true);
    cJSON_AddStringToObject(c, "name", get_str(user, "name", NULL) ?: "");
    cJSON_AddStringToObject(c, "email", get_str(user, "email", NULL) ?: "");
    cJSON_AddBoolToObject(c, "email_verified", true);
    cJSON_AddStringToObject(c, "sstamp", get_str(user, "securityStamp", NULL) ?: "");
    cJSON_AddStringToObject(c, "device", device_id ? device_id : "");
    cJSON_AddStringToObject(c, "devicetype", device_type ? device_type : "");
    cJSON_AddStringToObject(c, "client_id", "browser");
    cJSON *scope = cJSON_AddArrayToObject(c, "scope");
    cJSON_AddItemToArray(scope, cJSON_CreateString("api"));
    cJSON_AddItemToArray(scope, cJSON_CreateString("offline_access"));
    cJSON *amr = cJSON_AddArrayToObject(c, "amr");
    cJSON_AddItemToArray(amr, cJSON_CreateString("Application"));
    char *jwt = jwt_sign(c);
    cJSON_Delete(c);
    return jwt;
}

char *tw_auth_issue_refresh(void)
{
    uint8_t raw[32];
    tw_random(raw, sizeof(raw));
    char *tok = &s_refresh[s_refresh_next][0];
    tw_b64url_encode(raw, sizeof(raw), tok, TOKEN_LEN);
    s_refresh_next = (s_refresh_next + 1) % REFRESH_SLOTS;
    return strdup(tok);
}

bool tw_auth_use_refresh(const char *token)
{
    if (!token || !token[0]) {
        return false;
    }
    for (int i = 0; i < REFRESH_SLOTS; i++) {
        if (s_refresh[i][0] && strcmp(s_refresh[i], token) == 0) {
            return true;
        }
    }
    return false;
}

bool tw_auth_check_bearer(httpd_req_t *req)
{
    char hdr[2048];
    if (httpd_req_get_hdr_value_str(req, "Authorization", hdr, sizeof(hdr)) != ESP_OK ||
        strncmp(hdr, "Bearer ", 7) != 0) {
        return false;
    }
    char *tok = hdr + 7;
    char *dot2 = strrchr(tok, '.');
    if (!dot2) {
        return false;
    }
    uint8_t mac[32], got[40];
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), s_jwt_secret, sizeof(s_jwt_secret),
                    (const unsigned char *)tok, dot2 - tok, mac);
    int n = tw_b64_decode(dot2 + 1, got, sizeof(got));
    return n == 32 && tw_ct_equal(mac, got, 32) && tw_user_exists();
}

// Wipe from the status page (after the button press): same effect as too many failed logins
esp_err_t tw_auth_factory_reset(void)
{
    esp_err_t err = tw_store_wipe();
    fails_set(0);
    tw_auth_init();  // tokens of the wiped user must not work for a new one
    return err;
}
