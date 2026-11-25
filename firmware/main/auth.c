// Registration, login check with fail counter and wipe, JWT (SPEC 4, 6).
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/sha256.h"
#include "esp_partition.h"
#include "nvs.h"
#include "tw.h"

static const char *TAG = "auth";

#define REFRESH_SLOTS 8
#define TOKEN_LEN 48  // base64 of 32 bytes is 44 chars; mbedtls also needs room for the NUL

static uint8_t s_jwt_secret[32];               // new every boot: unplugging logs everyone out
static char s_refresh[REFRESH_SLOTS][TOKEN_LEN];
static int s_refresh_next;
static char s_refresh_email[REFRESH_SLOTS][256];  // the username each refresh token was issued for
static char s_reg_name[128], s_reg_token[TOKEN_LEN];
static uint8_t s_sk[32];  // storage key, in RAM only after a login (SPEC 5.4)
static bool s_have_sk;

void tw_auth_init(void)
{
    tw_random(s_jwt_secret, sizeof(s_jwt_secret));
    memset(s_refresh, 0, sizeof(s_refresh));
    memset(s_refresh_email, 0, sizeof(s_refresh_email));
}

static void forget_sk(void)
{
    memset(s_sk, 0, sizeof(s_sk));
    s_have_sk = false;
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

// ---------- the account: plaintext header + sealed user record ----------
// The header holds what is needed before the store is unlocked, and what a KDF change replaces in one
// write: the KDF settings, the user key as wrapped by the master key (an EncString: opening it needs the
// password and the username, like the storage key), the security stamp and the wrapped storage key.

static const char *const HEAD_FIELDS[] = {"v", "kdf", "kdfIterations", "kdfMemory", "kdfParallelism", "key",
                                          "securityStamp", "pwSalt", "pwIter", "wrap"};
#define N_HEAD_FIELDS (sizeof(HEAD_FIELDS) / sizeof(HEAD_FIELDS[0]))
#define HEAD_VERSION 2

cJSON *tw_head_load(void)
{
    return tw_store_read(TW_HEAD_PATH);
}

bool tw_user_exists(void)
{
    return tw_store_exists(TW_HEAD_PATH);
}

cJSON *tw_user_load(void)
{
    cJSON *head = tw_head_load();
    if (!head) {
        return NULL;
    }
    cJSON *user = tw_store_read(TW_USER_PATH);  // NULL while locked
    if (!user) {
        user = cJSON_CreateObject();
    }
    for (size_t i = 0; i < N_HEAD_FIELDS; i++) {
        const char *k = HEAD_FIELDS[i];
        if (!strcmp(k, "pwSalt") || !strcmp(k, "pwIter") || !strcmp(k, "wrap")) continue;
        const cJSON *v = cJSON_GetObjectItemCaseSensitive(head, k);
        if (!v) continue;
        cJSON_DeleteItemFromObjectCaseSensitive(user, k);
        cJSON_AddItemToObject(user, k, cJSON_Duplicate(v, true));
    }
    cJSON_Delete(head);
    return user;
}

esp_err_t tw_user_save(const cJSON *user)
{
    cJSON *u = cJSON_Duplicate(user, true);
    if (!u) {
        return ESP_ERR_NO_MEM;
    }
    for (size_t i = 0; i < N_HEAD_FIELDS; i++) {
        cJSON_DeleteItemFromObjectCaseSensitive(u, HEAD_FIELDS[i]);
    }
    cJSON_DeleteItemFromObjectCaseSensitive(u, "email");  // never stored, even sealed
    cJSON_DeleteItemFromObjectCaseSensitive(u, "salt");   // the clients' salt is the email
    esp_err_t err = tw_store_write(TW_USER_PATH, u);
    cJSON_Delete(u);
    return err;
}

void tw_email_norm(const char *in, char *out, size_t out_len)
{
    if (!in) in = "";
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

// ---------- the storage key, wrapped with a key from the client's masterPasswordHash ----------
// kek = PBKDF2-SHA256(masterPasswordHash, pwSalt, pwIter); wrap = base64(nonce 12 || AES-256-GCM(kek, sk) || tag 16).
// The login check is that the wrap opens: the board keeps no hash to compare with.

#define WRAP_AAD "tinywarden storage key"

static bool kek_derive(const char *client_hash, const uint8_t *salt, size_t salt_len, int iter, uint8_t out[32])
{
    return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)client_hash, strlen(client_hash),
                                         salt, salt_len, iter, 32, out) == 0;
}

// Adds pwSalt, pwIter and wrap for this hash to head (replacing old ones)
static bool head_set_wrap(cJSON *head, const char *client_hash, const uint8_t sk[32])
{
    uint8_t salt[16], kek[32], blob[12 + 32 + 16];
    char b64[128];
    tw_random(salt, sizeof(salt));
    tw_random(blob, 12);
    bool ok = kek_derive(client_hash, salt, sizeof(salt), TW_PW_ITER, kek);
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    ok = ok && mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, kek, 256) == 0 &&
         mbedtls_gcm_crypt_and_tag(&g, MBEDTLS_GCM_ENCRYPT, 32, blob, 12, (const unsigned char *)WRAP_AAD,
                                   strlen(WRAP_AAD), sk, blob + 12, 16, blob + 44) == 0;
    mbedtls_gcm_free(&g);
    memset(kek, 0, sizeof(kek));
    if (!ok) return false;
    cJSON_DeleteItemFromObjectCaseSensitive(head, "pwSalt");
    cJSON_DeleteItemFromObjectCaseSensitive(head, "pwIter");
    cJSON_DeleteItemFromObjectCaseSensitive(head, "wrap");
    tw_b64_encode(salt, sizeof(salt), b64, sizeof(b64));
    cJSON_AddStringToObject(head, "pwSalt", b64);
    cJSON_AddNumberToObject(head, "pwIter", TW_PW_ITER);
    tw_b64_encode(blob, sizeof(blob), b64, sizeof(b64));
    cJSON_AddStringToObject(head, "wrap", b64);
    return true;
}

static bool head_unwrap(const cJSON *head, const char *client_hash, uint8_t sk[32])
{
    uint8_t salt[32], blob[64], kek[32];
    int salt_len = tw_b64_decode(get_str(head, "pwSalt", NULL) ?: "", salt, sizeof(salt));
    int blob_len = tw_b64_decode(get_str(head, "wrap", NULL) ?: "", blob, sizeof(blob));
    const cJSON *iter = cJSON_GetObjectItemCaseSensitive(head, "pwIter");
    if (salt_len <= 0 || blob_len != 60 || !cJSON_IsNumber(iter) || !client_hash ||
        !kek_derive(client_hash, salt, salt_len, iter->valueint, kek)) {
        return false;
    }
    mbedtls_gcm_context g;
    mbedtls_gcm_init(&g);
    bool ok = mbedtls_gcm_setkey(&g, MBEDTLS_CIPHER_ID_AES, kek, 256) == 0 &&
              mbedtls_gcm_auth_decrypt(&g, 32, blob, 12, (const unsigned char *)WRAP_AAD, strlen(WRAP_AAD),
                                       blob + 44, 16, blob + 12, sk) == 0;
    mbedtls_gcm_free(&g);
    memset(kek, 0, sizeof(kek));
    return ok;
}

// ---------- one-time setup code (partition "setup", written by the flasher) ----------
// Layout: "SC" 0x01 0x00, salt 16 bytes, SHA-256(salt || code) 32 bytes, the rest 0xFF. The code is
// 12 characters of tools/setup_code.py's alphabet (60 bits); the flasher shows it, the board keeps only
// the hash. It opens the status page until an account exists; registering erases it.

static const esp_partition_t *setup_part(void)
{
    return esp_partition_find_first(ESP_PARTITION_TYPE_DATA, (esp_partition_subtype_t)0x41, "setup");
}

static bool setup_read(uint8_t salt[16], uint8_t hash[32])
{
    const esp_partition_t *p = setup_part();
    uint8_t buf[52];
    if (!p || esp_partition_read(p, 0, buf, sizeof(buf)) != ESP_OK) return false;
    if (buf[0] != 'S' || buf[1] != 'C' || buf[2] != 1 || buf[3] != 0) return false;
    memcpy(salt, buf + 4, 16);
    memcpy(hash, buf + 20, 32);
    return true;
}

bool tw_setup_present(void)
{
    uint8_t salt[16], hash[32];
    return setup_read(salt, hash);
}

static void setup_clear(void)
{
    const esp_partition_t *p = setup_part();
    if (p) esp_partition_erase_range(p, 0, p->size);
}

// Before an account exists only. Checked like a login: button first, then the failure counter.
tw_login_result_t tw_auth_check_setup(const char *code_in)
{
    uint8_t salt[16], want[32], got[32];
    if (tw_user_exists() || !setup_read(salt, want)) {
        return TW_LOGIN_BAD;
    }
    if (!tw_button_wait(TW_BUTTON_WAIT_MS)) {
        return TW_LOGIN_NO_BUTTON;
    }
    uint8_t fails = fails_get();
    fails_set(fails + 1 >= TW_MAX_FAILS ? 0 : fails + 1);  // nothing to wipe yet: the button is the brake
    char code[16];
    size_t n = 0;
    for (const char *c = code_in ? code_in : ""; *c && n < 12; c++) {
        if (*c == '-' || *c == ' ') continue;
        code[n++] = (char)toupper((unsigned char)*c);
    }
    mbedtls_sha256_context h;
    mbedtls_sha256_init(&h);
    mbedtls_sha256_starts(&h, 0);
    mbedtls_sha256_update(&h, salt, 16);
    mbedtls_sha256_update(&h, (const unsigned char *)code, n);
    mbedtls_sha256_finish(&h, got);
    mbedtls_sha256_free(&h);
    if (n == 12 && tw_ct_equal(got, want, 32)) {
        fails_set(0);
        return TW_LOGIN_OK;
    }
    return TW_LOGIN_BAD;
}

// ---------- registration ----------

const char *tw_auth_pending_register_token(const char *name)
{
    uint8_t raw[32];
    tw_random(raw, sizeof(raw));
    tw_b64url_encode(raw, sizeof(raw), s_reg_token, sizeof(s_reg_token));
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

static void copy_kdf(cJSON *user, const cJSON *kdf)
{
    const cJSON *t = get_any(kdf, "kdf", "kdfType");
    const cJSON *i = get_any(kdf, "kdfIterations", "iterations");
    const cJSON *m = get_any(kdf, "kdfMemory", "memory");
    const cJSON *p = get_any(kdf, "kdfParallelism", "parallelism");
    static const char *const keys[] = {"kdf", "kdfIterations", "kdfMemory", "kdfParallelism"};
    for (size_t k = 0; k < 4; k++) cJSON_DeleteItemFromObjectCaseSensitive(user, keys[k]);
    cJSON_AddNumberToObject(user, "kdf", cJSON_IsNumber(t) ? t->valueint : 0);
    cJSON_AddNumberToObject(user, "kdfIterations", cJSON_IsNumber(i) ? i->valueint : 600000);
    cJSON_AddItemToObject(user, "kdfMemory", cJSON_IsNumber(m) ? cJSON_CreateNumber(m->valueint) : cJSON_CreateNull());
    cJSON_AddItemToObject(user, "kdfParallelism", cJSON_IsNumber(p) ? cJSON_CreateNumber(p->valueint) : cJSON_CreateNull());
}

// Accepts both the old flat body and the current masterPasswordAuthentication/Unlock body
// (Vaultwarden RegisterDataCompat). The email in it, and the "salt" (the same email), are not kept.
esp_err_t tw_auth_register(cJSON *body)
{
    if (tw_user_exists()) {
        return ESP_ERR_INVALID_STATE;
    }
    char name[128] = "";
    tw_auth_check_register_token(get_str(body, "emailVerificationToken", NULL), name, sizeof(name));

    const cJSON *mpa = get_any(body, "masterPasswordAuthentication", "MasterPasswordAuthentication");
    const cJSON *mpu = get_any(body, "masterPasswordUnlock", "MasterPasswordUnlock");
    const char *client_hash, *akey, *key_id = NULL;
    const cJSON *kdf;
    if (mpa && mpu) {
        client_hash = get_str(mpa, "hash", "masterPasswordAuthenticationHash");
        kdf = get_any(mpa, "kdf", "Kdf");
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

    uint8_t sk[32];
    tw_random(sk, sizeof(sk));
    esp_err_t err = tw_store_unlock(sk);
    if (err != ESP_OK) {
        return err;
    }

    // Sealed user record first, header last: until the header exists there is no account
    cJSON *user = cJSON_CreateObject();
    char id[37], iso[32], stamp[37];
    tw_uuid(id);
    tw_uuid(stamp);
    tw_now_iso(iso);
    cJSON_AddStringToObject(user, "id", id);
    cJSON_AddItemToObject(user, "name", name[0] ? cJSON_CreateString(name) : cJSON_CreateNull());
    cJSON_AddStringToObject(user, "creationDate", iso);
    cJSON_AddItemToObject(user, "userKeyId", key_id ? cJSON_CreateString(key_id) : cJSON_CreateNull());
    const cJSON *keys = get_any(body, "userAsymmetricKeys", "keys");
    const char *priv = keys ? get_str(keys, "encryptedPrivateKey", NULL) : NULL;
    const char *pub = keys ? get_str(keys, "publicKey", NULL) : NULL;
    cJSON_AddItemToObject(user, "privateKey", priv ? cJSON_CreateString(priv) : cJSON_CreateNull());
    cJSON_AddItemToObject(user, "publicKey", pub ? cJSON_CreateString(pub) : cJSON_CreateNull());
    const cJSON *account_keys = cJSON_GetObjectItemCaseSensitive(body, "accountKeys");
    cJSON_AddItemToObject(user, "accountKeys", account_keys ? cJSON_Duplicate(account_keys, true) : cJSON_CreateNull());
    cJSON_AddItemToObject(user, "devices", cJSON_CreateArray());
    err = tw_user_save(user);
    cJSON_Delete(user);

    cJSON *head = cJSON_CreateObject();
    cJSON_AddNumberToObject(head, "v", HEAD_VERSION);
    cJSON_AddStringToObject(head, "key", akey);
    copy_kdf(head, kdf);
    cJSON_AddStringToObject(head, "securityStamp", stamp);
    if (err == ESP_OK && !head_set_wrap(head, client_hash, sk)) {
        err = ESP_FAIL;
    }
    if (err == ESP_OK) {
        err = tw_store_write(TW_HEAD_PATH, head);
    }
    cJSON_Delete(head);
    if (err == ESP_OK) {
        memcpy(s_sk, sk, sizeof(sk));
        s_have_sk = true;
        setup_clear();  // from now on only the account opens the status page
    }
    memset(sk, 0, sizeof(sk));
    fails_set(0);
    tw_clock_persist();
    s_reg_token[0] = '\0';
    tw_auth_init();
    ESP_LOGI(TAG, "user created");
    return err;
}

// ---------- changing the KDF (POST /s/kdf) ----------
// The vault's user key stays the same: only its wrapping by the master key, the KDF settings and the
// wrapping of the storage key change, all in the header, in one record write (old or new state after a
// power cut, never a mix). Everyone is logged out afterwards. The caller has checked the old password
// and the button (which unlocked the store).
esp_err_t tw_auth_set_master(const char *client_hash, const char *key, const cJSON *kdf)
{
    if (!s_have_sk) {
        return ESP_ERR_INVALID_STATE;
    }
    cJSON *head = tw_head_load();
    if (!head) {
        return ESP_ERR_NOT_FOUND;
    }
    char stamp[37];
    tw_uuid(stamp);
    cJSON_DeleteItemFromObjectCaseSensitive(head, "key");
    cJSON_DeleteItemFromObjectCaseSensitive(head, "securityStamp");
    cJSON_AddStringToObject(head, "key", key);
    cJSON_AddStringToObject(head, "securityStamp", stamp);
    copy_kdf(head, kdf);
    esp_err_t err = head_set_wrap(head, client_hash, s_sk) ? tw_store_write(TW_HEAD_PATH, head) : ESP_FAIL;
    cJSON_Delete(head);
    if (err == ESP_OK) {
        tw_auth_init();  // new token key: every client logs in again and picks up the new KDF
        ESP_LOGI(TAG, "KDF changed");
    }
    return err;
}

// ---------- login ----------
// The username is not checked: it is not stored. A wrong one gives a different masterPasswordHash,
// which does not open the wrap, so it counts as a failure like a wrong password.

tw_login_result_t tw_auth_check_password(const char *client_hash)
{
    cJSON *head = tw_head_load();
    if (!head) {
        return TW_LOGIN_BAD;
    }
    if (!cJSON_IsString(cJSON_GetObjectItemCaseSensitive(head, "wrap"))) {
        // A vault from before 0.3 (docs/MANUAL.md): never let it count toward the wipe
        cJSON_Delete(head);
        return TW_LOGIN_OLD_FORMAT;
    }
    // Button first, so an unattended device cannot be brute-forced and a missed press is not a failure
    if (!tw_button_wait(TW_BUTTON_WAIT_MS)) {
        cJSON_Delete(head);
        return TW_LOGIN_NO_BUTTON;
    }

    uint8_t fails = fails_get();
    if (fails >= TW_MAX_FAILS) {
        cJSON_Delete(head);
        tw_auth_factory_reset();
        return TW_LOGIN_WIPED;
    }
    fails_set(fails + 1);  // before comparing (SPEC 6)

    uint8_t sk[32];
    bool ok = head_unwrap(head, client_hash, sk);
    cJSON_Delete(head);

    if (ok) {
        fails_set(0);
        if (tw_store_unlock(sk) == ESP_OK) {
            memcpy(s_sk, sk, sizeof(sk));
            s_have_sk = true;
        } else {
            ESP_LOGE(TAG, "unlock failed");
        }
        memset(sk, 0, sizeof(sk));
        return TW_LOGIN_OK;
    }
    if (fails + 1 >= TW_MAX_FAILS) {
        tw_auth_factory_reset();  // tokens of the wiped user must not work for a new one
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

char *tw_auth_issue_access(const cJSON *user, const char *email, const char *device_id, const char *device_type)
{
    char em[256];
    tw_email_norm(email, em, sizeof(em));
    cJSON *c = cJSON_CreateObject();
    cJSON_AddNumberToObject(c, "nbf", (double)(tw_now_ms() / 1000 - 60));
    // 2038-01-19, just under 2^31: the Android app reads exp as a 32-bit Int and crashes on more (SPEC 4)
    cJSON_AddNumberToObject(c, "exp", 2147483000.0);
    cJSON_AddStringToObject(c, "iss", TW_ORIGIN "|login");
    cJSON_AddStringToObject(c, "sub", get_str(user, "id", NULL) ?: "");
    cJSON_AddBoolToObject(c, "premium", true);
    cJSON_AddStringToObject(c, "name", get_str(user, "name", NULL) ?: em);
    cJSON_AddStringToObject(c, "email", em);
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

char *tw_auth_issue_refresh(const char *email)
{
    uint8_t raw[32];
    tw_random(raw, sizeof(raw));
    char *tok = &s_refresh[s_refresh_next][0];
    tw_b64url_encode(raw, sizeof(raw), tok, TOKEN_LEN);
    tw_email_norm(email, s_refresh_email[s_refresh_next], sizeof(s_refresh_email[0]));
    s_refresh_next = (s_refresh_next + 1) % REFRESH_SLOTS;
    return strdup(tok);
}

bool tw_auth_use_refresh(const char *token, char *email_out, size_t email_len)
{
    if (!token || !token[0]) {
        return false;
    }
    for (int i = 0; i < REFRESH_SLOTS; i++) {
        if (s_refresh[i][0] && strcmp(s_refresh[i], token) == 0) {
            snprintf(email_out, email_len, "%s", s_refresh_email[i]);
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

// The username of the session: the "email" claim of a token this boot signed
bool tw_auth_bearer_email(httpd_req_t *req, char *out, size_t out_len)
{
    out[0] = '\0';
    if (!tw_auth_check_bearer(req)) {
        return false;
    }
    char hdr[2048];
    if (httpd_req_get_hdr_value_str(req, "Authorization", hdr, sizeof(hdr)) != ESP_OK) {
        return false;
    }
    char *p1 = strchr(hdr + 7, '.');
    char *p2 = p1 ? strchr(p1 + 1, '.') : NULL;
    if (!p2) {
        return false;
    }
    *p2 = '\0';
    uint8_t json[1536];
    int n = tw_b64_decode(p1 + 1, json, sizeof(json) - 1);
    if (n <= 0) {
        return false;
    }
    cJSON *c = cJSON_ParseWithLength((const char *)json, n);
    const char *em = get_str(c, "email", NULL);
    snprintf(out, out_len, "%s", em ? em : "");
    cJSON_Delete(c);
    return em != NULL;
}

// Wipe from the status page (after the button press): same effect as too many failed logins
esp_err_t tw_auth_factory_reset(void)
{
    forget_sk();
    esp_err_t err = tw_store_wipe();
    fails_set(0);
    tw_auth_init();  // tokens of the wiped user must not work for a new one
    return err;
}
