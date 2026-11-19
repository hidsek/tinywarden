// tinywarden: shared declarations. See docs/SPEC.md.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sdkconfig.h"
#include "cJSON.h"
#include "esp_err.h"
#include "esp_http_server.h"

#define TW_IP_STR        "192.168.237.1"
#define TW_ORIGIN        "https://" TW_IP_STR
#define TW_MOUNT         "/tw"
#define TW_USER_PATH     TW_MOUNT "/user.json"
#define TW_CIPHER_DIR    TW_MOUNT "/c"
#define TW_FOLDER_DIR    TW_MOUNT "/f"
#define TW_MAX_FAILS     10
#define TW_BUTTON_GPIO   0
#define TW_LED_GPIO      48  // plain LED on the development SuperMini, WS2812 on some boards (Kconfig)
#define TW_BUTTON_WAIT_MS 30000
#define TW_PW_ITER       10000
#define TW_MAX_BODY      (64 * 1024)
#define TW_IMPORT_HEADROOM (256 * 1024)  // PSRAM kept free during an import (TLS buffers, JSON)
#define TW_AVG_ITEM_BYTES 2200            // typical stored login record (ciphertext + server fields), for estimates only

// util.c
void tw_random(void *buf, size_t len);
void tw_uuid(char out[37]);
bool tw_is_uuid(const char *s);
size_t tw_b64_encode(const uint8_t *in, size_t len, char *out, size_t out_len);          // standard
size_t tw_b64url_encode(const uint8_t *in, size_t len, char *out, size_t out_len);       // no padding
int tw_b64_decode(const char *in, uint8_t *out, size_t out_len);                          // either alphabet, -1 on error
void tw_url_decode(char *s);
bool tw_form_get(const char *body, const char *key, char *out, size_t out_len);           // x-www-form-urlencoded
bool tw_ct_equal(const uint8_t *a, const uint8_t *b, size_t len);

// clock.c (SPEC 4)
void tw_clock_init(void);
int64_t tw_now_ms(void);
void tw_now_iso(char out[32]);
void tw_clock_persist(void);

// store.c (SPEC 5): log-structured store; paths are names for (kind, id) keys
#define TW_TEST_DIR TW_MOUNT "/t"  // development self-test records
esp_err_t tw_store_init(void);
cJSON *tw_store_read(const char *path);
esp_err_t tw_store_write(const char *path, const cJSON *obj);
esp_err_t tw_store_write_new(const char *path, const cJSON *obj);  // same as write; kept for callers
esp_err_t tw_store_remove(const char *path);
bool tw_store_exists(const char *path);
typedef esp_err_t (*tw_rec_cb)(const char *path, const char *data, size_t len, void *ctx);
esp_err_t tw_store_foreach(const char *dir, tw_rec_cb cb, void *ctx);  // TW_CIPHER_DIR, TW_FOLDER_DIR, TW_TEST_DIR
esp_err_t tw_store_delete_all(const char *dir);
esp_err_t tw_store_wipe(void);
int tw_store_count(const char *dir);
uint32_t tw_store_record_bytes(size_t payload_len);  // flash bytes one record of this size takes
bool tw_store_fits(uint32_t record_bytes);           // would this many more record bytes fit
typedef struct {
    uint32_t capacity, live_bytes, stale_bytes, free_bytes;
    uint16_t segs_total, segs_free;
    uint32_t ciphers, folders, gc_runs, torn_records, mount_ms;
} tw_store_stats_t;
void tw_store_stats(tw_store_stats_t *out);
typedef struct {
    uint32_t time, seq;
    const char *kind, *op;
    char id[37];
} tw_store_change_t;
int tw_store_recent(tw_store_change_t *out, int max);  // newest first

esp_err_t tw_auth_factory_reset(void);  // wipe storage, reset fails and tokens

// led.c
void tw_led_init(void);
void tw_led_set(bool on);

// button.c
void tw_button_init(void);
bool tw_button_wait(int timeout_ms);

// usb_net.c
esp_err_t tw_usb_net_start(void);

// tls.c (SPEC 3)
// cert/key: the server certificate and its key (for HTTPS). ca: the CA certificate people trust.
esp_err_t tw_tls_load_or_create(const char **cert_pem, size_t *cert_len, const char **key_pem, size_t *key_len,
                                const char **ca_pem);

// auth.c (SPEC 6)
void tw_auth_init(void);
cJSON *tw_user_load(void);
bool tw_user_exists(void);
esp_err_t tw_auth_register(cJSON *body);                       // ESP_ERR_INVALID_STATE if a user exists
typedef enum { TW_LOGIN_OK, TW_LOGIN_BAD, TW_LOGIN_NO_BUTTON, TW_LOGIN_WIPED } tw_login_result_t;
tw_login_result_t tw_auth_check_password(const char *email, const char *client_hash);
esp_err_t tw_auth_set_master(const char *client_hash, const char *key, const cJSON *kdf);  // KDF change
char *tw_auth_issue_access(const cJSON *user, const char *device_id, const char *device_type);
char *tw_auth_issue_refresh(void);
bool tw_auth_use_refresh(const char *token);
bool tw_auth_check_bearer(httpd_req_t *req);
const char *tw_auth_pending_register_token(const char *email, const char *name);
bool tw_auth_check_register_token(const char *token, char *name_out, size_t name_len);

// api.c
esp_err_t tw_api_start(void);
esp_err_t tw_web_file(httpd_req_t *req);
// Pages run only the board's own scripts (firmware/web/); their <style> is inline
#define TW_PAGE_CSP "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; " \
                    "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"  // GET /web/* : the pages' scripts (web.c)
