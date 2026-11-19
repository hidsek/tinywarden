// Static files for the board's pages (firmware/web/), embedded at build time (CMakeLists EMBED_FILES).
// They are scripts that run in the browser; nothing here sees a password or plaintext.
#include <string.h>
#include "tw.h"

#define WEB_SYM(sym)                                                    \
    extern const uint8_t _binary_##sym##_start[] asm("_binary_" #sym "_start"); \
    extern const uint8_t _binary_##sym##_end[] asm("_binary_" #sym "_end");

WEB_SYM(status_js)
WEB_SYM(merge_html)
WEB_SYM(merge_ui_js)
WEB_SYM(merge_js)
WEB_SYM(twcrypto_js)
WEB_SYM(argon2_js)
WEB_SYM(_u64_js)
WEB_SYM(blake2_js)
WEB_SYM(_blake_js)
WEB_SYM(_md_js)
WEB_SYM(utils_js)
WEB_SYM(LICENSE)

typedef struct {
    const char *path;
    const uint8_t *start, *end;
    const char *type;
    bool page;  // an HTML page: no caching, and the same Content-Security-Policy as the status page
} web_file_t;

#define JS "text/javascript; charset=utf-8"
#define F(p, sym, t) {p, _binary_##sym##_start, _binary_##sym##_end, t, false}

static const web_file_t FILES[] = {
    {"/merge", _binary_merge_html_start, _binary_merge_html_end, "text/html; charset=utf-8", true},
    F("/web/status.js", status_js, JS),
    F("/web/merge-ui.js", merge_ui_js, JS),
    F("/web/merge.js", merge_js, JS),
    F("/web/twcrypto.js", twcrypto_js, JS),
    F("/web/vendor/noble-hashes/argon2.js", argon2_js, JS),
    F("/web/vendor/noble-hashes/_u64.js", _u64_js, JS),
    F("/web/vendor/noble-hashes/blake2.js", blake2_js, JS),
    F("/web/vendor/noble-hashes/_blake.js", _blake_js, JS),
    F("/web/vendor/noble-hashes/_md.js", _md_js, JS),
    F("/web/vendor/noble-hashes/utils.js", utils_js, JS),
    F("/web/vendor/noble-hashes/LICENSE", LICENSE, "text/plain; charset=utf-8"),
};

esp_err_t tw_web_file(httpd_req_t *req)
{
    size_t n = strcspn(req->uri, "?#");
    for (size_t i = 0; i < sizeof(FILES) / sizeof(FILES[0]); i++) {
        const web_file_t *f = &FILES[i];
        if (strlen(f->path) == n && memcmp(f->path, req->uri, n) == 0) {
            httpd_resp_set_type(req, f->type);
            if (f->page) {
                httpd_resp_set_hdr(req, "Cache-Control", "no-store");
                httpd_resp_set_hdr(req, "Content-Security-Policy", TW_PAGE_CSP);
            } else {
                // Files change only with the firmware; always revalidate so an update takes effect
                httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
            }
            httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
            return httpd_resp_send(req, (const char *)f->start, f->end - f->start);
        }
    }
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not found");
    return ESP_OK;
}
