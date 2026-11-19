// Small helpers: random, uuid, base64, form parsing.
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "esp_random.h"
#include "mbedtls/base64.h"
#include "tw.h"

void tw_random(void *buf, size_t len)
{
    esp_fill_random(buf, len);
}

void tw_uuid(char out[37])
{
    uint8_t b[16];
    tw_random(b, sizeof(b));
    b[6] = (b[6] & 0x0f) | 0x40;  // version 4
    b[8] = (b[8] & 0x3f) | 0x80;  // variant
    snprintf(out, 37, "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
             b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
}

// Only uuids are used as file names, so this also keeps paths safe
bool tw_is_uuid(const char *s)
{
    if (strlen(s) != 36) {
        return false;
    }
    for (int i = 0; i < 36; i++) {
        if (i == 8 || i == 13 || i == 18 || i == 23) {
            if (s[i] != '-') {
                return false;
            }
        } else if (!isxdigit((unsigned char)s[i])) {
            return false;
        }
    }
    return true;
}

size_t tw_b64_encode(const uint8_t *in, size_t len, char *out, size_t out_len)
{
    size_t olen = 0;
    if (mbedtls_base64_encode((unsigned char *)out, out_len, &olen, in, len) != 0) {
        return 0;
    }
    return olen;
}

size_t tw_b64url_encode(const uint8_t *in, size_t len, char *out, size_t out_len)
{
    size_t n = tw_b64_encode(in, len, out, out_len);
    while (n > 0 && out[n - 1] == '=') {
        out[--n] = '\0';
    }
    for (size_t i = 0; i < n; i++) {
        if (out[i] == '+') out[i] = '-';
        else if (out[i] == '/') out[i] = '_';
    }
    return n;
}

int tw_b64_decode(const char *in, uint8_t *out, size_t out_len)
{
    size_t n = strlen(in);
    char *tmp = malloc(n + 4);
    if (!tmp) {
        return -1;
    }
    for (size_t i = 0; i < n; i++) {
        tmp[i] = in[i] == '-' ? '+' : in[i] == '_' ? '/' : in[i];
    }
    while (n % 4) {
        tmp[n++] = '=';
    }
    tmp[n] = '\0';
    size_t olen = 0;
    int rc = mbedtls_base64_decode(out, out_len, &olen, (unsigned char *)tmp, n);
    free(tmp);
    return rc == 0 ? (int)olen : -1;
}

void tw_url_decode(char *s)
{
    char *o = s;
    for (; *s; s++, o++) {
        if (*s == '+') {
            *o = ' ';
        } else if (*s == '%' && isxdigit((unsigned char)s[1]) && isxdigit((unsigned char)s[2])) {
            char hex[3] = {s[1], s[2], 0};
            *o = (char)strtol(hex, NULL, 16);
            s += 2;
        } else {
            *o = *s;
        }
    }
    *o = '\0';
}

// Both names and values are percent-decoded before use: the iOS app encodes every character
// that is not a letter or digit, names included ("grant%5Ftype=password").
bool tw_form_get(const char *body, const char *key, char *out, size_t out_len)
{
    if (!body || !key || !out || out_len == 0) {
        return false;
    }
    out[0] = '\0';
    const char *p = body;
    while (*p) {
        const char *amp = strchr(p, '&');
        const char *end = amp ? amp : p + strlen(p);
        const char *eq = memchr(p, '=', (size_t)(end - p));
        const char *name_end = eq ? eq : end;
        char name[64];
        size_t nl = (size_t)(name_end - p);
        if (nl < sizeof(name)) {
            memcpy(name, p, nl);
            name[nl] = '\0';
            tw_url_decode(name);
            if (strcasecmp(name, key) == 0) {
                const char *v = eq ? eq + 1 : end;
                size_t vl = (size_t)(end - v);
                if (vl >= out_len) {
                    return false;  // too long even before decoding
                }
                memcpy(out, v, vl);
                out[vl] = '\0';
                tw_url_decode(out);
                return true;
            }
        }
        if (!amp) {
            break;
        }
        p = amp + 1;
    }
    return false;
}

bool tw_ct_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t d = 0;
    for (size_t i = 0; i < len; i++) {
        d |= a[i] ^ b[i];
    }
    return d == 0;
}
