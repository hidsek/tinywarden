// Certificates for 192.168.237.1, made on first boot and kept in NVS (SPEC 3).
//
// Two certificates:
//   CA      self-signed, CA:TRUE, nameConstraints limiting it to 192.168.237.1. This is what the
//           Mac and phones trust (iOS lists only CA certificates under Certificate Trust Settings).
//           Its private key is thrown away right after signing the server certificate, so nothing
//           on the board can vouch for any other host.
//   server  CA:FALSE, serverAuth, SAN IP:192.168.237.1, signed by the CA. Served on HTTPS.
// The board only ever parses the server certificate: mbedTLS refuses certificates with critical
// extensions it does not know, such as nameConstraints.
#include <string.h>
#include <time.h>

#include "esp_log.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecp.h"
#include "mbedtls/entropy.h"
#include "mbedtls/oid.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_crt.h"
#include "nvs.h"
#include "tw.h"

static const char *TAG = "tls";
#define PEM_MAX 2048
// Bump when the certificates change; older ones in NVS are replaced on boot.
// 1: one self-signed CA:FALSE certificate (iOS cannot trust it)
// 4: CA (key discarded) + server certificate with serverAuth
#define CERT_VERSION 5  // 5: names without the project name

#define SERVER_NAME "CN=" TW_IP_STR
#define CA_NAME "CN=Local CA " TW_IP_STR

static char s_cert[PEM_MAX];
static char s_key[PEM_MAX];
static char s_ca[PEM_MAX];

static bool load(void)
{
    nvs_handle_t h;
    if (nvs_open("tw", NVS_READONLY, &h) != ESP_OK) {
        return false;
    }
    uint8_t ver = 0;
    nvs_get_u8(h, "tlsver", &ver);
    size_t cl = sizeof(s_cert), kl = sizeof(s_key), al = sizeof(s_ca);
    bool ok = ver == CERT_VERSION && nvs_get_str(h, "tlscrt", s_cert, &cl) == ESP_OK &&
              nvs_get_str(h, "tlskey", s_key, &kl) == ESP_OK && nvs_get_str(h, "tlsca", s_ca, &al) == ESP_OK;
    nvs_close(h);
    return ok;
}

static void validity(char from[15], char to[15])
{
    // No clock: start a day before the build, stay under the 825-day Apple limit
    time_t start = (time_t)TW_BUILD_EPOCH - 86400;
    time_t end = start + 820L * 86400;
    struct tm tm;
    gmtime_r(&start, &tm);
    strftime(from, 15, "%Y%m%d%H%M%S", &tm);
    gmtime_r(&end, &tm);
    strftime(to, 15, "%Y%m%d%H%M%S", &tm);
}

static int gen_key(mbedtls_pk_context *key, mbedtls_ctr_drbg_context *drbg)
{
    int rc = mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    return rc ? rc : mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(*key), mbedtls_ctr_drbg_random, drbg);
}

static int common(mbedtls_x509write_cert *crt, mbedtls_pk_context *subject, mbedtls_pk_context *issuer,
                  const char *subject_name)
{
    mbedtls_x509write_crt_set_version(crt, MBEDTLS_X509_CRT_VERSION_3);
    mbedtls_x509write_crt_set_md_alg(crt, MBEDTLS_MD_SHA256);
    mbedtls_x509write_crt_set_subject_key(crt, subject);
    mbedtls_x509write_crt_set_issuer_key(crt, issuer);
    int rc;
    if ((rc = mbedtls_x509write_crt_set_subject_name(crt, subject_name))) return rc;
    if ((rc = mbedtls_x509write_crt_set_issuer_name(crt, CA_NAME))) return rc;
    unsigned char serial[16];
    tw_random(serial, sizeof(serial));
    serial[0] &= 0x7f;
    if ((rc = mbedtls_x509write_crt_set_serial_raw(crt, serial, sizeof(serial)))) return rc;
    char from[15], to[15];
    validity(from, to);
    if ((rc = mbedtls_x509write_crt_set_validity(crt, from, to))) return rc;
    if ((rc = mbedtls_x509write_crt_set_subject_key_identifier(crt))) return rc;
    return mbedtls_x509write_crt_set_authority_key_identifier(crt);
}

static esp_err_t create(void)
{
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_pk_context ca_key, key;
    mbedtls_x509write_cert ca, crt;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_pk_init(&ca_key);
    mbedtls_pk_init(&key);
    mbedtls_x509write_crt_init(&ca);
    mbedtls_x509write_crt_init(&crt);
    int rc = -1;

    if (mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)"tw-tls", 6) != 0) goto out;
    if (gen_key(&ca_key, &drbg) != 0 || gen_key(&key, &drbg) != 0) goto out;

    // CA
    if (common(&ca, &ca_key, &ca_key, CA_NAME) != 0) goto out;
    if (mbedtls_x509write_crt_set_basic_constraints(&ca, 1, 0) != 0) goto out;
    if (mbedtls_x509write_crt_set_key_usage(&ca, MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN) != 0) goto out;
    // nameConstraints (critical), permitted subtrees only: iPAddress 192.168.237.1/32, and DNS and
    // email under "invalid" (no real name). Checked with openssl: other IPs and DNS names give
    // "permitted subtree violation". Belt and braces: the CA key is discarded anyway.
    static const unsigned char nc[] = {
        0x30, 0x24, 0xa0, 0x22,
        0x30, 0x0a, 0x87, 0x08, 192, 168, 237, 1, 0xff, 0xff, 0xff, 0xff,
        0x30, 0x09, 0x82, 0x07, 'i', 'n', 'v', 'a', 'l', 'i', 'd',
        0x30, 0x09, 0x81, 0x07, 'i', 'n', 'v', 'a', 'l', 'i', 'd',
    };
    if (mbedtls_x509write_crt_set_extension(&ca, MBEDTLS_OID_NAME_CONSTRAINTS,
                                            MBEDTLS_OID_SIZE(MBEDTLS_OID_NAME_CONSTRAINTS), 1, nc, sizeof(nc)) != 0)
        goto out;
    if (mbedtls_x509write_crt_pem(&ca, (unsigned char *)s_ca, sizeof(s_ca), mbedtls_ctr_drbg_random, &drbg) != 0) goto out;

    // Server certificate
    if (common(&crt, &key, &ca_key, SERVER_NAME) != 0) goto out;
    if (mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1) != 0) goto out;
    if (mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE) != 0) goto out;
    mbedtls_asn1_sequence eku = {0};  // serverAuth: iOS requires it on TLS server certificates
    eku.buf.tag = MBEDTLS_ASN1_OID;
    eku.buf.p = (unsigned char *)MBEDTLS_OID_SERVER_AUTH;
    eku.buf.len = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH);
    if (mbedtls_x509write_crt_set_ext_key_usage(&crt, &eku) != 0) goto out;
    static const unsigned char ip[4] = {192, 168, 237, 1};  // SAN (SPEC 8.3: needs mbedTLS 3.5+)
    mbedtls_x509_san_list san = {0};
    san.node.type = MBEDTLS_X509_SAN_IP_ADDRESS;
    san.node.san.unstructured_name.p = (unsigned char *)ip;
    san.node.san.unstructured_name.len = sizeof(ip);
    if (mbedtls_x509write_crt_set_subject_alternative_name(&crt, &san) != 0) goto out;
    if (mbedtls_x509write_crt_pem(&crt, (unsigned char *)s_cert, sizeof(s_cert), mbedtls_ctr_drbg_random, &drbg) != 0)
        goto out;
    if (mbedtls_pk_write_key_pem(&key, (unsigned char *)s_key, sizeof(s_key)) != 0) goto out;

    nvs_handle_t h;
    if (nvs_open("tw", NVS_READWRITE, &h) != ESP_OK) goto out;
    nvs_set_str(h, "tlscrt", s_cert);
    nvs_set_str(h, "tlskey", s_key);
    nvs_set_str(h, "tlsca", s_ca);
    nvs_set_u8(h, "tlsver", CERT_VERSION);
    nvs_commit(h);
    nvs_close(h);
    rc = 0;

out:
    mbedtls_x509write_crt_free(&ca);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&ca_key);  // the CA key never leaves RAM and is gone from here on
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
    return rc == 0 ? ESP_OK : ESP_FAIL;
}

esp_err_t tw_tls_load_or_create(const char **cert_pem, size_t *cert_len, const char **key_pem, size_t *key_len,
                                const char **ca_pem)
{
    if (!load()) {
        ESP_LOGI(TAG, "creating certificates");
        if (create() != ESP_OK) {
            ESP_LOGE(TAG, "certificate creation failed");
            return ESP_FAIL;
        }
    }
    *cert_pem = s_cert;
    *cert_len = strlen(s_cert) + 1;  // esp_https_server wants the NUL counted
    *key_pem = s_key;
    *key_len = strlen(s_key) + 1;
    *ca_pem = s_ca;
    return ESP_OK;
}
