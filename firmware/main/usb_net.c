// USB CDC-NCM <-> lwIP glue. The device is 192.168.237.1 and hands out addresses by DHCP (SPEC 2).
// Unverified on hardware (SPEC 8.2): written against esp_tinyusb 1.x tinyusb_net_* and esp_netif's
// custom driver interface.
#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "lwip/ip4_addr.h"
#include "tinyusb.h"
#include "tinyusb_net.h"
#include "tw.h"

static const char *TAG = "usb_net";
static esp_netif_t *s_netif;

typedef struct {
    esp_netif_driver_base_t base;
} usb_glue_t;

static usb_glue_t s_glue;

// lwIP -> USB
static esp_err_t netif_transmit(void *h, void *buffer, size_t len)
{
    return tinyusb_net_send_sync(buffer, len, NULL, pdMS_TO_TICKS(100));
}

static void netif_free_rx(void *h, void *buffer)
{
    free(buffer);
}

// USB -> lwIP. TinyUSB reuses its buffer after this returns, so copy it.
static esp_err_t usb_recv(void *buffer, uint16_t len, void *ctx)
{
    if (!s_netif) {
        return ESP_OK;
    }
    void *copy = malloc(len);
    if (!copy) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(copy, buffer, len);
    return esp_netif_receive(s_netif, copy, len, NULL);
}

static esp_err_t glue_post_attach(esp_netif_t *netif, void *args)
{
    usb_glue_t *glue = args;
    glue->base.netif = netif;
    const esp_netif_driver_ifconfig_t ifcfg = {
        .handle = glue,
        .transmit = netif_transmit,
        .driver_free_rx_buffer = netif_free_rx,
    };
    return esp_netif_set_driver_config(netif, &ifcfg);
}

#if CONFIG_TINYUSB_NET_MODE_ECM_RNDIS
// CDC-ECM instead of NCM (test build for Android, whose kernels more often carry cdc_ether than
// cdc_ncm). esp_tinyusb's default descriptors only cover NCM, so ECM brings its own.
enum { ITF_ECM = 0, ITF_ECM_DATA, ITF_TOTAL };
enum { STR_LANG = 0, STR_MANUFACTURER, STR_PRODUCT, STR_SERIAL, STR_NET, STR_MAC, STR_COUNT };
static const uint8_t s_ecm_cfg[] = {
    TUD_CONFIG_DESCRIPTOR(1, ITF_TOTAL, 0, TUD_CONFIG_DESC_LEN + TUD_CDC_ECM_DESC_LEN, 0, 100),
    TUD_CDC_ECM_DESCRIPTOR(ITF_ECM, STR_NET, STR_MAC, 0x81, 64, 0x02, 0x82, 64, CFG_TUD_NET_MTU),
};
static char s_ecm_mac[13];
static const char *s_ecm_str[STR_COUNT] = {
    (const char[]){0x09, 0x04},
    CONFIG_TINYUSB_DESC_MANUFACTURER_STRING,
    CONFIG_TINYUSB_DESC_PRODUCT_STRING,
    CONFIG_TINYUSB_DESC_SERIAL_STRING,
    "USB Ethernet",
    s_ecm_mac,  // host-side MAC as 12 hex digits, filled in before the driver is installed
};
#endif

esp_err_t tw_usb_net_start(void)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_ETH);
#if CONFIG_TINYUSB_NET_MODE_ECM_RNDIS
    snprintf(s_ecm_mac, sizeof(s_ecm_mac), "%02X%02X%02X%02X%02X%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    const tinyusb_config_t tusb_cfg = {
        .string_descriptor = s_ecm_str,
        .string_descriptor_count = STR_COUNT,
        .configuration_descriptor = s_ecm_cfg,
    };
    ESP_LOGW(TAG, "USB in CDC-ECM mode");
#else
    const tinyusb_config_t tusb_cfg = {0};
#endif
    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));

    tinyusb_net_config_t net_cfg = {
        .on_recv_callback = usb_recv,
    };
    memcpy(net_cfg.mac_addr, mac, sizeof(mac));
    ESP_ERROR_CHECK(tinyusb_net_init(TINYUSB_USBDEV_0, &net_cfg));

    // Like the Wi-Fi AP default: static address plus a DHCP server
    static esp_netif_ip_info_t ip;  // static: esp_netif keeps the pointer
    IP4_ADDR(&ip.ip, 192, 168, 237, 1);
    IP4_ADDR(&ip.gw, 192, 168, 237, 1);
    IP4_ADDR(&ip.netmask, 255, 255, 255, 0);

    esp_netif_inherent_config_t base = ESP_NETIF_INHERENT_DEFAULT_WIFI_AP();
    base.if_key = "USB_NCM";
    base.if_desc = "usb";
    base.route_prio = 10;
    base.ip_info = &ip;
    // MAC on our side of the link must differ from the one given to the host
    mac[5] ^= 0x01;
    memcpy(base.mac, mac, sizeof(mac));

    const esp_netif_config_t cfg = {
        .base = &base,
        .driver = NULL,
        .stack = ESP_NETIF_NETSTACK_DEFAULT_ETH,
    };
    s_netif = esp_netif_new(&cfg);
    if (!s_netif) {
        return ESP_FAIL;
    }
    s_glue.base.post_attach = glue_post_attach;
    ESP_ERROR_CHECK(esp_netif_attach(s_netif, &s_glue));

    // Offer neither a router nor DNS. Otherwise the Mac sends all its traffic
    // here (default route and DNS), and the internet goes down while the board
    // is plugged in. Must be set before the DHCP server starts.
    uint8_t no_offer = 0;  // dhcps_offer_t (u8_t)
    ESP_ERROR_CHECK(esp_netif_dhcps_option(s_netif, ESP_NETIF_OP_SET,
                                           ESP_NETIF_ROUTER_SOLICITATION_ADDRESS,
                                           &no_offer, sizeof(no_offer)));
    ESP_ERROR_CHECK(esp_netif_dhcps_option(s_netif, ESP_NETIF_OP_SET,
                                           ESP_NETIF_DOMAIN_NAME_SERVER,
                                           &no_offer, sizeof(no_offer)));

    esp_netif_action_start(s_netif, NULL, 0, NULL);
    esp_netif_action_connected(s_netif, NULL, 0, NULL);
    ESP_LOGI(TAG, "USB network up at " TW_IP_STR);
    return ESP_OK;
}
