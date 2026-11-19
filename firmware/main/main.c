// tinywarden: a Bitwarden-compatible server that lives on an ESP32-S3 plugged in by USB.
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "tw.h"

static const char *TAG = "tinywarden";

void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    tw_clock_init();
    tw_auth_init();
    tw_led_init();
    tw_button_init();
    ESP_ERROR_CHECK(tw_store_init());

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(tw_usb_net_start());
    ESP_ERROR_CHECK(tw_api_start());

    ESP_LOGI(TAG, "ready, user %s", tw_user_exists() ? "present" : "not created yet");
}
