// BOOT button (GPIO0, active low) as the "user is here" check.
#include "driver/gpio.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "tw.h"

static const char *TAG = "button";

void tw_button_init(void)
{
    const gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << TW_BUTTON_GPIO,
        .mode = GPIO_MODE_INPUT,
        .pull_up_en = GPIO_PULLUP_ENABLE,
    };
    gpio_config(&cfg);
}

// Blocks the calling HTTP handler. Other requests wait meanwhile, which is fine for one user.
bool tw_button_wait(int timeout_ms)
{
#if CONFIG_TW_DEV_SKIP_BUTTON
    ESP_LOGW(TAG, "development build: button wait skipped");
    return true;
#endif
    ESP_LOGI(TAG, "waiting for button (%d ms)", timeout_ms);
    bool pressed = false;
    for (int t = 0; t < timeout_ms; t += 20) {
        tw_led_set((t / 250) % 2 == 0);  // blink while waiting
        if (gpio_get_level(TW_BUTTON_GPIO) == 0) {
            vTaskDelay(pdMS_TO_TICKS(50));  // debounce
            if (gpio_get_level(TW_BUTTON_GPIO) == 0) {
                pressed = true;
                break;
            }
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    tw_led_set(false);
    return pressed;
}
