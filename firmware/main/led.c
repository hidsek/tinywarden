// The LED on GPIO48 (TW_LED_GPIO). Kept off, except blinking while something waits for the BOOT button.
// Plain LED (the development SuperMini; it shows red) or WS2812 RGB LED: Kconfig TW_LED_KIND.
// The board's power LED cannot be turned off from firmware.
#include "tw.h"

#if CONFIG_TW_LED_WS2812
#include "esp_log.h"
#include "led_strip.h"

static const char *TAG = "led";

static led_strip_handle_t s_strip;

void tw_led_init(void)
{
    const led_strip_config_t cfg = {
        .strip_gpio_num = TW_LED_GPIO,
        .max_leds = 1,
        .led_model = LED_MODEL_WS2812,
        .color_component_format = LED_STRIP_COLOR_COMPONENT_FMT_GRB,
    };
    const led_strip_rmt_config_t rmt = {
        .resolution_hz = 10 * 1000 * 1000,
    };
    esp_err_t err = led_strip_new_rmt_device(&cfg, &rmt, &s_strip);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "no LED: %s", esp_err_to_name(err));
        s_strip = NULL;
        return;
    }
    led_strip_clear(s_strip);  // the WS2812 can power up showing a random colour
}

void tw_led_set(bool on)
{
    if (!s_strip) return;
    if (on) {
        // All three channels: lights up whatever the LED's colour order is
        led_strip_set_pixel(s_strip, 0, 64, 64, 64);
        led_strip_refresh(s_strip);
    } else {
        led_strip_clear(s_strip);
    }
}

#else
#include "driver/gpio.h"

void tw_led_init(void)
{
    const gpio_config_t cfg = {
        .pin_bit_mask = 1ULL << TW_LED_GPIO,
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&cfg);
    gpio_set_level(TW_LED_GPIO, 0);
}

void tw_led_set(bool on)
{
    gpio_set_level(TW_LED_GPIO, on ? 1 : 0);
}
#endif
