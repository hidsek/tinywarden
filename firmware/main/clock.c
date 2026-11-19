// The device has no real-time clock. Time = max(build time, last saved time) + uptime (SPEC 4).
#include <stdio.h>
#include <time.h>

#include "esp_timer.h"
#include "nvs.h"
#include "tw.h"

static int64_t s_base_ms;

void tw_clock_init(void)
{
    int64_t saved = 0;
    nvs_handle_t h;
    if (nvs_open("tw", NVS_READONLY, &h) == ESP_OK) {
        nvs_get_i64(h, "clock", &saved);
        nvs_close(h);
    }
    int64_t build = (int64_t)TW_BUILD_EPOCH * 1000;
    s_base_ms = saved > build ? saved : build;
}

int64_t tw_now_ms(void)
{
    return s_base_ms + esp_timer_get_time() / 1000;
}

void tw_now_iso(char out[32])
{
    int64_t ms = tw_now_ms();
    time_t t = (time_t)(ms / 1000);
    struct tm tm;
    gmtime_r(&t, &tm);
    size_t n = strftime(out, 32, "%Y-%m-%dT%H:%M:%S", &tm);
    snprintf(out + n, 32 - n, ".%03dZ", (int)(ms % 1000));
}

// Called after every change so time never goes backwards across reboots
void tw_clock_persist(void)
{
    nvs_handle_t h;
    if (nvs_open("tw", NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_i64(h, "clock", tw_now_ms());
        nvs_commit(h);
        nvs_close(h);
    }
}
