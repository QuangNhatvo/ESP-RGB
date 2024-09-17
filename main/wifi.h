#ifndef _WIFI_H
#define _WIFI_H

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"

#include "lwip/err.h"
#include "lwip/sys.h"

#define EXAMPLE_ESP_WIFI_SSID "Hoang Le"
#define EXAMPLE_ESP_WIFI_PASS "07032017"
#define EXAMPLE_ESP_MAXIMUM_RETRY 5
#define WIFI_AUTH_WPA2_PSK 1

void wifi_event_handler(void *arg, esp_event_base_t event_base,
                         int32_t event_id, void *event_data);

void wifi_init_sta(void);

#endif 