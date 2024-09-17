/*
 * SPDX-FileCopyrightText: 2021-2024 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Unlicense OR CC0-1.0
 */
#include <string.h>
#include <math.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "driver/rmt_tx.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "esp_ota_ops.h"
#include "esp_timer.h"
#include "tls.h"
#include "wifi.h"

#define RMT_LED_STRIP_RESOLUTION_HZ 10000000 // 10MHz resolution, 1 tick = 0.1us (led strip needs a high resolution)
#define RMT_LED_STRIP_GPIO_NUM      8

#define EXAMPLE_LED_NUMBERS         20

#define EXAMPLE_FRAME_DURATION_MS   20
#define EXAMPLE_ANGLE_INC_FRAME     0.02
#define EXAMPLE_ANGLE_INC_LED       0.3
#define FIRMWARE_VERSION "1.8.1"

static const char *TAG = "example";
char *json_buffer;

static uint8_t led_strip_pixels[EXAMPLE_LED_NUMBERS * 3];

static const rmt_symbol_word_t ws2812_zero = {
    .level0 = 1,
    .duration0 = 0.3 * RMT_LED_STRIP_RESOLUTION_HZ / 1000000, // T0H=0.3us
    .level1 = 0,
    .duration1 = 0.9 * RMT_LED_STRIP_RESOLUTION_HZ / 1000000, // T0L=0.9us
};

static const rmt_symbol_word_t ws2812_one = {
    .level0 = 1,
    .duration0 = 0.9 * RMT_LED_STRIP_RESOLUTION_HZ / 1000000, // T1H=0.9us
    .level1 = 0,
    .duration1 = 0.3 * RMT_LED_STRIP_RESOLUTION_HZ / 1000000, // T1L=0.3us
};

//reset defaults to 50uS
static const rmt_symbol_word_t ws2812_reset = {
    .level0 = 1,
    .duration0 = RMT_LED_STRIP_RESOLUTION_HZ / 1000000 * 50 / 2,
    .level1 = 0,
    .duration1 = RMT_LED_STRIP_RESOLUTION_HZ / 1000000 * 50 / 2,
};

static size_t encoder_callback(const void *data, size_t data_size,
                               size_t symbols_written, size_t symbols_free,
                               rmt_symbol_word_t *symbols, bool *done, void *arg)
{
    // We need a minimum of 8 symbol spaces to encode a byte. We only
    // need one to encode a reset, but it's simpler to simply demand that
    // there are 8 symbol spaces free to write anything.
    if (symbols_free < 8) {
        return 0;
    }

    // We can calculate where in the data we are from the symbol pos.
    // Alternatively, we could use some counter referenced by the arg
    // parameter to keep track of this.
    size_t data_pos = symbols_written / 8;
    uint8_t *data_bytes = (uint8_t*)data;
    if (data_pos < data_size) {
        // Encode a byte
        size_t symbol_pos = 0;
        for (int bitmask = 0x80; bitmask != 0; bitmask >>= 1) {
            if (data_bytes[data_pos]&bitmask) {
                symbols[symbol_pos++] = ws2812_one;
            } else {
                symbols[symbol_pos++] = ws2812_zero;
            }
        }
        // We're done; we should have written 8 symbols.
        return symbol_pos;
    } else {
        //All bytes already are encoded.
        //Encode the reset, and we're done.
        symbols[0] = ws2812_reset;
        *done = 1; //Indicate end of the transaction.
        return 1; //we only wrote one symbol
    }
}

void store_nvs_version(){
    nvs_handle my_handle;
    esp_err_t err;

    nvs_flash_init();
    nvs_open("storage",NVS_READWRITE, &my_handle);
    err = nvs_set_str(my_handle, "ver", FIRMWARE_VERSION);
    if(err == ESP_OK){ 
        ESP_LOGI("NVS", "Firmware version stored in NVS: %s \n", FIRMWARE_VERSION);
    }
    nvs_commit(my_handle);
    nvs_close(my_handle);
}

void timer_callback(void *arg) {
    char* json_response = https_get_response();
    if (json_response == NULL) {
        ESP_LOGE(TAG, "None response from API");
        return;
    }
    char* new_version = get_version(json_response);
    if (new_version == NULL) {
        ESP_LOGE(TAG, "Can't not parse version JSON");
        return;
    }
    
    ESP_LOGI(TAG, "current version: %s, version get from API: %s", FIRMWARE_VERSION, new_version);
    if (strcmp(new_version, FIRMWARE_VERSION) > 0) {
        ESP_LOGI(TAG, "OTA updatingg ...");
        const esp_partition_t *factory_partition = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL);
        if (factory_partition != NULL) {
            esp_err_t err = esp_ota_set_boot_partition(factory_partition);
            if (err == ESP_OK) {
                ESP_LOGI(TAG, "restarting ...");
                esp_restart();
            } else {
                ESP_LOGE(TAG, "can not setting partitions reboot.");
            }
        } else {
            ESP_LOGE(TAG, "can not find factory partitions");
        }
    } else {
        ESP_LOGI(TAG, "no new version");
    }
}

void app_main(void)
{
    store_nvs_version(); 

    ESP_LOGI(TAG, "Create RMT TX channel");
    rmt_channel_handle_t led_chan = NULL;
    rmt_tx_channel_config_t tx_chan_config = {
        .clk_src = RMT_CLK_SRC_DEFAULT, // select source clock
        .gpio_num = RMT_LED_STRIP_GPIO_NUM,
        .mem_block_symbols = 64, // increase the block size can make the LED less flickering
        .resolution_hz = RMT_LED_STRIP_RESOLUTION_HZ,
        .trans_queue_depth = 4, // set the number of transactions that can be pending in the background
    };
    ESP_ERROR_CHECK(rmt_new_tx_channel(&tx_chan_config, &led_chan));

    ESP_LOGI(TAG, "Create simple callback-based encoder");
    rmt_encoder_handle_t simple_encoder = NULL;
    const rmt_simple_encoder_config_t simple_encoder_cfg = {
        .callback = encoder_callback
        //Note we don't set min_chunk_size here as the default of 64 is good enough.
    };
    ESP_ERROR_CHECK(rmt_new_simple_encoder(&simple_encoder_cfg, &simple_encoder));

    ESP_LOGI(TAG, "Enable RMT TX channel");
    ESP_ERROR_CHECK(rmt_enable(led_chan));

    ESP_LOGI(TAG, "Start LED rainbow chase");
    rmt_transmit_config_t tx_config = {
        .loop_count = 0, // no transfer loop
    };
    float offset = 0;

    wifi_init_sta();

    /*-------------- Ngắt -------------------*/
    esp_timer_handle_t timer; 
    esp_timer_create_args_t timer_args = {
        .callback = &timer_callback,
        .arg = NULL,
        .name = "version_check_timer"
    };
    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &timer));
    ESP_ERROR_CHECK(esp_timer_start_periodic(timer, (30* 1000000)));    

    /*---------------------------------------*/

    while (1) {
        for (int led = 0; led < EXAMPLE_LED_NUMBERS; led++) {
            // Build RGB pixels. Each color is an offset sine, which gives a
            // hue-like effect.
            float angle = offset + (led * EXAMPLE_ANGLE_INC_LED);
            const float color_off = (M_PI * 2) / 3;
            led_strip_pixels[led * 3 + 0] = sin(angle + color_off * 0) * 127 + 128;
            led_strip_pixels[led * 3 + 1] = sin(angle + color_off * 1) * 127 + 128;
            led_strip_pixels[led * 3 + 2] = sin(angle + color_off * 2) * 117 + 128;;
        }
        // Flush RGB values to LEDs
        ESP_ERROR_CHECK(rmt_transmit(led_chan, simple_encoder, led_strip_pixels, sizeof(led_strip_pixels), &tx_config));
        ESP_ERROR_CHECK(rmt_tx_wait_all_done(led_chan, portMAX_DELAY));
        vTaskDelay(pdMS_TO_TICKS(EXAMPLE_FRAME_DURATION_MS));
        //Increase offset to shift pattern
        offset += EXAMPLE_ANGLE_INC_FRAME;
        if (offset > 2 * M_PI) {
            offset -= 2 * M_PI;
        }
    }
}
