/*
    * TLS_lib
    * Authorized by: Em Nhật depzai. Release date: 4-9-2024 at XSOLAR-co.
*/
#ifndef TLS_H_
#define TLS_H_

#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include "esp_log.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "cJSON.h"

#include "esp_crt_bundle.h"
#include "esp_https_ota.h"

#define WEB_SERVER "www.xsolar.energy"
#define WEB_PORT "443"
#define WEB_URL "https://xsolar.energy/beapi/v1/firmware/get?deviceType=RGB"

char* https_get_response();
char* get_version(const char* json_string); 
#endif