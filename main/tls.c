#include "tls.h"

static const char *TAG = "TLS_LIB";
static const char *REQUEST = "GET " WEB_URL " HTTP/1.0\r\n"
    "Host: "WEB_SERVER"\r\n"
    "User-Agent: esp-idf/1.0 esp32\r\n"
    "\r\n";

char* https_get_response()
{
    char buf[512];
    int ret, flags, len;
    char *response_str = NULL;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);

    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ret = esp_crt_bundle_attach(&conf);
    if(ret < 0)
    {
        ESP_LOGE(TAG, "esp_crt_bundle_attach returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

    if((ret = mbedtls_ssl_set_hostname(&ssl, WEB_SERVER)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    if((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x", -ret);
        goto exit;
    }

    mbedtls_net_init(&server_fd);

    ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

    if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER, WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
        goto exit;
    }

    ESP_LOGI(TAG, "Connected.");

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
    {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
        {
            ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
            goto exit;
        }
    }

    ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

    if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
    {
        ESP_LOGW(TAG, "Failed to verify peer certificate!");
        bzero(buf, sizeof(buf));
        mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
        ESP_LOGW(TAG, "verification info: %s", buf);
    }
    else {
        ESP_LOGI(TAG, "Certificate verified.");
    }

    ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&ssl));

    ESP_LOGI(TAG, "Writing HTTP request...");

    size_t written_bytes = 0;
    do {
        ret = mbedtls_ssl_write(&ssl, (const unsigned char *)REQUEST + written_bytes, strlen(REQUEST) - written_bytes);
        if (ret >= 0) {
            ESP_LOGI(TAG, "%d bytes written", ret);
            written_bytes += ret;
        } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
            ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
            goto exit;
        }
    } while(written_bytes < strlen(REQUEST));

    ESP_LOGI(TAG, "Reading HTTP response...");

    len = sizeof(buf) - 1;
    bzero(buf, sizeof(buf));
    ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);
    char* json_res= strstr(buf, "\r\n\r\n");
    if (json_res) {
        json_res += 4;
        while (*json_res == '\r' || *json_res == '\n') {
            json_res++;
        }
    }
    response_str = (char *)malloc(strlen(json_res) + 1);
    if (response_str != NULL) {
        strcpy(response_str, json_res);
    } else {
        ESP_LOGE(TAG, "Không thể cấp phát bộ nhớ cho response_str");
    }

exit:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_ssl_session_reset(&ssl);
    mbedtls_net_free(&server_fd);

    if (response_str) {
        ESP_LOGI(TAG,"https response: \n%s",response_str);
        return response_str;
    } else {
        return NULL;  
    }
}

char* get_version(const char* json_string) {
    cJSON *root = cJSON_Parse(json_string);
    if (root == NULL) {
        return NULL;
    }

    cJSON *data = cJSON_GetObjectItem(root, "data");
    if (data == NULL) {
        cJSON_Delete(root);
        return NULL;
    }

    cJSON *version = cJSON_GetObjectItem(data, "version");
    if (cJSON_IsString(version) && (version->valuestring != NULL)) {
        char *version_str = strdup(version->valuestring);
        cJSON_Delete(root);
        return version_str;
    } else {
        cJSON_Delete(root);
        return NULL;
    }
}