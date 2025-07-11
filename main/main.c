#include <sys/param.h>
#include <string.h>
#include <inttypes.h>

// OTA
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "nvs.h"
#include "esp_http_client.h"
#include "esp_https_ota.h"
#include "esp_crt_bundle.h"
#include "cJSON.h"
#include "driver/gpio.h"
#include "esp_ota_ops.h"

// STA-AP
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"

#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "lwip/inet.h"

#include "esp_http_server.h"
#include "dns_server.h"
#include "nvs.h"
// Firebase
#include "esp_sntp.h"
#include <sys/time.h>
#include "esp_timer.h"

#define EXAMPLE_ESP_WIFI_SSID CONFIG_ESP_WIFI_SSID
#define EXAMPLE_ESP_WIFI_PASS CONFIG_ESP_WIFI_PASSWORD
#define EXAMPLE_MAX_STA_CONN CONFIG_ESP_MAX_STA_CONN

extern const char root_start[] asm("_binary_root_html_start");
extern const char root_end[] asm("_binary_root_html_end");
bool connected = false;

// firebase config
#define FIREBASE_HOST "iot-bin-database-default-rtdb.firebaseio.com"
#define FIREBASE_PATH "/firmware.json"
#define FIREBASE_AUTH "8Eru70ElyOzwf7w8bL36uKxnY5HDOBrmKCuqZZwZ"

// LED pin
#define LED_PIN GPIO_NUM_2

// static const char *TAG_WIFI = "wifi";
static const char *TAG_OTA = "ota";
static char response_buffer[1024];
static int response_len = 0;

// Version holder
char CURRENT_FIRMWARE_VERSION[16] = "v1.0.0";

static const char *TAG = "example";
static const char *TAG_FIREBASE = "firebase_send";
static dns_server_handle_t dns_handle = NULL;
static httpd_handle_t server_handle = NULL;

#define MAX_WIFI_RETRIES 5
static EventGroupHandle_t wifi_event_group;
#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1

static void dhcp_set_captiveportal_url(void);
static httpd_handle_t start_webserver(void);
static void wifi_sta_reconnect_task(void *arg);

// ===== USER LOGIC (UPDATABLE VIA OTA) ===== //
void user_main_logic(void)
{
    gpio_config_t io_conf = {
        .pin_bit_mask = (1ULL << LED_PIN),
        .mode = GPIO_MODE_OUTPUT,
        .pull_up_en = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type = GPIO_INTR_DISABLE};
    gpio_config(&io_conf);
}
// ======================================== //

// URL decode function (handles %XX and '+')
static void url_decode(char *str)
{
    char *p = str;
    char code[3] = {0};
    while (*str)
    {
        if (*str == '%')
        {
            if (str[1] && str[2])
            {
                code[0] = str[1];
                code[1] = str[2];
                *p++ = (char)strtol(code, NULL, 16);
                str += 3;
            }
        }
        else if (*str == '+')
        {
            *p++ = ' ';
            str++;
        }
        else
        {
            *p++ = *str++;
        }
    }
    *p = '\0';
}

static esp_err_t connect_post_handler(httpd_req_t *req)
{
    char content[100];
    int ret = httpd_req_recv(req, content, MIN(req->content_len, sizeof(content)));
    if (ret <= 0)
    {
        return ESP_FAIL;
    }
    content[ret] = '\0';

    // Extract SSID and password from form
    char ssid[32] = {0}, password[64] = {0};
    sscanf(content, "ssid=%31[^&]&password=%63s", ssid, password);

    // Decode URL-encoded strings
    url_decode(ssid);
    url_decode(password);

    ESP_LOGI(TAG, "Received credentials: SSID='%s', Password='%s'", ssid, password);

    // Save to NVS
    nvs_handle_t nvs_handle;
    ESP_ERROR_CHECK(nvs_open("wifi_creds", NVS_READWRITE, &nvs_handle));
    ESP_ERROR_CHECK(nvs_set_str(nvs_handle, "ssid", ssid));
    ESP_ERROR_CHECK(nvs_set_str(nvs_handle, "password", password));
    ESP_ERROR_CHECK(nvs_commit(nvs_handle));
    nvs_close(nvs_handle);

    // Respond to client
    httpd_resp_send(req, "Connecting to Wi-Fi... Rebooting.", HTTPD_RESP_USE_STRLEN);

    vTaskDelay(pdMS_TO_TICKS(2000));
    esp_restart();

    return ESP_OK;
}

void stop_webserver(void)
{
    if (server_handle != NULL)
    {
        esp_err_t err = httpd_stop(server_handle);
        vTaskDelay(pdMS_TO_TICKS(100)); // Give time for server to stop
        if (err == ESP_OK)
        {
            ESP_LOGI(TAG, "HTTP server stopped.");
            server_handle = NULL;
        }
        else if (err == ESP_ERR_INVALID_STATE)
        {
            ESP_LOGW(TAG, "HTTP server already stopped.");
        }
        else
        {
            ESP_LOGE(TAG, "httpd_stop failed: %s", esp_err_to_name(err));
        }
    }
}

void switch_to_sta_only_mode_if_needed()
{
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    if (mode == WIFI_MODE_APSTA)
    {
        stop_dns_server(dns_handle);
        stop_webserver();
        esp_wifi_set_mode(WIFI_MODE_STA);
        ESP_LOGI(TAG, "Switched to STA-only mode after reconnect.");
    }
}

static void wifi_sta_event_handler(void *arg, esp_event_base_t event_base,
                                   int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)
    {
        esp_wifi_connect();
        ESP_LOGI(TAG, "Wi-Fi STA started. Attempting to connect...");
    }
    else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)
    {
        xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        ESP_LOGW(TAG, "Wi-Fi disconnected. Enabling AP + portal...");

        // Ensure AP is active
        wifi_mode_t current_mode;
        esp_wifi_get_mode(&current_mode);
        if (!(current_mode & WIFI_MODE_AP))
        {
            ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
            server_handle = start_webserver();
            dns_server_config_t config = DNS_SERVER_CONFIG_SINGLE("*", "WIFI_AP_DEF");
            dns_handle = start_dns_server(&config);
        }

        xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
    }
    else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)
    {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));

        xEventGroupClearBits(wifi_event_group, WIFI_FAIL_BIT);
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
        switch_to_sta_only_mode_if_needed();
    }
}

static void start_dual_mode_wifi()
{
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_sta_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_sta_event_handler, NULL));

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    // Configure AP part
    wifi_config_t wifi_ap_config = {
        .ap = {
            .ssid = EXAMPLE_ESP_WIFI_SSID,
            .ssid_len = strlen(EXAMPLE_ESP_WIFI_SSID),
            .password = EXAMPLE_ESP_WIFI_PASS,
            .max_connection = EXAMPLE_MAX_STA_CONN,
            .authmode = WIFI_AUTH_WPA_WPA2_PSK},
    };
    if (strlen(EXAMPLE_ESP_WIFI_PASS) == 0)
    {
        wifi_ap_config.ap.authmode = WIFI_AUTH_OPEN;
    }

    ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_AP, &wifi_ap_config));

    // ✅ Set mode again just in case
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_start());

    // ✅ Add delay after start
    vTaskDelay(pdMS_TO_TICKS(1000));

    wifi_mode_t mode;
    ESP_ERROR_CHECK(esp_wifi_get_mode(&mode));
    if (!(mode & WIFI_MODE_STA))
    {
        ESP_LOGW(TAG, "STA interface not active. Forcing APSTA mode again.");
        ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    }

#ifdef CONFIG_ESP_ENABLE_DHCP_CAPTIVEPORTAL
    dhcp_set_captiveportal_url();
#endif
    server_handle = start_webserver();
    dns_server_config_t config = DNS_SERVER_CONFIG_SINGLE("*", "WIFI_AP_DEF");
    dns_handle = start_dns_server(&config);

    // Launch STA reconnect task
    xTaskCreate(&wifi_sta_reconnect_task, "wifi_sta_reconnect_task", 4096, NULL, 5, NULL);
}

static void wifi_sta_reconnect_task(void *arg)
{
    char ssid[32] = {0}, password[64] = {0};
    nvs_handle_t nvs_handle;

    esp_err_t err = nvs_open("wifi_creds", NVS_READONLY, &nvs_handle);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "No saved credentials in NVS.");
        vTaskDelete(NULL);
        return;
    }

    size_t ssid_len = sizeof(ssid), pass_len = sizeof(password);
    if (nvs_get_str(nvs_handle, "ssid", ssid, &ssid_len) != ESP_OK ||
        nvs_get_str(nvs_handle, "password", password, &pass_len) != ESP_OK)
    {
        ESP_LOGW(TAG, "Incomplete credentials.");
        nvs_close(nvs_handle);
        vTaskDelete(NULL);
        return;
    }
    nvs_close(nvs_handle);

    wifi_config_t wifi_sta_config = {0};
    strncpy((char *)wifi_sta_config.sta.ssid, ssid, sizeof(wifi_sta_config.sta.ssid));
    strncpy((char *)wifi_sta_config.sta.password, password, sizeof(wifi_sta_config.sta.password));

    while (1)
    {
        EventBits_t bits = xEventGroupGetBits(wifi_event_group);

        if ((bits & WIFI_CONNECTED_BIT) == 0)
        {
            ESP_LOGW(TAG, "Not connected. Trying to reconnect...");

            ESP_ERROR_CHECK(esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_sta_config));

            wifi_mode_t mode;
            esp_wifi_get_mode(&mode);
            if (!(mode & WIFI_MODE_STA))
            {
                ESP_LOGW(TAG, "STA interface inactive. Resetting mode to APSTA...");
                ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
                ESP_ERROR_CHECK(esp_wifi_start());
            }

            esp_err_t res = esp_wifi_connect();
            if (res != ESP_OK)
            {
                ESP_LOGE(TAG, "esp_wifi_connect() failed: %s", esp_err_to_name(res));
            }

            // Wait for either success or fail
            bits = xEventGroupWaitBits(wifi_event_group,
                                       WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
                                       pdFALSE,
                                       pdFALSE,
                                       pdMS_TO_TICKS(10000));

            if (bits & WIFI_CONNECTED_BIT)
            {
                ESP_LOGI(TAG, "Connected to saved Wi-Fi. Starting main logic...");
                switch_to_sta_only_mode_if_needed();
            }
            else
            {
                ESP_LOGW(TAG, "Connection attempt failed. Will retry...");
            }
        }

        vTaskDelay(pdMS_TO_TICKS(15000)); // periodic check
    }
}

#ifdef CONFIG_ESP_ENABLE_DHCP_CAPTIVEPORTAL
static void dhcp_set_captiveportal_url(void)
{
    // get the IP of the access point to redirect to
    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(esp_netif_get_handle_from_ifkey("WIFI_AP_DEF"), &ip_info);

    char ip_addr[16];
    inet_ntoa_r(ip_info.ip.addr, ip_addr, 16);
    ESP_LOGI(TAG, "Set up softAP with IP: %s", ip_addr);

    // turn the IP into a URI
    char *captiveportal_uri = (char *)malloc(32 * sizeof(char));
    assert(captiveportal_uri && "Failed to allocate captiveportal_uri");
    strcpy(captiveportal_uri, "http://");
    strcat(captiveportal_uri, ip_addr);

    // get a handle to configure DHCP with
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");

    // set the DHCP option 114
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_dhcps_stop(netif));
    ESP_ERROR_CHECK(esp_netif_dhcps_option(netif, ESP_NETIF_OP_SET, ESP_NETIF_CAPTIVEPORTAL_URI, captiveportal_uri, strlen(captiveportal_uri)));
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_dhcps_start(netif));
}
#endif // CONFIG_ESP_ENABLE_DHCP_CAPTIVEPORTAL

// HTTP GET Handler
static esp_err_t root_get_handler(httpd_req_t *req)
{
    const uint32_t root_len = root_end - root_start;

    ESP_LOGI(TAG, "Serve root");
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, root_start, root_len);

    return ESP_OK;
}

static const httpd_uri_t root = {
    .uri = "/",
    .method = HTTP_GET,
    .handler = root_get_handler};

// HTTP Error (404) Handler - Redirects all requests to the root page
esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    // Set status
    httpd_resp_set_status(req, "302 Temporary Redirect");
    // Redirect to the "/" root directory
    httpd_resp_set_hdr(req, "Location", "/");
    // iOS requires content in the response to detect a captive portal, simply redirecting is not sufficient.
    httpd_resp_send(req, "Redirect to the captive portal", HTTPD_RESP_USE_STRLEN);

    ESP_LOGI(TAG, "Redirecting to root");
    return ESP_OK;
}

static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.max_open_sockets = 13;
    config.lru_purge_enable = true;

    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK)
    {
        ESP_LOGI(TAG, "Registering URI handlers");

        static const httpd_uri_t connect = {
            .uri = "/connect",
            .method = HTTP_POST,
            .handler = connect_post_handler};

        httpd_register_uri_handler(server, &connect);
        httpd_register_uri_handler(server, &root);
        httpd_register_err_handler(server, HTTPD_404_NOT_FOUND, http_404_error_handler);
    }

    return server;
}

esp_err_t _http_event_handler(esp_http_client_event_t *evt)
{
    switch (evt->event_id)
    {
    case HTTP_EVENT_ON_DATA:
        if (!esp_http_client_is_chunked_response(evt->client))
        {
            if (response_len + evt->data_len < sizeof(response_buffer))
            {
                memcpy(response_buffer + response_len, evt->data, evt->data_len);
                response_len += evt->data_len;
                response_buffer[response_len] = 0;
            }
        }
        break;
    default:
        break;
    }
    return ESP_OK;
}

int parse_version(const char *vstr, int *major, int *minor, int *patch)
{
    return sscanf(vstr, "v%d.%d.%d", major, minor, patch);
}

bool is_newer_version(const char *current, const char *available)
{
    int c_major, c_minor, c_patch;
    int a_major, a_minor, a_patch;

    if (parse_version(current, &c_major, &c_minor, &c_patch) != 3 ||
        parse_version(available, &a_major, &a_minor, &a_patch) != 3)
    {
        return false;
    }

    if (a_major != c_major)
        return a_major > c_major;
    if (a_minor != c_minor)
        return a_minor > c_minor;
    return a_patch > c_patch;
}

void save_new_version_to_nvs(const char *version)
{
    nvs_handle_t nvs;
    if (nvs_open("ota_store", NVS_READWRITE, &nvs) == ESP_OK)
    {
        nvs_set_str(nvs, "fw_version", version);
        nvs_commit(nvs);
        nvs_close(nvs);
        ESP_LOGI(TAG_OTA, "Saved new version to NVS: %s", version);
    }
}

void load_current_version_from_nvs()
{
    nvs_handle_t nvs;
    size_t size = sizeof(CURRENT_FIRMWARE_VERSION);
    if (nvs_open("ota_store", NVS_READONLY, &nvs) == ESP_OK)
    {
        if (nvs_get_str(nvs, "fw_version", CURRENT_FIRMWARE_VERSION, &size) != ESP_OK)
        {
            strcpy(CURRENT_FIRMWARE_VERSION, "v1.0.0"); // fallback
        }
        nvs_close(nvs);
    }
    else
    {
        ESP_LOGW(TAG_OTA, "NVS not initialized, using default version: %s", CURRENT_FIRMWARE_VERSION);
    }
    ESP_LOGI(TAG_OTA, "Current firmware version loaded from NVS: %s", CURRENT_FIRMWARE_VERSION);
}

void perform_ota_update(const char *firmware_url, const char *new_version)
{
    esp_http_client_config_t http_config = {
        .url = firmware_url,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };

    esp_https_ota_config_t ota_config = {
        .http_config = &http_config,
    };

    esp_https_ota_handle_t ota_handle = NULL;
    esp_err_t ret = esp_https_ota_begin(&ota_config, &ota_handle);
    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG_OTA, "OTA begin failed: %s", esp_err_to_name(ret));
        return;
    }

    while (1)
    {
        ret = esp_https_ota_perform(ota_handle);
        if (ret != ESP_ERR_HTTPS_OTA_IN_PROGRESS)
            break;
    }

    if (ret == ESP_OK)
    {
        ret = esp_https_ota_finish(ota_handle);
        if (ret == ESP_OK)
        {
            ESP_LOGI(TAG_OTA, "OTA successful. Rebooting into new firmware.");
            save_new_version_to_nvs(new_version);

            // Do NOT call esp_ota_mark_app_valid() yet!
            // Let app validate itself after successful startup.
            esp_restart();
        }
        else
        {
            ESP_LOGE(TAG_OTA, "esp_https_ota_finish failed: %s", esp_err_to_name(ret));
        }
    }
    else
    {
        ESP_LOGE(TAG_OTA, "OTA perform failed: %s", esp_err_to_name(ret));
        esp_https_ota_abort(ota_handle);
    }
}

void check_and_perform_ota(void)
{
    response_len = 0;

    char url[256];
    snprintf(url, sizeof(url),
             "https://%s%s?auth=%s",
             FIREBASE_HOST, FIREBASE_PATH, FIREBASE_AUTH);

    esp_http_client_config_t config = {
        .url = url,
        .event_handler = _http_event_handler,
        .transport_type = HTTP_TRANSPORT_OVER_SSL,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .skip_cert_common_name_check = true,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_method(client, HTTP_METHOD_GET);

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK)
    {
        cJSON *root = cJSON_Parse(response_buffer);
        if (root)
        {
            const cJSON *url = cJSON_GetObjectItem(root, "url");
            const cJSON *version = cJSON_GetObjectItem(root, "version");

            if (url && cJSON_IsString(url) &&
                version && cJSON_IsString(version))
            {
                ESP_LOGI(TAG_OTA, "Available firmware: %s (version: %s)", url->valuestring, version->valuestring);
                ESP_LOGI(TAG_OTA, "Current firmware version: %s", CURRENT_FIRMWARE_VERSION);

                if (is_newer_version(CURRENT_FIRMWARE_VERSION, version->valuestring))
                {
                    ESP_LOGI(TAG_OTA, "New firmware available. Performing OTA update...");
                    save_new_version_to_nvs(version->valuestring);
                    perform_ota_update(url->valuestring, version->valuestring);
                }
                else
                {
                    ESP_LOGI(TAG_OTA, "Firmware is up to date.");
                }
            }
            else
            {
                ESP_LOGE(TAG_OTA, "Invalid JSON from Firebase.");
            }
            cJSON_Delete(root);
        }
        else
        {
            ESP_LOGE(TAG_OTA, "JSON parsing failed.");
        }
    }
    else
    {
        ESP_LOGE(TAG_OTA, "HTTP GET failed: %s", esp_err_to_name(err));
    }
    esp_http_client_cleanup(client);
}

//  get current time from server
void initialize_sntp(void)
{
    ESP_LOGI(TAG, "Initializing SNTP...");
    esp_sntp_stop(); // Always stop before re-initializing (safe for re-entry)

    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);

    // Set multiple servers
    esp_sntp_setservername(0, "pool.ntp.org");     // Primary
    esp_sntp_setservername(1, "time.google.com");  // Fallback 1
    esp_sntp_setservername(2, "time.windows.com"); // Fallback 2

    esp_sntp_init();
}

void obtain_time(void)
{
    while (1)
    {
        // ✅ Check if Wi-Fi is connected before proceeding
        EventBits_t bits = xEventGroupGetBits(wifi_event_group);
        if ((bits & WIFI_CONNECTED_BIT) == 0)
        {
            ESP_LOGW(TAG, "Wi-Fi not connected. Waiting before time sync...");
            vTaskDelay(pdMS_TO_TICKS(2000));
            continue;
        }

        ESP_LOGI(TAG, "Wi-Fi connected. Attempting SNTP sync...");
        initialize_sntp();

        time_t now = 0;
        struct tm timeinfo = {0};
        int retry = 0;
        const int retry_count = 20;

        while (timeinfo.tm_year < (2016 - 1900) && ++retry < retry_count)
        {
            ESP_LOGI(TAG, "Waiting for system time to be set... (%d/%d)", retry, retry_count);
            vTaskDelay(pdMS_TO_TICKS(2000));
            time(&now);
            localtime_r(&now, &timeinfo);
        }

        if (timeinfo.tm_year >= (2016 - 1900))
        {
            ESP_LOGI(TAG, "Time is set.");
            break; // ✅ SUCCESS: Exit outer loop
        }
        else
        {
            ESP_LOGW(TAG, "SNTP failed after %d retries. Reinitializing...", retry);
            esp_sntp_stop();
            vTaskDelay(pdMS_TO_TICKS(3000)); // Give time before retrying
        }
    }
}

// data sending part

bool send_data_to_firebase()
{
    gpio_set_level(LED_PIN, 1);
    // Check if Wi-Fi is connected

    if (!(xEventGroupGetBits(wifi_event_group) & WIFI_CONNECTED_BIT))
    {
        ESP_LOGW(TAG_FIREBASE, "Wi-Fi not connected. Skipping data send.");
        return false;
    }

    // Prepare Firebase URL and device name
    static char device_name[32] = {0};
    static char firebase_url[256] = {0};

    if (device_name[0] == 0)
    {
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_STA);
        snprintf(device_name, sizeof(device_name), "ESP32-%02X%02X%02X", mac[3], mac[4], mac[5]);
        snprintf(firebase_url, sizeof(firebase_url),
                 "https://esp32-iot-project-75fdf-default-rtdb.firebaseio.com/iot/%s/logs.json",
                 device_name);
        ESP_LOGI(TAG_FIREBASE, "Device identified as: %s", device_name);
    }

    float temperature = 26.0 + (esp_random() % 100) / 10.0f;
    int humidity = 50 + esp_random() % 10;
    int pressure = 30 + esp_random() % 10;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    int64_t timestamp_ms = (int64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;

    char post_data[256];
    snprintf(post_data, sizeof(post_data),
             "{\"temperature\": %.1f, \"humidity\": %d, \"pressure\": %d, \"timestamp\": %" PRId64 "}",
             temperature, humidity, pressure, timestamp_ms);

    esp_http_client_config_t config = {
        .url = firebase_url,
        .method = HTTP_METHOD_POST,
        .event_handler = _http_event_handler,
        .crt_bundle_attach = esp_crt_bundle_attach,
    };

    esp_http_client_handle_t client = esp_http_client_init(&config);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, post_data, strlen(post_data));

    esp_err_t err = esp_http_client_perform(client);
    bool success = false;
    if (err == ESP_OK)
    {
        ESP_LOGI(TAG_FIREBASE, "[%s] Data sent: %s", device_name, post_data);
        success = true;
    }
    else
    {
        ESP_LOGE(TAG_FIREBASE, "Error sending data: %s", esp_err_to_name(err));
    }
    if (!(xEventGroupGetBits(wifi_event_group) & WIFI_CONNECTED_BIT))
    {
        ESP_LOGW(TAG_FIREBASE, "Wi-Fi lost during send. Waiting for reconnection...");
        return false;
    }

    esp_http_client_cleanup(client);
    vTaskDelay(pdMS_TO_TICKS(50));
    gpio_set_level(LED_PIN, 0);
    return success;
}

void firebase_task(void *pvParameters)
{
    const int send_interval_ms = 10000; // Send every 10 seconds
    int retry_delay_ms = 2000;          // Backoff starts at 2s
    const int max_delay_ms = 120000;    // Max 2 minutes

    while (1)
    {
        // Wait until Wi-Fi is connected
        xEventGroupWaitBits(wifi_event_group,
                            WIFI_CONNECTED_BIT,
                            pdFALSE, pdTRUE,
                            portMAX_DELAY); // wait forever

        // Now Wi-Fi is connected, attempt to send
        bool success = send_data_to_firebase();

        if (success)
        {
            retry_delay_ms = 2000; // reset backoff
            vTaskDelay(pdMS_TO_TICKS(send_interval_ms));
        }
        else
        {
            ESP_LOGW(TAG_FIREBASE, "Send failed. Retrying in %d ms", retry_delay_ms);

            // Still connected? Wait for backoff then try again
            EventBits_t still_connected = xEventGroupGetBits(wifi_event_group);
            if (still_connected & WIFI_CONNECTED_BIT)
            {
                vTaskDelay(pdMS_TO_TICKS(retry_delay_ms));
                retry_delay_ms *= 2;
                if (retry_delay_ms > max_delay_ms)
                    retry_delay_ms = max_delay_ms;
            }
            else
            {
                // Wi-Fi disconnected during retry → block again on event
                retry_delay_ms = 2000; // reset backoff
            }
        }
    }
}

void ota_validate_task(void *pvParameters)
{
    ESP_LOGI(TAG_OTA, "Waiting before marking OTA app valid...");
    vTaskDelay(pdMS_TO_TICKS(5000)); // 5 second delay

    esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
    if (err == ESP_OK)
    {
        ESP_LOGI(TAG_OTA, "App marked valid (rollback cancelled).");
    }
    else
    {
        ESP_LOGE(TAG_OTA, "Failed to mark OTA app valid: %s", esp_err_to_name(err));
    }

    vTaskDelete(NULL);
}

void app_main(void)
{
    // int *p = NULL;
    // *p = 42; // Intentional crash: dereference NULL pointe
    // assert(false && "Simulated OTA failure");
    // Reduce HTTP log noise
    esp_log_level_set("httpd_uri", ESP_LOG_ERROR);
    esp_log_level_set("httpd_txrx", ESP_LOG_ERROR);
    esp_log_level_set("httpd_parse", ESP_LOG_ERROR);

    // Initialize core networking and storage
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    wifi_event_group = xEventGroupCreate();
    assert(wifi_event_group != NULL);

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    load_current_version_from_nvs();

    // Create default interfaces
    esp_netif_create_default_wifi_sta(); // for station mode
    esp_netif_create_default_wifi_ap();  // for fallback softAP

    // Init Wi-Fi driver
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_FLASH));

    // logic for connecting to saved Wi-Fi or starting AP
    start_dual_mode_wifi(); // handles both AP + STA + reconnect task

    ESP_LOGI(TAG, "Waiting for Wi-Fi connection...");
    xEventGroupWaitBits(wifi_event_group,
                        WIFI_CONNECTED_BIT,
                        pdFALSE,
                        pdTRUE,
                        portMAX_DELAY);
    ESP_LOGI(TAG, "Wi-Fi connected, continuing startup.");
    // Delay rollback cancellation to ensure stability
    xTaskCreate(ota_validate_task, "ota_validate_task", 4096, NULL, 5, NULL);

    check_and_perform_ota(); // will restart if update happens
    ESP_LOGI(TAG_OTA, "Starting user logic...");
    obtain_time();     // Get current time from NTP server
    user_main_logic(); // Run user-defined logic
    const esp_partition_t *running = esp_ota_get_running_partition();
    ESP_LOGI(TAG_OTA, "Running partition: subtype 0x%" PRIx32 " at offset 0x%08" PRIx32,
             (uint32_t)running->subtype,
             (uint32_t)running->address);

    ESP_LOGI(TAG_OTA, "Starting Firebase data sending task...");
    xTaskCreate(firebase_task, "firebase_task", 4096, NULL, 5, NULL);
}
