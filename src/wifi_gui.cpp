/**
 * Much of thise code is from pico-examples/pico_w/wifi/access_point_wifi_provisioning --pboothby
 *
 * Copyright (c) 2022 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pico/cyw43_arch.h"
#include "pico/stdlib.h"

#include "lwip/ip4_addr.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/apps/httpd.h"
#include "lwip/pbuf.h"

#include "dhcpserver.h"
#include "dnsserver.h"

#include "wifi_gui.hpp"

#define CYW43_STA_IS_ACTIVE(self) (((self)->itf_state >> CYW43_ITF_STA) & 1)
#define CYW43_AP_IS_ACTIVE(self) (((self)->itf_state >> CYW43_ITF_AP) & 1)

#define AP_SSID "asha-pico"
#define AP_PASSWORD "listentome"
#define AP_TIMEOUT_MS (2 * 1000 * 60) // disable Access Point after this time of inactivity

namespace asha
{
    namespace webgui
    {
        // Function prototypes
        void ap_reset_one_shot_timer(uint32_t delay_ms);
        static const char *clear_cgi_handler(int iIndex, int iNumParams, char *pcParam[], char *pcValue[]);
        static u16_t ssi_handler(int iIndex, char *pcInsert, int iInsertLen
#if LWIP_HTTPD_SSI_MULTIPART
                                 ,
                                 uint16_t current_tag_part, uint16_t *next_tag_part
#endif
        );
        extern "C"
        {
            void httpd_post_finished(void *connection, char *response_uri, u16_t response_uri_len);
            err_t httpd_post_begin(void *connection, const char *uri, __unused const char *http_request,
                                   __unused u16_t http_request_len, __unused int content_len, char *response_uri,
                                   u16_t response_uri_len, u8_t *post_auto_wnd);
            err_t httpd_post_receive_data(void *connection, struct pbuf *p);
        }

        static tCGI cgi_handlers[] = {
            {"/clear.cgi", clear_cgi_handler}
        };  // stop webgui service

        // Be aware of LWIP_HTTPD_MAX_TAG_NAME_LEN
        static const char *ssi_tags[] = {
            "ipaddress",
            "ssid",
            "password"};

        static dhcp_server_t dhcp_server;
        static dns_server_t dns_server;
        static bool ap_running = false;

        static const char *ssid = AP_SSID;
        static const char *password = AP_PASSWORD;

        volatile bool button_pressed = false;
        const uint BUTTON_PIN = 11; // used to trigger webgui service

        // erase existing settings from nvram
        static const char *clear_cgi_handler(__unused int iIndex, __unused int iNumParams, __unused char *pcParam[], __unused char *pcValue[])
        {
            ap_reset_one_shot_timer(AP_TIMEOUT_MS);
            printf("clear_cgi_handler called\n");
            // call to Sherman's code here
            return "/index.shtml";
        }


        // Only one POST is handled at a time; track which connection owns it.
        static void *current_post_connection;
        // Set true once a POST body has been successfully decoded into ssid/password,
        // so httpd_post_finished knows to kick off a connection attempt.
        static bool post_credentials_ok;

        // Decodes application/x-www-form-urlencoded text in place.
        // '+' -> ' ', "%XX" -> byte. dst and src may be the same buffer.
        // Trailing spaces are stripped from the result.
        /*
        static void url_decode(char *dst, const char *src, size_t dst_size)
        {
            size_t di = 0;
            while (*src && di + 1 < dst_size)
            {
                char c = *src;
                if (c == '+')
                {
                    dst[di++] = ' ';
                    src++;
                }
                else if (c == '%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2]))
                {
                    int hi = src[1] <= '9' ? src[1] - '0' : (src[1] | 0x20) - 'a' + 10;
                    int lo = src[2] <= '9' ? src[2] - '0' : (src[2] | 0x20) - 'a' + 10;
                    dst[di++] = (char)((hi << 4) | lo);
                    src += 3;
                }
                else
                {
                    dst[di++] = c;
                    src++;
                }
            }
            // strip trailing spaces
            while (di > 0 && dst[di - 1] == ' ')
            {
                di--;
            }
            dst[di] = '\0';
        }
        */

        err_t httpd_post_begin(void *connection, const char *uri, __unused const char *http_request,
                               __unused u16_t http_request_len, __unused int content_len, char *response_uri,
                               u16_t response_uri_len, u8_t *post_auto_wnd)
        {
            ap_reset_one_shot_timer(AP_TIMEOUT_MS);
            if (strcmp(uri, "/credentials.cgi") == 0)
            {
                current_post_connection = connection;
                post_credentials_ok = false;
                // default redirect; overwritten on success in httpd_post_finished
                snprintf(response_uri, response_uri_len, "/index.shtml");
                *post_auto_wnd = 1;
                return ERR_OK;
            }
            return ERR_VAL;
        }

        err_t httpd_post_receive_data(void *connection, struct pbuf *p)
        {
            err_t ret = ERR_VAL;
            ap_reset_one_shot_timer(AP_TIMEOUT_MS);
            if (connection == current_post_connection)
            {
                // For a small two-field form the body arrives in a single pbuf, so we
                // parse it directly here. post_param_value searches this pbuf only.
                /*
                char ssid_enc[sizeof(ssid)];
                char password_enc[sizeof(password)];

                char *s = post_param_value(p, "ssid=", ssid_enc, sizeof(ssid_enc));
                char *pw = post_param_value(p, "password=", password_enc, sizeof(password_enc));

                if (s != NULL && pw != NULL)
                {
                    url_decode(ssid, s, sizeof(ssid));
                    url_decode(password, pw, sizeof(password));
                    printf("SSID AND PASSWORD: >%s< >%s<\n", ssid, password);
                    post_credentials_ok = true;
                    ret = ERR_OK;
                }
                else
                {
                    printf("missing ssid/password in POST body\n");
                }
                    */
            }
            pbuf_free(p);
            return ret;
        }

        void httpd_post_finished(void *connection, char *response_uri, u16_t response_uri_len)
        {
            ap_reset_one_shot_timer(AP_TIMEOUT_MS);
            if (connection == current_post_connection)
            {
                /* snprintf(response_uri, response_uri_len, "/index.shtml");
                 if (post_credentials_ok)
                 {
                     // Store the new credentials and ask the main loop to connect.
                     attempt_wifi_connection();
                 } */
            }
            current_post_connection = NULL;
        }

        // Appends s to dst with HTML special chars escaped. Writes at most dst_size-1
        // chars plus a null terminator. Returns number of chars written (excl. null).
        static int html_escape(char *dst, size_t dst_size, const char *s)
        {
            size_t di = 0;
            for (; *s && di + 1 < dst_size; s++)
            {
                const char *rep;
                switch (*s)
                {
                case '&':
                    rep = "&amp;";
                    break;
                case '<':
                    rep = "&lt;";
                    break;
                case '>':
                    rep = "&gt;";
                    break;
                case '"':
                    rep = "&quot;";
                    break;
                case '\'':
                    rep = "&#39;";
                    break;
                default:
                    dst[di++] = *s;
                    continue;
                }
                size_t rlen = strlen(rep);
                if (di + rlen >= dst_size)
                    break; // not enough room for the whole entity
                memcpy(dst + di, rep, rlen);
                di += rlen;
            }
            dst[di] = '\0';
            return (int)di;
        }

        alarm_id_t ap_one_shot_timer = -1;

        // timer isr to shut down AP and services after inactivity to minimise battery use
        int64_t ap_one_shot_alarm_callback(alarm_id_t id, void *user_data)
        {
            printf("webgui::ap_one_shot_alarm_callback(): One-time timer expired!\n");

            // stop Access Point and services
            cyw43_arch_lwip_begin();
            dns_server_deinit(&dns_server);
            dhcp_server_deinit(&dhcp_server);
            cyw43_arch_disable_ap_mode();
            cyw43_arch_lwip_end();
            ap_running = false;
            return 0; // Return 0 means the alarm does not re-trigger (one-shot)
        }

        // Function to start or reset the one-shot timer
        void ap_reset_one_shot_timer(uint32_t delay_ms)
        {
            // Cancel existing alarm if it is currently running
            if (ap_one_shot_timer >= 0)
            {
                cancel_alarm(ap_one_shot_timer);
            }

            // 2. Schedule a new one-shot alarm
            ap_one_shot_timer = add_alarm_in_ms(delay_ms, ap_one_shot_alarm_callback, NULL, true);
            printf("webgui::ap_reset_one_shot_timer() called\n");
        }

        unsigned long button_time = to_ms_since_boot(get_absolute_time());
        const int delayTime = 50; // Delay for every push button may vary
        void gpio_callback(uint gpio, uint32_t events)
        {
            if (gpio == BUTTON_PIN)
            {
                if ((to_ms_since_boot(get_absolute_time()) - button_time) > delayTime)
                {
                    // Recommend to not to change the position of this line
                    button_time = to_ms_since_boot(get_absolute_time());
                    button_pressed = true;
                    ap_reset_one_shot_timer(AP_TIMEOUT_MS); // let httpd run longer
                }
            }
        }

        void init()
        {
            // Initialize the GPIO pin
            gpio_init(BUTTON_PIN);

            // Set the pin as an input
            gpio_set_dir(BUTTON_PIN, GPIO_IN);

            // Enable the internal pull-up resistor (defaults the pin to HIGH; pressing pulls it to LOW)
            gpio_pull_up(BUTTON_PIN);

            // Set up the interrupt
            // Triggers on EDGE_FALLING (when the button transitions from HIGH to LOW)
            gpio_set_irq_enabled_with_callback(BUTTON_PIN, GPIO_IRQ_EDGE_FALL, true, &gpio_callback);

            //
            // Bring up the WiFi Access Point + services once, at the start
            //
            cyw43_arch_enable_ap_mode(AP_SSID, AP_PASSWORD, CYW43_AUTH_WPA2_AES_PSK);
            printf("\nReady, running web server at %s\n", ip4addr_ntoa(netif_ip4_addr(netif_list)));
            printf("Connect to ssid \"%s\" with password \"%s\"\n", ssid, password);

#if LWIP_IPV6
#define IP(x) ((x).u_addr.ip4)
#else
#define IP(x) (x)
#endif
            ip4_addr_t mask;
            ip4_addr_t gw;
            IP(gw).addr = PP_HTONL(CYW43_DEFAULT_IP_AP_ADDRESS);
            IP(mask).addr = PP_HTONL(CYW43_DEFAULT_IP_MASK);
#undef IP

            dhcp_server_init(&dhcp_server, &cyw43_state.netif[CYW43_ITF_AP], &gw, &mask);
            dns_server_init(&dns_server, &cyw43_state.netif[CYW43_ITF_AP], &gw);

            char hostname[sizeof(CYW43_HOST_NAME) + 4];
            memcpy(&hostname[0], CYW43_HOST_NAME, sizeof(CYW43_HOST_NAME) - 1);
            hostname[sizeof(hostname) - 1] = '\0';
            netif_set_hostname(&cyw43_state.netif[CYW43_ITF_STA], hostname);

            // setup http server
            cyw43_arch_lwip_begin();
            httpd_init();
            http_set_cgi_handlers(cgi_handlers, LWIP_ARRAYSIZE(cgi_handlers));
            http_set_ssi_handler(ssi_handler, ssi_tags, LWIP_ARRAYSIZE(ssi_tags));
            cyw43_arch_lwip_end();
            ap_running = true;
            ap_reset_one_shot_timer(AP_TIMEOUT_MS);
        }

        // Note that the buffer size is limited by LWIP_HTTPD_MAX_TAG_INSERT_LEN, so use LWIP_HTTPD_SSI_MULTIPART to return larger amounts of data
        static u16_t ssi_handler(int iIndex, char *pcInsert, int iInsertLen
#if LWIP_HTTPD_SSI_MULTIPART
                                 ,
                                 uint16_t current_tag_part, uint16_t *next_tag_part
#endif
        )
        {
            int printed = 0;
            switch (iIndex)
            {
            case 0:
            { // ipaddress
                char esc[15 * 6];   // max IP address + 1
                html_escape(esc, sizeof(esc), ip4addr_ntoa(netif_ip4_addr(netif_list)));
                printed = snprintf(pcInsert, iInsertLen, "%s", esc);
                break;
            }
            case 1:
            { // ssid
                char esc[sizeof(ssid) * 6];
                html_escape(esc, sizeof(esc), ssid);
                printed = snprintf(pcInsert, iInsertLen, "%s", esc);
                break;
            }
            case 2:
            { // password
                char esc[sizeof(password) * 6];
                html_escape(esc, sizeof(esc), password);
                printed = snprintf(pcInsert, iInsertLen, "%s", esc);
                break;
            }
            default:
            { // unknown tag
                printed = 0;
                break;
            }
            }
            return printed;
        }

        void wifi_task()
        {
            if (!ap_running)
                return;
            cyw43_arch_poll();
            cyw43_arch_wait_for_work_until(at_the_end_of_time);
        }
    }

}