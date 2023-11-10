#include <limits.h>
#include <string.h>

#include <zephyr/net/http/service.h>
#include <zephyr/net/socket.h>

BUILD_ASSERT(CONFIG_TEST_SERVER_B_PORT >= 0 && CONFIG_TEST_SERVER_B_PORT <= UINT16_MAX);

/** @brief Manually define the port for HTTP service B */
#if CONFIG_TEST_SERVER_A_PORT == 0
/* An ephemeral port number is generated and written back to RAM */
#define PORTCONST
#else
/* Constant port numbers reside in ROM */
#define PORTCONST const
#endif
static PORTCONST uint16_t service_B_port = htons(CONFIG_TEST_SERVER_A_PORT);

/** @brief Manually define HTTP service B */
HTTP_SERVICE_DEFINE(service_B, CONFIG_NET_CONFIG_MY_IPV4_ADDR, &service_B_port, 1, 1, NULL);

/**
 * @brief Manually define CRiMe for index.html for service B
 *
 * This is just about as manual as we get currently. In this case, the user would have needed
 * to compress the contents of service_B/index.html offline and copy-paste it into this C file.
 *
 * E.g. the data below should match what is produced with
 * ```
 * $ gzip -9 < tests/net/lib/http_server/crime/service_B/index.html > /tmp/index.html.gz
 * $ xxd -i /tmp/index.html.gz
 * ```
 *
 * Normally, we should rely on code generation tools to do this for us, as the contents of
 * files may change from one build to the next. Here, it is only done the manual way for
 * illustrative purposes.
 */
static const uint8_t service_B_index_html_gzip_data[] = {
    0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0xff, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
};
HTTP_RESOURCE_DEFINE(service_B_index_html, service_B, "/index.html", service_B_index_html_gzip_data);

/**
 * @brief Manually define CRiMe for js/service-A.js
 *
 * This is not quite as manual as the definition of index.html above, but intentionally does not
 * use batch mode.
 *
 * The contents of the included file are generated at build time by using cmake with
 * @ref generate_inc_file_for_target. For more details, see the CMakeLists.txt in the project
 * directory.
 *
 * @note The ISO C23 standard introduces the `#embed <file.x>` directive which translates the
 * bytes of arbitrary files into C array contents.
 */
static const uint8_t service_B_js_service_B_js_gzip_data[] = {
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
#embed "service_B/js/service-B.js"
#else 
#include "zephyr/include/generated/http_server/service_B/js/service-B.js.inc"
#endif
};
HTTP_RESOURCE_DEFINE(service_B_js_service_B_js, service_B, "/js/service-B.js", service_B_js_service_B_js_gzip_data);

