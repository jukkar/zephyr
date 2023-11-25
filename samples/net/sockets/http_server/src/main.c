/*
 * Copyright (c) 2023, Emna Rekik
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>

#include <zephyr/kernel.h>
#include <zephyr/net/tls_credentials.h>
#include <zephyr/net/http/server.h>
#include <zephyr/net/http/service.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/socket.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(net_http_server_sample, LOG_LEVEL_DBG);

static uint8_t index_html_gz[] = {
#include "index.html.gz.inc"
};

#if defined(CONFIG_NET_SAMPLE_HTTP_SERVICE)
static uint16_t test_http_service_port = CONFIG_NET_SAMPLE_HTTP_SERVER_SERVICE_PORT;
HTTP_SERVICE_DEFINE(test_http_service, CONFIG_NET_CONFIG_MY_IPV4_ADDR, &test_http_service_port, 1,
		    10, NULL);

struct http_resource_detail_static index_html_gz_resource_detail = {
	.common = {
			.type = HTTP_RESOURCE_TYPE_STATIC,
			.bitmask_of_supported_http_methods = BIT(HTTP_GET),
		},
	.static_data = index_html_gz,
	.static_data_len = sizeof(index_html_gz),
};

HTTP_RESOURCE_DEFINE(index_html_gz_resource, test_http_service, "/",
		     &index_html_gz_resource_detail);

static uint8_t recv_buffer[1024];

static int dyn1_handler(struct http_client_ctx *client,
			uint8_t *buffer, size_t len, void *user_data)
{
#define MAX_TEMP_PRINT_LEN 32
	static char print_str[MAX_TEMP_PRINT_LEN];
	static int counter;
	enum http_method method = client->parser.method;

	int ret;

	__ASSERT_NO_MSG(buffer != NULL);

	if (len == 0) {
		LOG_DBG("All data received.");
	} else {
		snprintf(print_str, sizeof(print_str), "%s received (%d bytes)", http_method_str(method), len);
		LOG_HEXDUMP_DBG(buffer, len, print_str);
	}

	switch (counter) {
	case 0:
		counter++;
		ret = snprintk(recv_buffer, sizeof(recv_buffer), "Sending some");
		return ret;

	case 1:
		counter++;
		ret = snprintk(recv_buffer, sizeof(recv_buffer), "buffer data");
		return ret;

	case 2:
		counter = 0;
		break;
	}

	return 0;
}

struct http_resource_detail_dynamic dyn1_resource_detail = {
	.common = {
		.type = HTTP_RESOURCE_TYPE_DYNAMIC,
		.bitmask_of_supported_http_methods =
				BIT(HTTP_GET) | BIT(HTTP_POST),
	},
	.cb = dyn1_handler,
	.data_buffer = recv_buffer,
	.data_buffer_len = sizeof(recv_buffer),
	.user_data = NULL,
};

HTTP_RESOURCE_DEFINE(dyn1_resource, test_http_service, "/dynamic",
		     &dyn1_resource_detail);

struct http_resource_detail_rest add_two_numbers_detail = {
	.common = {
			.type = HTTP_RESOURCE_TYPE_REST,
			.bitmask_of_supported_http_methods = BIT(HTTP_POST),
		},
};

HTTP_RESOURCE_DEFINE(add_two_numbers, test_http_service, "/add", &add_two_numbers_detail);
#endif /* CONFIG_NET_SAMPLE_HTTP_SERVICE */

#if defined(CONFIG_NET_SAMPLE_HTTPS_SERVICE)
#include "certificate.h"

static const sec_tag_t sec_tag_list_verify_none[] = {
		HTTP_SERVER_CERTIFICATE_TAG,
#if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
		PSK_TAG,
#endif
	};

static uint16_t test_https_service_port = CONFIG_NET_SAMPLE_HTTPS_SERVER_SERVICE_PORT;
HTTPS_SERVICE_DEFINE(test_https_service, CONFIG_NET_CONFIG_MY_IPV4_ADDR, \
		     &test_https_service_port, 1, 10, NULL,		\
		     sec_tag_list_verify_none, sizeof(sec_tag_list_verify_none));

static struct http_resource_detail_static index_html_gz_resource_detail_https = {
	.common = {
			.type = HTTP_RESOURCE_TYPE_STATIC,
			.bitmask_of_supported_http_methods = BIT(HTTP_GET),
		},
	.static_data = index_html_gz,
	.static_data_len = sizeof(index_html_gz),
};

HTTP_RESOURCE_DEFINE(index_html_gz_resource_https, test_https_service, "/",
		     &index_html_gz_resource_detail_https);

#endif /* CONFIG_NET_SAMPLE_HTTPS_SERVICE */

static void setup_tls(void)
{
#if defined(CONFIG_NET_SAMPLE_HTTPS_SERVICE)
#if defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS)
	int err;

#if defined(CONFIG_NET_SAMPLE_CERTS_WITH_SC)
	err = tls_credential_add(HTTP_SERVER_CERTIFICATE_TAG,
				 TLS_CREDENTIAL_CA_CERTIFICATE,
				 ca_certificate,
				 sizeof(ca_certificate));
	if (err < 0) {
		LOG_ERR("Failed to register CA certificate: %d", err);
	}
#endif /* defined(CONFIG_NET_SAMPLE_CERTS_WITH_SC) */

	err = tls_credential_add(HTTP_SERVER_CERTIFICATE_TAG,
				 TLS_CREDENTIAL_SERVER_CERTIFICATE,
				 server_certificate,
				 sizeof(server_certificate));
	if (err < 0) {
		LOG_ERR("Failed to register public certificate: %d", err);
	}

	err = tls_credential_add(HTTP_SERVER_CERTIFICATE_TAG,
				 TLS_CREDENTIAL_PRIVATE_KEY,
				 private_key, sizeof(private_key));
	if (err < 0) {
		LOG_ERR("Failed to register private key: %d", err);
	}

#if defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED)
	err = tls_credential_add(PSK_TAG,
				 TLS_CREDENTIAL_PSK,
				 psk,
				 sizeof(psk));
	if (err < 0) {
		LOG_ERR("Failed to register PSK: %d", err);
	}

	err = tls_credential_add(PSK_TAG,
				 TLS_CREDENTIAL_PSK_ID,
				 psk_id,
				 sizeof(psk_id) - 1);
	if (err < 0) {
		LOG_ERR("Failed to register PSK ID: %d", err);
	}
#endif /* defined(CONFIG_MBEDTLS_KEY_EXCHANGE_PSK_ENABLED) */
#endif /* defined(CONFIG_NET_SOCKETS_SOCKOPT_TLS) */
#endif /* defined(CONFIG_NET_SAMPLE_HTTPS_SERVICE) */
}

int main(void)
{
	struct http_server_ctx ctx;
	int server_fd;

	setup_tls();

	server_fd = http_server_init(&ctx);
	if (server_fd < 0) {
		printf("Failed to initialize HTTP2 server\n");
		return server_fd;
	}

	http_server_start(&ctx);

	return 0;
}
