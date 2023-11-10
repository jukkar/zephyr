/*
 * Copyright (c) 2023, Meta
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>

#include <zephyr/net/http/client.h>
#include <zephyr/net/socket.h>
#include <zephyr/ztest.h>

static int sock_A;
static int sock_B;
static struct http_request req;
static uint8_t buf[CONFIG_TEST_BUF_SIZE];
static char port_str[sizeof("65535")];

void http_client_req_create(const char *url, uint16_t port, http_response_cb_t cb)
{
	snprintf(port_str, sizeof(port_str), "%u", port);

	req = (struct http_request){
		.method = HTTP_GET,
		.url = url,
		.host = CONFIG_NET_CONFIG_MY_IPV4_ADDR,
		.protocol = CONFIG_TEST_SERVER_PROTO,
		.response = cb,
		.recv_buf = buf,
		.recv_buf_len = sizeof(buf),
		.port = port_str,
	};
}

static const struct http_service_desc *http_service_get_by_port(uint16_t port)
{
	const struct http_service_desc *svc;

	HTTP_SERVICE_FOREACH(svc)
	{
		if (*svc->port == port) {
			return svc;
		}
	}

	return NULL;
}

static const struct http_service_desc *
http_service_get_resource(const struct http_service_desc *scv, const char *resource)
{
	const struct http_resource_desc *res;
	HTTP_SERVICE_FOREACH_RESOURCE(svc, res)
	{
		if (strcmp(res->resource, resource) == 0) {
			return res;
		}
	}

	return NULL;
}

static void common(uint16_t port, size_t n_res, const char **const urn, const uint8_t *data,
		   size_t size)
{
	const struct http_service_desc *svc;
	const struct http_resource_desc *res;

	svc = http_service_get_by_port();
	zassert_not_null(svc);
}

ZTEST(http_server_CRiMe, test_service_A)
{
	static const char *const urn[] = {
		"/index.html",
		"/js/service-A.js",
		"/error-pages/four-zero-four.html",
		"/css/service-A.css",
	};
	uint8_t *data[ARRAY_SIZE(urn)] = {0};
	size_t size[ARRAY_SIZE(urn)] = {0};

	common("service_A", ARRAY_SIZE(urn), urn, data, size);
}

ZTEST(http_server_CRiMe, test_service_B)
{
	static const char *const urn[] = {
		"/index.html",
		"/js/service-B.js",
		"/status-pages/404.htm",
		"/css/service-B.css",
	};
	uint8_t *data[ARRAY_SIZE(urn)] = {0};
	size_t size[ARRAY_SIZE(urn)] = {0};

	common("service_B", ARRAY_SIZE(urn), urn, data, size);
}

static void before(void *arg)
{
	int ret;
	struct addrinfo *res;
	struct addrinfo hints;

	ARG_UNUSED(arg);

	memset(buf, 0, sizeof(buf));

	hints = (struct addrinfo){
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_NUMERICSERV,
	};
	ret = getaddrinfo(CONFIG_NET_CONFIG_MY_IPV4_ADDR, STRINGIFY(CONFIG_TEST_SERVER_A_PORT),
								    &hints, &res);
	zassert_ok(ret, "getaddrinfo() failed with code %d (errno %d)", ret, errno);
	sock_A = zsock_socket(AF_INET, res->ai_socktype, res->ai_protocol);
	zassert_true(sock_A >= 0);
	zassert_true(zsock_connect(sock_A, res->ai_addr, res->ai_addrlen));
	freeaddrinfo(res);

	hints = (struct addrinfo){
		.ai_family = AF_INET,
		.ai_socktype = SOCK_STREAM,
		.ai_flags = AI_NUMERICSERV,
	};
	ret = getaddrinfo(CONFIG_NET_CONFIG_MY_IPV4_ADDR, STRINGIFY(CONFIG_TEST_SERVER_B_PORT),
								    &hints, &res);
	zassert_ok(ret, "getaddrinfo() failed with code %d (errno %d)", ret, errno);
	sock_B = zsock_socket(AF_INET, res->ai_socktype, res->ai_protocol);
	zassert_true(sock_B >= 0);
	zassert_true(zsock_connect(sock_B, res->ai_addr, res->ai_addrlen));
	freeaddrinfo(res);
}

static void after(void *arg)
{
	ARG_UNUSED(arg);
}

static void *setup(void)
{

	return NULL;
}

static void teardown(void *arg)
{
	ARG_UNUSED(arg);

	zsock_close(sock_A);
	sock_A = -1;

	zsock_close(sock_B);
	sock_B = -1;
}

ZTEST_SUITE(http_server_CRiMe, NULL, setup, before, after, NULL);
