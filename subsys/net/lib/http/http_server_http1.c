/*
 * Copyright (c) 2023, Emna Rekik
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/net/http/service.h>

LOG_MODULE_DECLARE(net_http_server, CONFIG_NET_HTTP_SERVER_LOG_LEVEL);

#include "headers/server_functions.h"

#define TEMP_BUF_LEN 64

static const char final_chunk[] = "0\r\n\r\n";
static const char *crlf = &final_chunk[3];

static int handle_http1_static_resource(
	struct http_resource_detail_static *static_detail, int client_fd)
{
#define RESPONSE_TEMPLATE			\
	"HTTP/1.1 200 OK\r\n"			\
	"Content-Type: text/html\r\n"		\
	"Content-Length: %d\r\n"

	/* Add couple of bytes to total response */
	char http_response[sizeof(RESPONSE_TEMPLATE) +
			   sizeof("Content-Encoding: 01234567890123456789\r\n") +
			   sizeof("xxxx") +
			   sizeof("\r\n")];
	const char *data;
	int len;
	int ret;

	if (static_detail->common.bitmask_of_supported_http_methods & BIT(HTTP_GET)) {
		data = static_detail->static_data;
		len = static_detail->static_data_len;

		if (static_detail->common.content_encoding != NULL &&
		    static_detail->common.content_encoding[0] != '\0') {
			snprintk(http_response, sizeof(http_response),
				 RESPONSE_TEMPLATE "Content-Encoding: %s\r\n\r\n",
				 len, static_detail->common.content_encoding);
		} else {
			snprintk(http_response, sizeof(http_response),
				 RESPONSE_TEMPLATE "\r\n", len);
		}

		ret = http_server_sendall(client_fd, http_response,
					  strlen(http_response));
		if (ret < 0) {
			return ret;
		}

		ret = http_server_sendall(client_fd, data, len);
		if (ret < 0) {
			return ret;
		}
	}

	return 0;
}

#define RESPONSE_TEMPLATE_CHUNKED			\
	"HTTP/1.1 200 OK\r\n"				\
	"Content-Type: text/html\r\n"			\
	"Transfer-Encoding: chunked\r\n\r\n"

#define RESPONSE_TEMPLATE_DYNAMIC			\
	"HTTP/1.1 200 OK\r\n"				\
	"Content-Type: text/html\r\n\r\n"		\

static int dynamic_get_req(struct http_resource_detail_dynamic *dynamic_detail,
			   struct http_client_ctx *client)
{
	/* offset tells from where the GET params start */
	int ret, remaining, offset = dynamic_detail->common.path_len;
	char *ptr;
	char tmp[TEMP_BUF_LEN];

	ret = http_server_sendall(client->fd, RESPONSE_TEMPLATE_CHUNKED,
				  sizeof(RESPONSE_TEMPLATE_CHUNKED) - 1);
	if (ret < 0) {
		return ret;
	}

	remaining = strlen(&client->url_buffer[dynamic_detail->common.path_len]);

	/* Pass URL to the client */
	while (1) {
		int copy_len, send_len;

		ptr = &client->url_buffer[offset];
		copy_len = MIN(remaining, dynamic_detail->data_buffer_len);

		memcpy(dynamic_detail->data_buffer, ptr, copy_len);

again:
		send_len = dynamic_detail->cb(client, dynamic_detail->data_buffer,
					      copy_len, dynamic_detail->user_data);
		if (send_len > 0) {
			ret = snprintk(tmp, sizeof(tmp), "%x\r\n", send_len);
			ret = http_server_sendall(client->fd, tmp, ret);
			if (ret < 0) {
				return ret;
			}

			ret = http_server_sendall(client->fd,
						  dynamic_detail->data_buffer,
						  send_len);
			if (ret < 0) {
				return ret;
			}

			(void)http_server_sendall(client->fd, crlf, 2);

			offset += copy_len;
			remaining -= copy_len;

			/* If we have passed all the data to the application,
			 * then just pass empty buffer to it.
			 */
			if (remaining == 0) {
				copy_len = 0;
				goto again;
			}

			continue;
		}

		break;
	}

	ret = http_server_sendall(client->fd, final_chunk,
				  sizeof(final_chunk) - 1);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

static int dynamic_post_req(struct http_resource_detail_dynamic *dynamic_detail,
			    struct http_client_ctx *client)
{
	/* offset tells from where the POST params start */
	char *start = strstr(client->buffer, "\r\n\r\n");
	int ret, remaining, offset = 0;
	char *ptr;
	char tmp[TEMP_BUF_LEN];

	if (start == NULL) {
		return -ENOENT;
	}

	ret = http_server_sendall(client->fd, RESPONSE_TEMPLATE_CHUNKED,
		      sizeof(RESPONSE_TEMPLATE_CHUNKED) - 1);
	if (ret < 0) {
		return ret;
	}

	start += 4; /* skip \r\n\r\n */
	remaining = strlen(start);

	while (1) {
		int copy_len, send_len;

		ptr = &start[offset];
		copy_len = MIN(remaining, dynamic_detail->data_buffer_len);

		memcpy(dynamic_detail->data_buffer, ptr, copy_len);

again:
		send_len = dynamic_detail->cb(client, dynamic_detail->data_buffer,
					      copy_len, dynamic_detail->user_data);
		if (send_len > 0) {
			ret = snprintk(tmp, sizeof(tmp), "%x\r\n", send_len);
			ret = http_server_sendall(client->fd, tmp, ret);
			if (ret < 0) {
				return ret;
			}

			ret = http_server_sendall(client->fd,
						  dynamic_detail->data_buffer,
						  send_len);
			if (ret < 0) {
				return ret;
			}

			(void)http_server_sendall(client->fd, crlf, 2);

			offset += copy_len;
			remaining -= copy_len;

			/* If we have passed all the data to the application,
			 * then just pass empty buffer to it.
			 */
			if (remaining == 0) {
				copy_len = 0;
				goto again;
			}

			continue;
		}

		break;
	}

	ret = http_server_sendall(client->fd, final_chunk,
				  sizeof(final_chunk) - 1);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

static int handle_http1_dynamic_resource(
	struct http_resource_detail_dynamic *dynamic_detail,
	struct http_client_ctx *client)
{
	uint32_t user_method;
	int ret;

	if (dynamic_detail->cb == NULL) {
		return -ESRCH;
	}

	user_method = dynamic_detail->common.bitmask_of_supported_http_methods;

	if (!(BIT(client->method) & user_method)) {
		return -ENOPROTOOPT;
	}

	switch (client->method) {
	case HTTP_HEAD:
		if (user_method & BIT(HTTP_HEAD)) {
			ret = http_server_sendall(
					client->fd, RESPONSE_TEMPLATE_DYNAMIC,
					sizeof(RESPONSE_TEMPLATE_DYNAMIC) - 1);
			if (ret < 0) {
				return ret;
			}

			return 0;
		}

	case HTTP_GET:
		/* For GET request, we do not pass any data to the app but let the app
		 * send data to the peer.
		 */
		if (user_method & BIT(HTTP_GET)) {
			return dynamic_get_req(dynamic_detail, client);
		}

		goto not_supported;

	case HTTP_POST:
		if (user_method & BIT(HTTP_POST)) {
			return dynamic_post_req(dynamic_detail, client);
		}

		goto not_supported;

not_supported:
	default:
		LOG_DBG("HTTP method %s (%d) not supported.",
			http_method_str(client->method),
			client->method);

		return -ENOTSUP;
	}

	return 0;
}

static int on_header_field(struct http_parser *parser, const char *at,
			   size_t length)
{
	struct http_client_ctx *ctx = CONTAINER_OF(parser,
						   struct http_client_ctx,
						   parser);

	ctx->parser_header_state = HTTP1_RECEIVING_HEADER_STATE;

	if (length == 7 && strncasecmp(at, "Upgrade", length) == 0) {
		LOG_DBG("The \"Upgrade: h2c\" header is present.");
		ctx->has_upgrade_header = true;
	}

	return 0;
}

static int on_headers_complete(struct http_parser *parser)
{
	struct http_client_ctx *ctx = CONTAINER_OF(parser,
						   struct http_client_ctx,
						   parser);

	ctx->parser_header_state = HTTP1_RECEIVED_HEADER_STATE;

	return 0;
}

static int on_url(struct http_parser *parser, const char *at, size_t length)
{
	struct http_client_ctx *ctx = CONTAINER_OF(parser,
						   struct http_client_ctx,
						   parser);

	ctx->parser_header_state = HTTP1_WAITING_HEADER_STATE;

	strncpy(ctx->url_buffer, at, length);
	ctx->url_buffer[length] = '\0';
	LOG_DBG("Requested URL: %s", ctx->url_buffer);
	return 0;
}

int enter_http1_request(struct http_client_ctx *client)
{
	client->server_state = HTTP_SERVER_REQUEST_STATE;

	http_parser_init(&client->parser, HTTP_REQUEST);
	http_parser_settings_init(&client->parser_settings);

	client->parser_settings.on_header_field = on_header_field;
	client->parser_settings.on_headers_complete = on_headers_complete;
	client->parser_settings.on_url = on_url;
	client->parser_header_state = HTTP1_INIT_HEADER_STATE;

	return 0;
}

int handle_http1_request(struct http_server_ctx *server, struct http_client_ctx *client)
{
	int ret, path_len = 0;
	struct http_resource_detail *detail;

	LOG_DBG("HTTP_SERVER_REQUEST");


	http_parser_execute(&client->parser, &client->parser_settings,
			    client->cursor, client->data_len);

	if (client->parser.http_errno != HPE_OK) {
		LOG_ERR("HTTP/1 parsing error, %d", client->parser.http_errno);
		return -EBADMSG;
	}

	if (client->parser_header_state != HTTP1_RECEIVED_HEADER_STATE) {
		return 0;
	}

	client->method = client->parser.method;

	if (client->has_upgrade_header) {
		return handle_http1_to_http2_upgrade(server, client);
	}

	detail = get_resource_detail(client->url_buffer, &path_len);
	if (detail != NULL) {
		detail->path_len = path_len;

		if (detail->type == HTTP_RESOURCE_TYPE_STATIC) {
			ret = handle_http1_static_resource(
				(struct http_resource_detail_static *)detail,
				client->fd);
			if (ret < 0) {
				return ret;
			}
		} else if (detail->type == HTTP_RESOURCE_TYPE_DYNAMIC) {
			ret = handle_http1_dynamic_resource(
				(struct http_resource_detail_dynamic *)detail,
				client);
			if (ret < 0) {
				return ret;
			}
		}
	} else {
		static const char not_found_response[] =
			"HTTP/1.1 404 Not Found\r\n"
			"Content-Length: 9\r\n\r\n"
			"Not Found";

		ret = http_server_sendall(client->fd, not_found_response,
					  sizeof(not_found_response) - 1);
		if (ret < 0) {
			LOG_DBG("Cannot write to socket (%d)", ret);
			return ret;
		}
	}

	LOG_DBG("Connection closed client #%zd", ARRAY_INDEX(server->clients, client));

	client->cursor += client->data_len;
	client->data_len = 0;

	enter_http_done_state(server, client);

	return 0;
}
