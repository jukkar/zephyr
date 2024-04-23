/*
 * Copyright (c) 2023, Emna Rekik
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef HTTP_SERVER_INTERNAL_H_
#define HTTP_SERVER_INTERNAL_H_

#include <stdbool.h>

#include <zephyr/net/http/server.h>
#include <zephyr/net/http/service.h>
#include <zephyr/net/http/status.h>
#include <zephyr/net/http/hpack.h>
#include <zephyr/net/http/frame.h>

#define HTTP_SERVER_MAX_SERVICES CONFIG_HTTP_NUM_SERVICES
#define HTTP_SERVER_MAX_CLIENTS  CONFIG_HTTP_SERVER_MAX_CLIENTS
#define HTTP_SERVER_SOCK_COUNT (1 + HTTP_SERVER_MAX_SERVICES + HTTP_SERVER_MAX_CLIENTS)

struct http_server_ctx {
	int num_clients;
	int listen_fds;   /* max value of 1 + MAX_SERVICES */

	/* First pollfd is eventfd that can be used to stop the server,
	 * then we have the server listen sockets,
	 * and then the accepted sockets.
	 */
	struct zsock_pollfd fds[HTTP_SERVER_SOCK_COUNT];
	struct http_client_ctx clients[HTTP_SERVER_MAX_CLIENTS];
};

/* HTTP1/HTTP2 state handling */
int handle_http_frame_rst_frame(struct http_server_ctx *server,
				struct http_client_ctx *client);
int handle_http_frame_goaway(struct http_server_ctx *server,
			     struct http_client_ctx *client);
int handle_http_frame_settings(struct http_client_ctx *client);
int handle_http_frame_priority(struct http_client_ctx *client);
int handle_http_frame_continuation(struct http_client_ctx *client);
int handle_http_frame_window_update(struct http_client_ctx *client);
int handle_http_frame_header(struct http_server_ctx *server,
			     struct http_client_ctx *client);
int handle_http_frame_headers(struct http_client_ctx *client);
int handle_http_frame_data(struct http_client_ctx *client);
int handle_http1_request(struct http_server_ctx *server,
			 struct http_client_ctx *client);
int handle_http1_to_http2_upgrade(struct http_server_ctx *server,
				  struct http_client_ctx *client);

int enter_http1_request(struct http_client_ctx *client);
int enter_http2_request(struct http_client_ctx *client);
int enter_http_done_state(struct http_server_ctx *server,
			  struct http_client_ctx *client);

/* Others */
struct http_resource_detail *get_resource_detail(const char *path, int *len);
int http_server_sendall(struct http_client_ctx *client, const void *buf, size_t len);
void http_client_timer_restart(struct http_client_ctx *client);

/* TODO Could be static, but currently used in tests. */
int parse_http_frame_header(struct http_client_ctx *client);
const char *get_frame_type_name(enum http_frame_type type);

#endif /* HTTP_SERVER_INTERNAL_H_ */
