/*
 * Copyright (c) 2017 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(CONFIG_NET_DEBUG_HTTP_APP)
#define SYS_LOG_DOMAIN "http-app"
#define NET_SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define NET_LOG_ENABLED 1
#endif

#include <zephyr.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdlib.h>
#include <version.h>

#include <net/net_core.h>
#include <net/net_ip.h>
#include <net/http.h>

#if defined(CONFIG_HTTP_LEGACY_SERVER)
#error "Select either CONFIG_HTTP_LEGACY_SERVER or CONFIG_HTTP_APP_SERVER "\
	"but not both."
#endif

#if defined(CONFIG_WEBSOCKET)
#include <net/websocket.h>
#endif

#define BUF_ALLOC_TIMEOUT 100

#define HTTP_DEFAULT_PORT  80
#define HTTPS_DEFAULT_PORT 443

#define RC_STR(rc)	(rc == 0 ? "OK" : "ERROR")

#define HTTP_STATUS_200_OK	"HTTP/1.1 200 OK\r\n" \
				"Content-Type: text/html\r\n" \
				"Transfer-Encoding: chunked\r\n" \
				"\r\n"

#define HTTP_STATUS_400_BR	"HTTP/1.1 400 Bad Request\r\n" \
				"\r\n"

#define HTTP_STATUS_403_FBD	"HTTP/1.1 403 Forbidden\r\n" \
				"\r\n"

#define HTTP_STATUS_404_NF	"HTTP/1.1 404 Not Found\r\n" \
				"\r\n"

#define HTTP_CRLF "\r\n"

#if defined(CONFIG_NET_DEBUG_HTTP_CONN)
/** List of http connections */
static sys_slist_t http_conn;

static http_server_cb_t ctx_mon;
static void *mon_user_data;

static void http_server_conn_add(struct http_ctx *ctx)
{
	sys_slist_prepend(&http_conn, &ctx->node);

	if (ctx_mon) {
		ctx_mon(ctx, mon_user_data);
	}
}

static void http_server_conn_del(struct http_ctx *ctx)
{
	sys_slist_find_and_remove(&http_conn, &ctx->node);
}

void http_server_conn_foreach(http_server_cb_t cb, void *user_data)
{
	struct http_ctx *ctx;

	SYS_SLIST_FOR_EACH_CONTAINER(&http_conn, ctx, node) {
		cb(ctx, user_data);
	}
}

void http_server_conn_monitor(http_server_cb_t cb, void *user_data)
{
	ctx_mon = cb;
	mon_user_data = user_data;
}

#else
static inline void http_server_conn_add(struct http_ctx *ctx) {}
static inline void http_server_conn_del(struct http_ctx *ctx) {}
#endif /* CONFIG_NET_DEBUG_HTTP_CONN */

const char * const http_state_str(enum http_state state)
{
#if defined(CONFIG_NET_DEBUG_HTTP)
	switch (state) {
	case HTTP_STATE_CLOSED:
		return "CLOSED";
	case HTTP_STATE_WAITING_HEADER:
		return "WAITING_HEADER";
	case HTTP_STATE_RECEIVING_HEADER:
		return "RECEIVING HEADER";
	case HTTP_STATE_HEADER_RECEIVED:
		return "HEADER_RECEIVED";
	case HTTP_STATE_OPEN:
		return "OPEN";
	}
#else /* CONFIG_NET_DEBUG_HTTP */
	ARG_UNUSED(state);
#endif /* CONFIG_NET_DEBUG_HTTP */

	return "";
}

#if defined(CONFIG_NET_DEBUG_HTTP)
static void validate_state_transition(struct http_ctx *ctx,
				      enum http_state current,
				      enum http_state new)
{
	static const u16_t valid_transitions[] = {
		[HTTP_STATE_CLOSED] = 1 << HTTP_STATE_WAITING_HEADER,
		[HTTP_STATE_WAITING_HEADER] =
					1 << HTTP_STATE_RECEIVING_HEADER |
					1 << HTTP_STATE_CLOSED,
		[HTTP_STATE_RECEIVING_HEADER] =
					1 << HTTP_STATE_HEADER_RECEIVED |
					1 << HTTP_STATE_CLOSED |
					1 << HTTP_STATE_OPEN,
		[HTTP_STATE_HEADER_RECEIVED] =
					1 << HTTP_STATE_OPEN |
					1 << HTTP_STATE_CLOSED,
		[HTTP_STATE_OPEN] = 1 << HTTP_STATE_CLOSED,
	};

	if (!(valid_transitions[current] & 1 << new)) {
		NET_DBG("[%p] Invalid state transition: %s (%d) => %s (%d)",
			ctx, http_state_str(current), current,
			http_state_str(new), new);
	}
}
#endif /* CONFIG_NET_DEBUG_HTTP */

void _http_change_state(struct http_ctx *ctx,
			enum http_state new_state,
			const char *func, int line)
{
	if (ctx->state == new_state) {
		return;
	}

	NET_ASSERT(new_state >= HTTP_STATE_CLOSED &&
		   new_state <= HTTP_STATE_OPEN);

	NET_DBG("[%p] state %s (%d) => %s (%d) [%s():%d]",
		ctx, http_state_str(ctx->state), ctx->state,
		http_state_str(new_state), new_state,
		func, line);

#if defined(CONFIG_NET_DEBUG_HTTP)
	validate_state_transition(ctx, ctx->state, new_state);
#endif /* CONFIG_NET_DEBUG_HTTP */

	ctx->state = new_state;
}

static inline u16_t http_strlen(const char *str)
{
	if (str) {
		return strlen(str);
	}

	return 0;
}

static int _http_add_header(struct net_pkt *pkt, s32_t timeout,
			    const char *str)
{
	if (net_pkt_append_all(pkt, strlen(str), (u8_t *)str, timeout)) {
		return 0;
	}

	return -ENOMEM;
}

static int _http_add_chunk(struct net_pkt *pkt, s32_t timeout,
			   const u8_t *buf, size_t len)
{
	char chunk_header[16];
	bool ret;

	if (!buf) {
		len = 0;
	}

	snprintk(chunk_header, sizeof(chunk_header), "%x" HTTP_CRLF,
		 (unsigned int)len);

	ret = net_pkt_append_all(pkt, strlen(chunk_header), chunk_header,
				 timeout);
	if (!ret) {
		return -ENOMEM;
	}

	if (len) {
		ret = net_pkt_append_all(pkt, len, buf, timeout);
		if (!ret) {
			return -ENOMEM;
		}
	}

	ret = net_pkt_append_all(pkt, sizeof(HTTP_CRLF) - 1, HTTP_CRLF,
				 timeout);
	if (!ret) {
		return -ENOMEM;
	}

	return 0;
}

static void http_data_sent(struct net_app_ctx *app_ctx,
			   int status,
			   void *user_data_send,
			   void *user_data)
{
	struct http_ctx *ctx = user_data;

	if (!user_data_send) {
		/* This is the token field in the net_context_send().
		 * If this is not set, then it is TCP ACK messages
		 * that are generated by the stack. We just ignore those.
		 */
		return;
	}

	if (ctx->state == HTTP_STATE_OPEN && ctx->cb.send) {
		ctx->cb.send(ctx, status, user_data_send, ctx->user_data);
	}
}

int http_send_error(struct http_ctx *ctx, int code,
		    u8_t *html_payload, size_t html_len)
{
	struct net_pkt *pkt = NULL;
	const char *msg;
	int ret;

	switch (code) {
	case 400:
		msg = HTTP_STATUS_400_BR;
		break;
	}

	ret = http_add_header(ctx, &pkt, msg);
	if (!ret) {
		return ret;
	}

	if (html_payload) {
		ret = http_add_data(ctx, &pkt, html_payload, html_len);
		if (!ret) {
			net_pkt_unref(pkt);
			return ret;
		}
	}

	return http_send_data(ctx, pkt, NULL);
}

int http_send_msg_raw(struct http_ctx *ctx, struct net_pkt *pkt,
		      void *user_send_data)
{
	int ret;

	NET_DBG("[%p] Sending %zd bytes data", ctx, net_pkt_get_len(pkt));

	ret = net_app_send_pkt(&ctx->app_ctx, pkt, NULL, 0, 0,
			       user_send_data);
	if (!ret) {
		/* We must let the system to send the packet, otherwise TCP
		 * might timeout before the packet is actually sent. This is
		 * easily seen if the application calls this functions many
		 * times in a row.
		 */
		k_yield();
	}

	return ret;
}

int http_add_header(struct http_ctx *ctx, struct net_pkt **pkt,
		    const char *http_header)
{
	if (!pkt) {
		return -EINVAL;
	}

	if (!*pkt) {
		*pkt = net_app_get_net_pkt(&ctx->app_ctx, AF_UNSPEC,
					   ctx->timeout);
		if (!*pkt) {
			return -ENOMEM;
		}
	}

	return _http_add_header(*pkt, ctx->timeout, http_header);
}

int http_add_data(struct http_ctx *ctx, struct net_pkt **pkt,
		  const u8_t *buf, size_t len)
{
	if (!pkt) {
		return -EINVAL;
	}

	if (!*pkt) {
		*pkt = net_app_get_net_pkt(&ctx->app_ctx, AF_UNSPEC,
					   ctx->timeout);
		if (!*pkt) {
			return -ENOMEM;
		}
	}

	return _http_add_chunk(*pkt, ctx->timeout, buf, len);
}

#if defined(CONFIG_NET_DEBUG_HTTP) && (CONFIG_SYS_LOG_NET_LEVEL > 2)
static char *sprint_ipaddr(char *buf, int buflen, const struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET6) {
#if defined(CONFIG_NET_IPV6)
		char ipaddr[NET_IPV6_ADDR_LEN];

		net_addr_ntop(addr->sa_family,
			      &net_sin6(addr)->sin6_addr,
			      ipaddr, sizeof(ipaddr));
		snprintk(buf, buflen, "[%s]:%u", ipaddr,
			 ntohs(net_sin6(addr)->sin6_port));
#endif
	} else if (addr->sa_family == AF_INET) {
#if defined(CONFIG_NET_IPV4)
		char ipaddr[NET_IPV4_ADDR_LEN];

		net_addr_ntop(addr->sa_family,
			      &net_sin(addr)->sin_addr,
			      ipaddr, sizeof(ipaddr));
		snprintk(buf, buflen, "%s:%u", ipaddr,
			 ntohs(net_sin(addr)->sin_port));
#endif
	} else {
		snprintk(buf, buflen, "<invalid address family %d>",
			 addr->sa_family);
	}

	return buf;
}

static struct net_context *get_server_ctx(struct net_app_ctx *ctx,
					  const struct sockaddr *dst)
{
	int i;

	for (i = 0; i < CONFIG_NET_APP_SERVER_NUM_CONN; i++) {
		struct net_context *tmp;
		u16_t port, rport;

		if (!ctx->server.net_ctxs[i]) {
			continue;
		}

		tmp = ctx->server.net_ctxs[i];

		if (IS_ENABLED(CONFIG_NET_IPV4) &&
		    tmp->remote.sa_family == AF_INET &&
		    dst->sa_family == AF_INET) {
			struct in_addr *addr4 = &net_sin(dst)->sin_addr;
			struct in_addr *remote4;

			remote4 = &net_sin(&tmp->remote)->sin_addr;
			rport = net_sin(&tmp->remote)->sin_port;
			port = net_sin(dst)->sin_port;

			if (net_ipv4_addr_cmp(addr4, remote4) &&
			    port == rport) {
				return tmp;
			}

		} else if (IS_ENABLED(CONFIG_NET_IPV6) &&
			   tmp->remote.sa_family == AF_INET6 &&
			   dst->sa_family == AF_INET6) {
			struct in6_addr *addr6 = &net_sin6(dst)->sin6_addr;
			struct in6_addr *remote6;

			remote6 = &net_sin6(&tmp->remote)->sin6_addr;
			rport = net_sin6(&tmp->remote)->sin6_port;
			port = net_sin6(dst)->sin6_port;

			if (net_ipv6_addr_cmp(addr6, remote6) &&
			    port == rport) {
				return tmp;
			}
		}
	}

	return NULL;
}
#endif /* CONFIG_NET_DEBUG_HTTP */

static inline void new_client(struct http_ctx *ctx,
			      enum http_connection_type type,
			      struct net_app_ctx *app_ctx)
{
#if defined(CONFIG_NET_DEBUG_HTTP) && (CONFIG_SYS_LOG_NET_LEVEL > 2)
#if defined(CONFIG_NET_IPV6)
#define PORT_LEN sizeof("[]:xxxxx")
#define ADDR_LEN NET_IPV6_ADDR_LEN
#elif defined(CONFIG_NET_IPV4)
#define PORT_LEN sizeof(":xxxxx")
#define ADDR_LEN NET_IPV4_ADDR_LEN
#endif
	char buf[ADDR_LEN + PORT_LEN];
	struct net_context *net_ctx;
	const char *type_str = "HTTP";

	if (type == WS_CONNECTION) {
		type_str = "WS";
	}

	net_ctx = get_server_ctx(app_ctx, ctx->addr);
	if (net_ctx) {
		NET_INFO("[%p] %s connection from %s (%p)", ctx, type_str,
			 sprint_ipaddr(buf, sizeof(buf), &net_ctx->remote),
			 net_ctx);
	} else {
		NET_INFO("[%p] %s connection", ctx, type_str);
	}
#endif /* CONFIG_NET_DEBUG_HTTP */
}

static void url_connected(struct http_ctx *ctx,
			  enum http_connection_type type)
{
	new_client(ctx, type, &ctx->app_ctx);

	if (ctx->cb.connect) {
		ctx->cb.connect(ctx, type, ctx->user_data);
	}
}

struct http_root_url *http_server_add_url(struct http_server_urls *my,
					  const char *url, u8_t flags)
{
	int i;

	for (i = 0; i < CONFIG_HTTP_SERVER_NUM_URLS; i++) {
		if (my->urls[i].is_used) {
			continue;
		}

		my->urls[i].is_used = true;
		my->urls[i].root = url;

		/* This will speed-up some future operations */
		my->urls[i].root_len = strlen(url);
		my->urls[i].flags = flags;

		NET_DBG("[%d] %s URL %s", i,
			flags == HTTP_URL_HTTP ? "HTTP" : "WS", url);

		return &my->urls[i];
	}

	return NULL;
}

int http_server_del_url(struct http_server_urls *my, const char *url)
{
	int i;

	for (i = 0; i < CONFIG_HTTP_SERVER_NUM_URLS; i++) {
		if (!my->urls[i].is_used) {
			continue;
		}

		if (strncmp(my->urls[i].root, url, my->urls[i].root_len)) {
			continue;
		}

		my->urls[i].is_used = false;
		my->urls[i].root = NULL;

		return 0;
	}

	return -ENOENT;
}

struct http_root_url *http_server_add_default(struct http_server_urls *my,
					      http_url_cb_t cb)
{
	if (my->default_url.is_used) {
		return NULL;
	}

	my->default_url.is_used = true;
	my->default_url.root = NULL;
	my->default_url.root_len = 0;
	my->default_url.flags = 0;
	my->default_cb = cb;

	return &my->default_url;
}

int http_server_del_default(struct http_server_urls *my)
{
	if (!my->default_url.is_used) {
		return -ENOENT;
	}

	my->default_url.is_used = false;

	return 0;
}

static int http_url_cmp(const char *url, u16_t url_len,
			const char *root_url, u16_t root_url_len)
{
	if (url_len < root_url_len) {
		return -EINVAL;
	}

	if (memcmp(url, root_url, root_url_len) == 0) {
		if (url_len == root_url_len) {
			return 0;
		}

		/* Here we evaluate the following conditions:
		 * root_url = /images, url = /images/ -> OK
		 * root_url = /images/, url = /images/img.png -> OK
		 * root_url = /images/, url = /images_and_docs -> ERROR
		 */
		if (url_len > root_url_len) {
			if (root_url[root_url_len - 1] == '/') {
				return 0;
			}

			if (url[root_url_len] == '/') {
				return 0;
			}
		}
	}

	return -EINVAL;
}

struct http_root_url *http_url_find(struct http_ctx *ctx,
				    enum http_url_flags flags)
{
	u16_t url_len = ctx->http.url_len;
	const char *url = ctx->http.url;
	struct http_root_url *root_url;
	u8_t i;
	int ret;

	for (i = 0; i < CONFIG_HTTP_SERVER_NUM_URLS; i++) {
		if (!ctx->http.urls) {
			continue;
		}

		root_url = &ctx->http.urls->urls[i];
		if (!root_url || !root_url->is_used) {
			continue;
		}

		ret = http_url_cmp(url, url_len,
				   root_url->root, root_url->root_len);
		if (!ret && flags == root_url->flags) {
			return root_url;
		}
	}

	return NULL;
}

static int http_process_recv(struct http_ctx *ctx)
{
	struct http_root_url *root_url;
	int ret;

	root_url = http_url_find(ctx, HTTP_URL_STANDARD);
	if (!root_url) {
		if (!ctx->http.urls) {
			NET_DBG("[%p] No URL handlers found", ctx);
			ret = -ENOENT;
			goto out;
		}

		root_url = &ctx->http.urls->default_url;
		if (!root_url || !root_url->is_used) {
			NET_DBG("[%p] No default handler found", ctx);
			ret = -ENOENT;
			goto out;
		}

		if (ctx->http.urls->default_cb) {
			ret = ctx->http.urls->default_cb(ctx,
							 HTTP_CONNECTION);
			if (ret != HTTP_VERDICT_ACCEPT) {
				ret = -ECONNREFUSED;
				goto out;
			}
		}
	}

	http_change_state(ctx, HTTP_STATE_OPEN);
	url_connected(ctx, HTTP_CONNECTION);

	ret = 0;

out:
	return ret;
}

static void http_closed(struct net_app_ctx *app_ctx,
			int status,
			void *user_data)
{
	struct http_ctx *ctx = user_data;

	ARG_UNUSED(app_ctx);
	ARG_UNUSED(status);

	http_change_state(ctx, HTTP_STATE_CLOSED);

	NET_DBG("[%p] http closed", ctx);

	http_server_conn_del(ctx);

	if (ctx->cb.close) {
		ctx->cb.close(ctx, 0, ctx->user_data);
	}
}

static void http_received(struct net_app_ctx *app_ctx,
			  struct net_pkt *pkt,
			  int status,
			  void *user_data)
{
	struct http_ctx *ctx = user_data;
	size_t start = ctx->http.data_len;
	u16_t len = 0;
	struct net_buf *frag;
	int parsed_len;
	size_t recv_len;
	size_t pkt_len;

	recv_len = net_pkt_appdatalen(pkt);
	if (recv_len == 0) {
		/* don't print info about zero-length app data buffers */
		goto quit;
	}

	if (status) {
		NET_DBG("[%p] Status %d <%s>", ctx, status, RC_STR(status));
		goto out;
	}

	/* Get rid of possible IP headers in the first fragment. */
	frag = pkt->frags;

	pkt_len = net_pkt_get_len(pkt);

	if (recv_len < pkt_len) {
		net_buf_pull(frag, pkt_len - recv_len);
		net_pkt_set_appdata(pkt, frag->data);
	}

	NET_DBG("[%p] Received %zd bytes http data", ctx, recv_len);

	if (ctx->state == HTTP_STATE_OPEN) {
		/* We have active websocket session and there is no longer
		 * any HTTP traffic in the connection. Give the data to
		 * application to send.
		 */
		goto ws_only;
	}

	while (frag) {
		/* If this fragment cannot be copied to result buf,
		 * then parse what we have which will cause the callback to be
		 * called in function on_body(), and continue copying.
		 */
		if ((ctx->http.data_len + frag->len) >
		    ctx->request_buf_len) {

			if (ctx->state == HTTP_STATE_HEADER_RECEIVED) {
				goto ws_ready;
			}

			/* If the caller has not supplied a callback, then
			 * we cannot really continue if the request buffer
			 * overflows. Set the data_len to mark how many bytes
			 * should be needed in the response_buf.
			 */
			if (http_process_recv(ctx) < 0) {
				ctx->http.data_len = recv_len;
				goto out;
			}

			parsed_len =
				http_parser_execute(&ctx->http.parser,
						    &ctx->http.parser_settings,
						    ctx->request_buf +
						    start,
						    len);
			if (parsed_len <= 0) {
				goto fail;
			}

			ctx->http.data_len = 0;
			len = 0;
			start = 0;
		}

		memcpy(ctx->request_buf + ctx->http.data_len,
		       frag->data, frag->len);

		ctx->http.data_len += frag->len;
		len += frag->len;
		frag = frag->frags;
	}

out:
	parsed_len = http_parser_execute(&ctx->http.parser,
					 &ctx->http.parser_settings,
					 ctx->request_buf + start,
					 len);
	if (parsed_len < 0) {
fail:
		NET_DBG("[%p] Received %zd bytes, only parsed %d "
			"bytes (%s %s)",
			ctx, recv_len, parsed_len,
			http_errno_name(ctx->http.parser.http_errno),
			http_errno_description(
				ctx->http.parser.http_errno));
	}

	if (ctx->http.parser.http_errno != HPE_OK) {
		http_send_error(ctx, 400, NULL, 0);
	} else {
		if (ctx->state == HTTP_STATE_HEADER_RECEIVED) {
			goto ws_ready;
		}

		http_process_recv(ctx);
	}

quit:
	http_parser_init(&ctx->http.parser, HTTP_REQUEST);
	ctx->http.data_len = 0;
	ctx->http.field_values_ctr = 0;
	net_pkt_unref(pkt);

	return;

ws_only:
	if (ctx->cb.recv) {
#if defined(CONFIG_WEBSOCKET)
		u32_t flags, mask_value = 0;
		bool masked = false;

		flags = ws_strip_header(pkt, &masked, &mask_value);

		if (flags & WS_FLAG_CLOSE) {
			NET_DBG("[%p] Close request from peer", ctx);
			http_close(ctx);
			return;
		}

		if (flags & WS_FLAG_PING) {
			NET_DBG("[%p] Ping request from peer", ctx);
			ws_send_msg(ctx, NULL, WS_OPCODE_PONG, false, true,
				    NULL);
			return;
		}

		NET_DBG("Forward the data to application for processing.");

		NET_DBG("Masked %s mask 0x%04x", masked ? "yes" : "no",
			mask_value);

		if (masked) {
			/* Always deliver unmasked data to the application */
			ws_mask_pkt(pkt, mask_value);
		}

		ctx->cb.recv(ctx, pkt, 0, flags, ctx->user_data);
#else
		ctx->cb.recv(ctx, pkt, 0, 0, ctx->user_data);
#endif
	}

	return;

ws_ready:
	http_change_state(ctx, HTTP_STATE_OPEN);
	url_connected(ctx, WS_CONNECTION);
	net_pkt_unref(pkt);
}

#if defined(CONFIG_HTTPS)
int http_server_set_tls(struct http_ctx *ctx,
			const char *server_banner,
			u8_t *personalization_data,
			size_t personalization_data_len,
			net_app_cert_cb_t cert_cb,
			net_app_entropy_src_cb_t entropy_src_cb,
			struct k_mem_pool *pool,
			k_thread_stack_t stack,
			size_t stack_len)
{
	int ret;

	if (!ctx->is_tls) {
		/* Change the default port if user did not set it */
		if (!ctx->server_addr) {
			net_sin(&ctx->local)->sin_port =
				htons(HTTPS_DEFAULT_PORT);

#if defined(CONFIG_NET_IPV6)
			net_sin6(&ctx->app_ctx.ipv6.local)->sin6_port =
				htons(HTTPS_DEFAULT_PORT);
#endif
#if defined(CONFIG_NET_IPV4)
			net_sin(&ctx->app_ctx.ipv4.local)->sin_port =
				htons(HTTPS_DEFAULT_PORT);
#endif
		}

		ret = net_app_server_tls(&ctx->app_ctx,
					 ctx->request_buf,
					 ctx->request_buf_len,
					 server_banner,
					 personalization_data,
					 personalization_data_len,
					 cert_cb,
					 entropy_src_cb,
					 pool,
					 stack,
					 stack_len);
		if (ret < 0) {
			NET_ERR("Cannot init TLS (%d)", ret);
			goto quit;
		}

		ctx->is_tls = true;
		return 0;
	}

	return -EALREADY;

quit:
	net_app_release(&ctx->app_ctx);
	return ret;
}
#endif

static int on_header_field(struct http_parser *parser,
			   const char *at, size_t length)
{
	struct http_ctx *ctx = parser->data;

	if (ctx->http.field_values_ctr >= CONFIG_HTTP_HEADERS) {
		return 0;
	}

	http_change_state(ctx, HTTP_STATE_RECEIVING_HEADER);

	ctx->http.field_values[ctx->http.field_values_ctr].key = at;
	ctx->http.field_values[ctx->http.field_values_ctr].key_len = length;

	return 0;
}

static int on_header_value(struct http_parser *parser,
			   const char *at, size_t length)
{
	struct http_ctx *ctx = parser->data;

	if (ctx->http.field_values_ctr >= CONFIG_HTTP_HEADERS) {
		return 0;
	}

	ctx->http.field_values[ctx->http.field_values_ctr].value = at;
	ctx->http.field_values[ctx->http.field_values_ctr].value_len = length;

	ctx->http.field_values_ctr++;

	return 0;
}

static int on_url(struct http_parser *parser, const char *at, size_t length)
{
	struct http_ctx *ctx = parser->data;

	ctx->http.url = at;
	ctx->http.url_len = length;

	http_change_state(ctx, HTTP_STATE_WAITING_HEADER);

	http_server_conn_add(ctx);

	return 0;
}

static int on_headers_complete(struct http_parser *parser)
{
	ARG_UNUSED(parser);

#if defined(CONFIG_WEBSOCKET)
	return ws_headers_complete(parser);
#else
	return 0;
#endif
}

static int init_http_parser(struct http_ctx *ctx)
{
	memset(ctx->http.field_values, 0, sizeof(ctx->http.field_values));

	ctx->http.parser_settings.on_header_field = on_header_field;
	ctx->http.parser_settings.on_header_value = on_header_value;
	ctx->http.parser_settings.on_url = on_url;
	ctx->http.parser_settings.on_headers_complete = on_headers_complete;

	http_parser_init(&ctx->http.parser, HTTP_REQUEST);

	ctx->http.parser.data = ctx;

	return 0;
}

static inline void new_server(struct http_ctx *ctx,
			      const char *server_banner,
			      const struct sockaddr *addr)
{
#if defined(CONFIG_NET_DEBUG_HTTP) && (CONFIG_SYS_LOG_NET_LEVEL > 2)
#if defined(CONFIG_NET_IPV6)
#define PORT_STR sizeof("[]:xxxxx")
	char buf[NET_IPV6_ADDR_LEN + PORT_STR];
#elif defined(CONFIG_NET_IPV4) && !defined(CONFIG_NET_IPV6)
#define PORT_STR sizeof(":xxxxx")
	char buf[NET_IPV4_ADDR_LEN + PORT_STR];
#endif

	if (addr) {
		NET_INFO("%s %s (%p)", server_banner,
			 sprint_ipaddr(buf, sizeof(buf), addr), ctx);
	} else {
		NET_INFO("%s (%p)", server_banner, ctx);
	}
#endif /* CONFIG_NET_DEBUG_HTTP */
}

static void init_net(struct http_ctx *ctx,
		     struct sockaddr *server_addr,
		     u16_t port)
{
	memset(&ctx->local, 0, sizeof(ctx->local));

	if (server_addr) {
		memcpy(&ctx->local, server_addr, sizeof(ctx->local));
	} else {
		ctx->local.sa_family = AF_UNSPEC;
		net_sin(&ctx->local)->sin_port = htons(port);
	}
}

int http_server_init(struct http_ctx *ctx,
		     struct http_server_urls *urls,
		     struct sockaddr *server_addr,
		     u8_t *request_buf,
		     size_t request_buf_len,
		     const char *server_banner,
		     void *user_data)
{
	int ret = 0;

	if (!ctx) {
		return -EINVAL;
	}

	if (ctx->is_init) {
		return -EALREADY;
	}

	if (!request_buf || request_buf_len == 0) {
		NET_ERR("Request buf must be set");
		return -EINVAL;
	}

	memset(ctx, 0, sizeof(*ctx));

	init_net(ctx, server_addr, HTTP_DEFAULT_PORT);

	if (server_banner) {
		new_server(ctx, server_banner, server_addr);
	}

	/* Timeout for network buffer allocations */
	ctx->timeout = BUF_ALLOC_TIMEOUT;

	ctx->request_buf = request_buf;
	ctx->request_buf_len = request_buf_len;
	ctx->http.urls = urls;
	ctx->http.data_len = 0;
	ctx->user_data = user_data;
	ctx->server_addr = server_addr;

	ret = net_app_init_tcp_server(&ctx->app_ctx,
				      &ctx->local,
				      HTTP_DEFAULT_PORT,
				      ctx);
	if (ret < 0) {
		NET_ERR("Cannot create http server (%d)", ret);
		return ret;
	}

	ret = net_app_set_cb(&ctx->app_ctx, NULL, http_received,
			     http_data_sent, http_closed);
	if (ret < 0) {
		NET_ERR("Cannot set callbacks (%d)", ret);
		goto quit;
	}

	init_http_parser(ctx);

	ctx->is_init = true;
	return 0;

quit:
	net_app_release(&ctx->app_ctx);
	return ret;
}

int http_close(struct http_ctx *ctx)
{
	if (!ctx) {
		return -EINVAL;
	}

	if (!ctx->is_init) {
		return -ENOENT;
	}

	http_server_conn_del(ctx);

	return net_app_close(&ctx->app_ctx);
}

int http_release(struct http_ctx *ctx)
{
	if (!ctx) {
		return -EINVAL;
	}

	if (!ctx->is_init) {
		return -ENOENT;
	}

	http_server_conn_del(ctx);

	ctx->is_tls = false;

	http_server_disable(ctx);

	return net_app_release(&ctx->app_ctx);
}

int http_server_enable(struct http_ctx *ctx)
{
	int ret;

	NET_ASSERT(ctx);

	net_app_server_enable(&ctx->app_ctx);

	ret = net_app_listen(&ctx->app_ctx);
	if (ret < 0) {
		NET_ERR("Cannot wait connection (%d)", ret);
		return false;
	}

	return 0;
}

int http_server_disable(struct http_ctx *ctx)
{
	NET_ASSERT(ctx);

	net_app_server_disable(&ctx->app_ctx);

	return 0;
}

int http_set_cb(struct http_ctx *ctx,
		http_connect_cb_t connect_cb,
		http_recv_cb_t recv_cb,
		http_send_cb_t send_cb,
		http_close_cb_t close_cb)
{
	if (!ctx) {
		return -EINVAL;
	}

	if (!ctx->is_init) {
		return -ENOENT;
	}

	ctx->cb.connect = connect_cb;
	ctx->cb.recv = recv_cb;
	ctx->cb.send = send_cb;
	ctx->cb.close = close_cb;

	return 0;
}
