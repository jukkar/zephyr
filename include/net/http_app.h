/*
 * Copyright (c) 2017 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __HTTP_APP_H__
#define __HTTP_APP_H__

#include <net/net_app.h>
#include <net/http_parser.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(ZEPHYR_USER_AGENT)
#define ZEPHYR_USER_AGENT "Zephyr OS v"KERNEL_VERSION_STRING
#endif

#if !defined(CONFIG_HTTP_SERVER_NUM_URLS)
#define CONFIG_HTTP_SERVER_NUM_URLS 1
#endif

#if !defined(CONFIG_HTTP_HEADERS)
#define CONFIG_HTTP_HEADERS 1
#endif

/**
 * @brief HTTP client and server library
 * @defgroup http HTTP Library
 * @{
 */

struct http_ctx;

enum http_state {
	  HTTP_STATE_CLOSED,
	  HTTP_STATE_WAITING_HEADER,
	  HTTP_STATE_RECEIVING_HEADER,
	  HTTP_STATE_HEADER_RECEIVED,
	  HTTP_STATE_OPEN,
};

enum http_url_flags {
	HTTP_URL_STANDARD = 0,
	HTTP_URL_WEBSOCKET = 0,
};

enum http_connection_type {
	HTTP_CONNECTION = 1,
	WS_CONNECTION,
};

/* HTTP header fields struct */
struct http_field_value {
	/** Field name, this variable will point to the beginning of the string
	 *  containing the HTTP field name
	 */
	const char *key;

	/** Value, this variable will point to the beginning of the string
	 *  containing the field value
	 */
	const char *value;

	/** Length of the field name */
	u16_t key_len;

	/** Length of the field value */
	u16_t value_len;
};

/* HTTP root URL struct, used for pattern matching */
struct http_root_url {
	/** URL */
	const char *root;

	/** URL specific user data */
	u8_t *user_data;

	/** Length of the URL */
	u16_t root_len;

	/** Flags for this URL (values are from enum http_url_flags) */
	u8_t flags;

	/** Is this URL resource used or not */
	u8_t is_used;
};

enum http_verdict {
	HTTP_VERDICT_DROP,
	HTTP_VERDICT_ACCEPT,
};

/**
 * @typedef http_url_cb_t
 * @brief Default URL callback.
 *
 * @details This callback is called if there is a connection to unknown URL.
 *
 * @param ctx The context to use.
 * @param type Connection type (websocket or HTTP)
 *
 * @return HTTP_VERDICT_DROP if connection is to be dropped,
 * HTTP_VERDICT_ACCEPT if the application wants to accept the unknown URL.
 */
typedef enum http_verdict (*http_url_cb_t)(struct http_ctx *ctx,
					   enum http_connection_type type);

/* Collection of URLs that this server will handle */
struct http_server_urls {
	/* First item is the default handler and it is always there.
	 */
	struct http_root_url default_url;

	/** Callback that is called when unknown (default) URL is received */
	http_url_cb_t default_cb;

	struct http_root_url urls[CONFIG_HTTP_SERVER_NUM_URLS];
};

/**
 * @typedef http_recv_cb_t
 * @brief Network data receive callback.
 *
 * @details The recv callback is called after a network data is
 * received.
 *
 * @param ctx The context to use.
 * @param pkt Network buffer that is received. If the pkt is not NULL,
 * then the callback will own the buffer and it needs to to unref the pkt
 * as soon as it has finished working with it.  On EOF, pkt will be NULL.
 * @param status Value is set to 0 if some data or the connection is
 * at EOF, <0 if there was an error receiving data, in this case the
 * pkt parameter is set to NULL.
 * @param flags Flags related to http. For example contains information
 * if the data is text or binary etc.
 * @param user_data The user data given in init call.
 */
typedef void (*http_recv_cb_t)(struct http_ctx *ctx,
			       struct net_pkt *pkt,
			       int status,
			       u32_t flags,
			       void *user_data);

/**
 * @typedef http_connect_cb_t
 * @brief Connection callback.
 *
 * @details The connect callback is called after there was a connection to
 * non-default URL.
 *
 * @param ctx The context to use.
 * @param type Connection type (websocket or HTTP)
 * @param user_data The user data given in init call.
 */
typedef void (*http_connect_cb_t)(struct http_ctx *ctx,
				  enum http_connection_type type,
				  void *user_data);

/**
 * @typedef http_send_cb_t
 * @brief Network data send callback.
 *
 * @details The send callback is called after a network data is
 * sent.
 *
 * @param ctx The context to use.
 * @param status Value is set to 0 if all data was sent ok, <0 if
 * there was an error sending data. >0 amount of data that was
 * sent when not all data was sent ok.
 * @param user_data_send The user data given in http_send() call.
 * @param user_data The user data given in init call.
 */
typedef void (*http_send_cb_t)(struct http_ctx *ctx,
			       int status,
			       void *user_data_send,
			       void *user_data);

/**
 * @typedef http_close_cb_t
 * @brief Close callback.
 *
 * @details The close callback is called after a connection was shutdown.
 *
 * @param ctx The context to use.
 * @param status Error code for the closing.
 * @param user_data The user data given in init call.
 */
typedef void (*http_close_cb_t)(struct http_ctx *ctx,
				int status,
				void *user_data);

/** Websocket and HTTP callbacks */
struct http_cb {
	/** Function that is called when a connection is established.
	 */
	http_connect_cb_t connect;

	/** Function that is called when data is received from network.
	 */
	http_recv_cb_t recv;

	/** Function that is called when net_pkt is sent.
	 */
	http_send_cb_t send;

	/** Function that is called when connection is shutdown.
	 */
	http_close_cb_t close;
};

/**
 * Http context information. This contains all the data that is
 * needed when working with http API.
 */
struct http_ctx {
	/** Net app context. The http connection is handled via
	 * the net app API.
	 */
	struct net_app_ctx app_ctx;

	/** Local endpoint IP address */
	struct sockaddr local;

	/** Original server address */
	struct sockaddr *server_addr;

	struct {
		/** Collection of HTTP URLs that this context will handle. */
		struct http_server_urls *urls;

		/** HTTP URL parser */
		struct http_parser_url parsed_uri;

		/** HTTP parser for parsing the initial request */
		struct http_parser parser;

		/** HTTP parser settings */
		struct http_parser_settings parser_settings;

		/** Collection of HTTP header fields */
		struct http_field_value field_values[CONFIG_HTTP_HEADERS];

		/** HTTP Request URL */
		const char *url;

		/** Length of the data in the request buf. */
		size_t data_len;

		/** URL's length */
		u16_t url_len;

		/** Number of header field elements */
		u16_t field_values_ctr;
	} http;

#if defined(CONFIG_NET_DEBUG_HTTP_CONN)
	sys_snode_t node;
#endif

	/** HTTP callbacks */
	struct http_cb cb;

	/** User specified data that is passed in callbacks. */
	u8_t *user_data;

	/** Where the request is stored, this is to be provided by the user.
	 */
	u8_t *request_buf;

	/** Request buffer maximum length */
	size_t request_buf_len;

	/** State of the websocket */
	enum http_state state;

	/** Network buffer allocation timeout */
	s32_t timeout;

	/** Websocket endpoint address */
	struct sockaddr *addr;

	/** Websocket endpoint port */
	u16_t port;

	/** Is this context setup or not */
	u8_t is_init : 1;

	/** Is this instance supporting TLS or not.
	 */
	u8_t is_tls : 1;
};

#if defined(CONFIG_HTTP_SERVER)
/**
 * @brief Create a HTTP listener.
 *
 * @details Note that the context must be valid for the whole duration of the
 * http life cycle. This usually means that it cannot be allocated from
 * stack.
 *
 * @param ctx Http context. This init function will initialize it.
 * @param urls Array of URLs that the server instance will serve. If the
 * server receives a HTTP request into one of the URLs, it will call user
 * supplied callback. If no such URL is registered, a default handler will
 * be called (if set by the user). If no data handler is found, the request
 * is dropped.
 * @param server_addr Socket address of the local network interface and TCP
 * port where the data is being waited. If the socket family is set to
 * AF_UNSPEC, then both IPv4 and IPv6 is started to be listened. If the
 * address is set to be INADDR_ANY (for IPv4) or unspecified address (all bits
 * zeros for IPv6), then the HTTP server will select proper IP address to bind
 * to. If caller has not specified HTTP listening port, then port 80 is being
 * listened. The parameter can be left NULL in which case a listener to port 80
 * using IPv4 and IPv6 is created. Note that if IPv4 or IPv6 is disabled, then
 * the corresponding disabled service listener is not created.
 * @param request_buf Caller-supplied buffer where the HTTP request will be
 * stored
 * @param request_buf_len Length of the caller-supplied buffer.
 * @param server_banner Print information about started service. This is only
 * printed if HTTP debugging is activated. The parameter can be set to NULL if
 * no extra prints are needed.
 * @param user_data User specific data that is passed as is to the connection
 * callbacks.
 *
 * @return 0 if ok, <0 if error.
 */
int http_server_init(struct http_ctx *ctx,
		     struct http_server_urls *urls,
		     struct sockaddr *server_addr,
		     u8_t *request_buf,
		     size_t request_buf_len,
		     const char *server_banner,
		     void *user_data);

#if defined(CONFIG_HTTPS)
/**
 * @brief Initialize TLS support for this http context
 *
 * @param ctx Http context
 * @param server_banner Print information about started service. This is only
 * printed if net_app debugging is activated. The parameter can be set to NULL
 * if no extra prints are needed.
 * @param personalization_data Personalization data (Device specific
 * identifiers) for random number generator. (Can be NULL).
 * @param personalization_data_len Length of the personalization data.
 * @param cert_cb User supplied callback that setups the certifacates.
 * @param entropy_src_cb User supplied callback that setup the entropy. This
 * can be set to NULL, in which case default entropy source is used.
 * @param pool Memory pool for RX data reads.
 * @param stack TLS thread stack.
 * @param stack_len TLS thread stack size.
 *
 * @return Return 0 if ok, <0 if error.
 */
int http_server_set_tls(struct http_ctx *ctx,
			const char *server_banner,
			u8_t *personalization_data,
			size_t personalization_data_len,
			net_app_cert_cb_t cert_cb,
			net_app_entropy_src_cb_t entropy_src_cb,
			struct k_mem_pool *pool,
			k_thread_stack_t stack,
			size_t stack_len);

#endif /* CONFIG_HTTPS */

/**
 * @brief Enable HTTP server that is related to this context.
 *
 * @detail The HTTP server will start to serve request after this.
 *
 * @param ctx Http context.
 *
 * @return 0 if server is enabled, <0 otherwise
 */
int http_server_enable(struct http_ctx *ctx);

/**
 * @brief Disable HTTP server that is related to this context.
 *
 * @detail The HTTP server will stop to serve request after this.
 *
 * @param ctx Http context.
 *
 * @return 0 if server is disabled, <0 if there was an error
 */
int http_server_disable(struct http_ctx *ctx);

/**
 * @brief Add an URL to a list of URLs that are tied to certain webcontext.
 *
 * @param urls URL struct that will contain all the URLs the user wants to
 * register.
 * @param url URL string.
 * @param flags Flags for the URL.
 *
 * @return NULL if the URL is already registered, pointer to  URL if
 * registering was ok.
 */
struct http_root_url *http_server_add_url(struct http_server_urls *urls,
					  const char *url, u8_t flags);

/**
 * @brief Delete the URL from list of URLs that are tied to certain
 * webcontext.
 *
 * @param urls URL struct that will contain all the URLs the user has
 * registered.
 * @param url URL string.
 *
 * @return 0 if ok, <0 if error.
 */
int http_server_del_url(struct http_server_urls *urls, const char *url);

/**
 * @brief Add default URL handler.
 *
 * @detail If no URL handler is found, then call this handler. There can
 * be only one default handler in the URL struct. The callback can decide
 * if the connection request is dropped or passed.
 *
 * @param urls URL struct that will contain all the URLs the user has
 * registered.
 * @param cb Callback that is called when non-registered URL is requested.
 *
 * @return NULL if default URL is already registered, pointer to default
 * URL if registering was ok.
 */
struct http_root_url *http_server_add_default(struct http_server_urls *urls,
					      http_url_cb_t cb);

/**
 * @brief Delete the default URL handler.
 *
 * @detail Unregister the previously registered default URL handler.
 *
 * @param urls URL struct that will contain all the URLs the user has
 * registered.
 *
 * @return 0 if ok, <0 if error.
 */
int http_server_del_default(struct http_server_urls *urls);

#else /* CONFIG_HTTP_SERVER */

static inline int http_server_init(struct http_ctx *ctx,
				   struct http_server_urls *urls,
				   struct sockaddr *server_addr,
				   u8_t *request_buf,
				   size_t request_buf_len,
				   const char *server_banner)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(urls);
	ARG_UNUSED(server_addr);
	ARG_UNUSED(request_buf);
	ARG_UNUSED(request_buf_len);
	ARG_UNUSED(server_banner);

	return -ENOTSUP;
}

#if defined(CONFIG_HTTP_TLS)
static inline int http_server_set_tls(struct http_ctx *ctx,
				      const char *server_banner,
				      u8_t *personalization_data,
				      size_t personalization_data_len,
				      net_app_cert_cb_t cert_cb,
				      net_app_entropy_src_cb_t entropy_src_cb,
				      struct k_mem_pool *pool,
				      k_thread_stack_t stack,
				      size_t stack_len)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(server_banner);
	ARG_UNUSED(personalization_data);
	ARG_UNUSED(personalization_data_len);
	ARG_UNUSED(cert_cb);
	ARG_UNUSED(entropy_src_cb);
	ARG_UNUSED(pool);
	ARG_UNUSED(stack);
	ARG_UNUSED(stack_len);

	return -ENOTSUP;
}
#endif /* CONFIG_HTTP_TLS */

static inline int http_server_enable(struct http_ctx *ctx)
{
	ARG_UNUSED(ctx);
	return -ENOTSUP;
}

static inline int http_server_disable(struct http_ctx *ctx)
{
	ARG_UNUSED(ctx);
	return -ENOTSUP;
}

static inline
struct http_root_url *http_server_add_url(struct http_server_urls *urls,
					  const char *url, u8_t flags,
					  http_url_cb_t write_cb)
{
	ARG_UNUSED(urls);
	ARG_UNUSED(url);
	ARG_UNUSED(flags);
	ARG_UNUSED(write_cb);

	return NULL;
}

#endif /* CONFIG_HTTP_SERVER */

/**
 * @brief Close a network connection to peer.
 *
 * @param ctx Http context.
 *
 * @return 0 if ok, <0 if error.
 */
int http_close(struct http_ctx *ctx);

/**
 * @brief Release this http context.
 *
 * @details No network data will be received via this context after this
 * call.
 *
 * @param ctx Http context.
 *
 * @return 0 if ok, <0 if error.
 */
int http_release(struct http_ctx *ctx);

/**
 * @brief Set various callbacks that are called at various stage of ws session.
 *
 * @param ctx Http context.
 * @param connect_cb Connect callback.
 * @param recv_cb Data receive callback.
 * @param send_cb Data sent callback.
 * @param close_cb Close callback.
 *
 * @return 0 if ok, <0 if error.
 */
int http_set_cb(struct http_ctx *ctx,
		http_connect_cb_t connect_cb,
		http_recv_cb_t recv_cb,
		http_send_cb_t send_cb,
		http_close_cb_t close_cb);

/**
 * @brief Send a message to peer. The data can be either HTTP or websocket
 * data.
 *
 * @details This does not modify the network packet but sends it as is.
 *
 * @param ctx Http context.
 * @param pkt Network packet to send
 * @param user_send_data User specific data to this connection. This is passed
 * as a parameter to sent cb after the packet has been sent.
 *
 * @return 0 if ok, <0 if error.
 */
int http_send_msg_raw(struct http_ctx *ctx, struct net_pkt *pkt,
		      void *user_send_data);

/**
 * @brief Send HTTP data to peer.
 *
 * @param ctx Http context.
 * @param pkt Network packet to send
 * @param user_send_data User specific data to this connection. This is passed
 * as a parameter to sent cb after the packet has been sent.
 *
 * @return 0 if ok, <0 if error.
 */
static inline int http_send_data(struct http_ctx *ctx, struct net_pkt *pkt,
				 void *user_send_data)
{
	return http_send_msg_raw(ctx, pkt, user_send_data);
}

/**
 * @brief Send HTTP error message to peer.
 *
 * @param ctx Http context.
 * @param code HTTP error code
 * @param html_payload Extra payload, can be null
 * @param html_len Payload length
 *
 * @return 0 if ok, <0 if error.
 */
int http_send_error(struct http_ctx *ctx, int code, u8_t *html_payload,
		    size_t html_len);

/**
 * @brief Add HTTP header to the message.
 *
 * @details This can be called multiple times to add pieces of HTTP header into
 * the message.
 *
 * @param ctx Http context.
 * @param pkt Network packet to that will eventually be sent. The HTTP header
 * is added to this packet. If *pkt is NULL, then the API will allocate network
 * packet and place the header into it.
 * @param http_header All or part of HTTP header to be added.
 *
 * @return 0 if ok, <0 if error.
 */
int http_add_header(struct http_ctx *ctx, struct net_pkt **pkt,
		    const char *http_header);

/**
 * @brief Add HTTP data to the message.
 *
 * @details This can be called multiple times to add pieces of HTTP data into
 * the message.
 *
 * @param ctx HTTP context.
 * @param pkt Network packet to send. If *pkt is NULL, then the API
 * will allocate network packet and place data into it.
 * @param buf Buffer that contains the data
 * @param len Length of the buffer
 *
 * @return 0 if ok, <0 if error.
 */
int http_add_data(struct http_ctx *ctx, struct net_pkt **pkt,
		  const u8_t *buf, size_t len);

/**
 * @brief Add data to the message.
 *
 * @details This can be called multiple times to add pieces of ws data into
 * the message.
 *
 * @param ctx Http context.
 * @param pkt Network packet to send. If *pkt is NULL, then the API
 * will allocate network packet and place data into it.
 * @param buf Buffer that contains the data
 * @param len Length of the buffer
 *
 * @return 0 if ok, <0 if error.
 */
int http_add_data(struct http_ctx *ctx, struct net_pkt **pkt,
		  const u8_t *buf, size_t len);

/**
 * @brief Find a handler function for a given URL.
 *
 * @details This is internal function, do not call this from application.
 *
 * @param ctx Http context.
 * @param flags Tells if the URL is either HTTP or websocket URL
 *
 * @return URL handler or NULL if no such handler was found.
 */
struct http_root_url *http_url_find(struct http_ctx *ctx,
				    enum http_url_flags flags);

#define http_change_state(ctx, new_state)			\
	_http_change_state(ctx, new_state, __func__, __LINE__)

/**
 * @brief Change the state of the HTTP engine
 *
 * @details This is internal function, do not call this from application.
 *
 * @param ctx HTTP context.
 * @param new_state New state of the context.
 * @param func Function that changed the state (for debugging)
 * @param line Line number of the function (for debugging)
 */
void _http_change_state(struct http_ctx *ctx,
			enum http_state new_state,
			const char *func, int line);

#if defined(CONFIG_NET_DEBUG_HTTP_CONN)
typedef void (*http_server_cb_t)(struct http_ctx *entry,
				      void *user_data);

void http_server_conn_foreach(http_server_cb_t cb, void *user_data);
void http_server_conn_monitor(http_server_cb_t cb, void *user_data);
#else
#define http_server_conn_foreach(...)
#define http_server_conn_monitor(...)
#endif /* CONFIG_NET_DEBUG_HTTP_CONN */

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* __HTTP_APP_H__ */
