/** @file
 * @brief Websocket API
 *
 * An API for applications to setup websocket connections
 */

/*
 * Copyright (c) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_NET_WEBSOCKET_H_
#define ZEPHYR_INCLUDE_NET_WEBSOCKET_H_

#include <kernel.h>

#include <net/net_ip.h>
#include <net/http_parser.h>
#include <net/http_client.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Websocket API
 * @defgroup websocket Websocket API
 * @ingroup networking
 * @{
 */

/** Values for flag variable in HTTP receive callback */
#define WEBSOCKET_FLAG_FINAL  0x00000001 /**< Final frame        */
#define WEBSOCKET_FLAG_TEXT   0x00000002 /**< Textual data       */
#define WEBSOCKET_FLAG_BINARY 0x00000004 /**< Binary data        */
#define WEBSOCKET_FLAG_CLOSE  0x00000008 /**< Closing connection */
#define WEBSOCKET_FLAG_PING   0x00000010 /**< Ping message       */
#define WEBSOCKET_FLAG_PONG   0x00000011 /**< Pong message       */

enum websocket_opcode  {
	WEBSOCKET_OPCODE_CONTINUE     = 0x00,
	WEBSOCKET_OPCODE_DATA_TEXT    = 0x01,
	WEBSOCKET_OPCODE_DATA_BINARY  = 0x02,
	WEBSOCKET_OPCODE_CLOSE        = 0x08,
	WEBSOCKET_OPCODE_PING         = 0x09,
	WEBSOCKET_OPCODE_PONG         = 0x0A,
};

/**
 * @typedef websocket_connect_cb_t
 * @brief Callback called after Websocket connection is established.
 *
 * @param sock Websocket id
 * @param req HTTP handshake request
 * @param user_data A valid pointer on some user data or NULL
 *
 * @return 0 if ok, <0 if there is an error and connection should be aborted
 */
typedef int (*websocket_connect_cb_t)(int ws_sock, struct http_request *req,
				      void *user_data);

/**
 * @brief Connect to a server that provides Websocket service. The callback is
 * called after connection is established. The returned value is a new socket
 * value that can be used to send / receive data.
 *
 * @param http_sock Socket id to the server. Note that this socket is used to do
 *        HTTP handshakes etc. The actual Websocket connectivity is done via the
 *        returned websocket id.
 * @param host Host of the Websocket server when doing HTTP handshakes.
 * @param url URL of the Websocket.
 * @param optional_headers A NULL terminated list of Any optional headers that
 *        should be added to the HTTP request.
 * @param cb User supplied callback function to call when connection is
 *        established.
 * @param http_cb User supplied list of callback functions if the
 *        calling application wants to know the parsing status or the HTTP
 *        fields during the handshake. This is optional parameter and normally
 *        not needed but is useful if the caller wants to know something about
 *        the fields that the server is sending.
 * @param tmp_buf User supplied buffer where HTTP connection data is stored
 * @param tmp_buf_len Length of the user supplied temp buffer
 * @param timeout Max timeout to wait for the connection. The timeout value
 *        cannot be 0 as there would be no time to receive the data.
 * @param user_data User specified data that is passed to the callback.
 *
 * @return Websocket id to be used when sending/receiving Websocket data.
 */
int websocket_connect(int http_sock, const char *host, const char *url,
		      const char **optional_headers,
		      websocket_connect_cb_t cb,
		      const struct http_parser_settings *http_cb,
		      u8_t *tmp_buf, size_t tmp_buf_len,
		      s32_t timeout, void *user_data);

/**
 * @brief Send websocket msg to peer.
 *
 * @details The function will automatically add websocket header to the
 * message.
 *
 * @param ws_sock websocket id returned by websocket_connect(). Note that this
 *        socket is used to do HTTP handshakes etc. The actual Websocket
 *        connectivity is done via the returned websocket id.
 * @param payload Websocket data to send.
 * @param payload_len Length of the data to be sent.
 * @param opcode Operation code (text, binary, ping, pong, close)
 * @param mask Mask the data, see RFC 6455 for details
 * @param final Is this final message for this message send. If final == false,
 *        then the first message must have valid opcode and subsequent messages
 *        must have opcode WEBSOCKET_OPCODE_CONTINUE. If final == true and this
 *        is the only message, then opcode should have proper opcode (text or
 *        binary) set.
 * @param timeout How long to try to send the message.
 *
 * @return <0 if error, >=0 amount of bytes sent
 */
int websocket_send_msg(int ws_sock, const u8_t *payload, size_t payload_len,
		       enum websocket_opcode opcode, bool mask, bool final,
		       s32_t timeout);

/**
 */
int websocket_recv_msg(int ws_sock, u8_t *buf, size_t buf_len,
		       bool *masked, u32_t *mask_value, u32_t *message_type,
		       s32_t timeout);

/**
 */
int websocket_disconnect(int ws_sock);

#if defined(CONFIG_WEBSOCKET_CLIENT)
void websocket_init(void);
#else
static inline void websocket_init(void)
{
}
#endif

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_NET_WEBSOCKET_H_ */
