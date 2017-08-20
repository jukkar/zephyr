/*
 * Copyright (c) 2017 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __WEBSOCKET_H__
#define __WEBSOCKET_H__

#include <net/http.h>
#include <net/http_parser.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Websocket library
 * @defgroup websocket Websocket Library
 * @{
 */

/** Values for flag variable in HTTP receive callback */
#define WS_FLAG_FINAL  0x00000001
#define WS_FLAG_TEXT   0x00000002
#define WS_FLAG_BINARY 0x00000004
#define WS_FLAG_CLOSE  0x00000008
#define WS_FLAG_PING   0x00000010
#define WS_FLAG_PONG   0x00000011

enum ws_opcode  {
	WS_OPCODE_CONTINUE     = 0x00,
	WS_OPCODE_DATA_TEXT    = 0x01,
	WS_OPCODE_DATA_BINARY  = 0x02,
	WS_OPCODE_CLOSE        = 0x08,
	WS_OPCODE_PING         = 0x09,
	WS_OPCODE_PONG         = 0x0A,
};

/**
 * @brief Send websocket msg to peer.
 *
 * @details The function will automatically add websocket header to the
 * message.
 *
 * @param ctx Websocket context.
 * @param pkt Network packet to send. This can be left NULL if no user data
 * is to be sent.
 * @param opcode Operation code (text, binary, ping, pong, close)
 * @param mask Mask the data, see RFC 6455 for details
 * @param final Is this final message for this message send. If final == false,
 * then the first message must have valid opcode and subsequent messages must
 * have opcode WS_OPCODE_CONTINUE. If final == true and this is the only
 * message, then opcode should have proper opcode (text or binary) set.
 * @param user_send_data User specific data to this connection. This is passed
 * as a parameter to sent cb after the packet has been sent.
 *
 * @return 0 if ok, <0 if error.
 */
int ws_send_msg(struct http_ctx *ctx, struct net_pkt *pkt,
		enum ws_opcode opcode, bool mask, bool final,
		void *user_send_data);

/**
 * @brief Send message to client.
 *
 * @details The function will automatically add websocket header to the
 * message.
 *
 * @param ctx Websocket context.
 * @param pkt Network packet to send
 * @param opcode Operation code (text, binary, ping ,pong ,close)
 * @param final Is this final message for this data send
 * @param user_send_data User specific data to this connection. This is passed
 * as a parameter to sent cb after the packet has been sent.
 *
 * @return 0 if ok, <0 if error.
 */
static inline int ws_send_msg_to_client(struct http_ctx *ctx,
					struct net_pkt *pkt,
					enum ws_opcode opcode,
					bool final,
					void *user_send_data)
{
	return ws_send_msg(ctx, pkt, opcode, false, final, user_send_data);
}

/**
 * @brief Strip websocket header from the packet.
 *
 * @details The function will remove websocket header from the network packet.
 *
 * @param pkt Network packet to send
 * @param masked The mask status of the message is returned.
 * @param mask_value The mask value of the message is returned.
 *
 * @return Websocket flag value is returned.
 */
u32_t ws_strip_header(struct net_pkt *pkt, bool *masked,
		      u32_t *mask_value);

/**
 * @brief Mask or unmask a websocket message if needed
 *
 * @details The function will either add or remove the masking from the data.
 *
 * @param pkt Network packet to process
 * @param masking_value The mask value to use.
 */
void ws_mask_pkt(struct net_pkt *pkt, u32_t masking_value);

/**
 * @brief This is called by HTTP server after all the HTTP headers have been
 * received.
 *
 * @details The function will check if this is a valid websocket connection.
 *
 * @param parser HTTP parser instance
 *
 * @return 0 if ok, 1 if there is no body, 2 if HTTP connection is to be
 * upgraded to websocket one
 */
int ws_headers_complete(struct http_parser *parser);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* __WS_H__ */
