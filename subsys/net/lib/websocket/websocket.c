/*
 * Copyright (c) 2017 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(CONFIG_NET_DEBUG_WEBSOCKET)
#define SYS_LOG_DOMAIN "ws"
#define NET_SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define NET_LOG_ENABLED 1
#endif

#include <zephyr.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <stdlib.h>
#include <version.h>

#include <net/net_ip.h>
#include <net/websocket.h>

#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>

#define BUF_ALLOC_TIMEOUT 100

#define HTTP_CRLF "\r\n"

/* From RFC 6455 chapter 4.2.2 */
#define WS_MAGIC "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

void ws_mask_pkt(struct net_pkt *pkt, u32_t masking_value)
{
	struct net_buf *frag;
	int i, count = 0;
	u16_t pos;

	frag = net_frag_get_pos(pkt,
				net_pkt_get_len(pkt) - net_pkt_appdatalen(pkt),
				&pos);
	if (!frag) {
		return;
	}

	NET_ASSERT(net_pkt_appdata(pkt) == frag->data + pos);

	while (frag) {
		for (i = pos; i < frag->len && count < net_pkt_appdatalen(pkt);
		     i++, count++) {
			frag->data[i] ^= masking_value >>
							(8 * (3 - count % 4));
		}

		pos = 0;
		frag = frag->frags;
	}
}

int ws_send_msg(struct http_ctx *ctx, struct net_pkt *pkt,
		enum ws_opcode opcode, bool mask, bool final,
		void *user_send_data)
{
	u8_t header[14], hdr_len = 2;
	int len, ret;
	bool alloc_here = false;

	if (ctx->state != HTTP_STATE_OPEN) {
		return -ENOTCONN;
	}

	if (opcode != WS_OPCODE_DATA_TEXT && opcode != WS_OPCODE_DATA_BINARY &&
	    opcode != WS_OPCODE_CONTINUE && opcode != WS_OPCODE_CLOSE &&
	    opcode != WS_OPCODE_PING && opcode != WS_OPCODE_PONG) {
		return -EINVAL;
	}

	if (!pkt) {
		pkt = net_app_get_net_pkt(&ctx->app_ctx,
					  AF_UNSPEC,
					  ctx->timeout);
		if (!pkt) {
			return -ENOMEM;
		}

		if (!net_app_get_net_buf(&ctx->app_ctx, pkt,
					 ctx->timeout)) {
			net_pkt_unref(pkt);
			return -ENOMEM;
		}

		alloc_here = true;
	}

	/* If there is IP + other headers in front, then get rid of them
	 * here.
	 */
	len = net_pkt_get_len(pkt);
	if (len > net_pkt_appdatalen(pkt) && net_pkt_appdatalen(pkt) > 0) {
		/* Make sure that appdata pointer is valid one */
		if ((net_pkt_appdata(pkt) < pkt->frags->data) ||
		    (net_pkt_appdata(pkt) > (pkt->frags->data +
					     pkt->frags->len))) {
			NET_DBG("appdata %p (%d len) is not [%p, %p], "
				"msg (%d bytes) discarded",
				net_pkt_appdata(pkt), net_pkt_appdatalen(pkt),
				pkt->frags->data, pkt->frags->data +
				pkt->frags->len, len);
			ret = -EINVAL;
			goto quit;
		}

		NET_DBG("Stripping %zd bytes from pkt %p",
			net_pkt_appdata(pkt) - pkt->frags->data, pkt);

		net_buf_pull(pkt->frags,
			     net_pkt_appdata(pkt) - pkt->frags->data);
	} else {
		net_pkt_set_appdatalen(pkt, len);
		net_pkt_set_appdata(pkt, pkt->frags->data);
	}

	len = net_pkt_appdatalen(pkt);

	memset(header, 0, sizeof(header));

	/* Is this the last packet? */
	header[0] = final ? BIT(7) : 0;

	/* Text, binary, ping, pong or close ? */
	header[0] |= opcode;

	/* Masking */
	header[1] = mask ? BIT(7) : 0;

	if (len < 126) {
		header[1] |= len;
	} else if (len < 65536) {
		header[1] |= 126;
		header[2] = len >> 8;
		header[3] = len;
		hdr_len += 2;
	} else {
		header[1] |= 127;
		header[2] = 0;
		header[3] = 0;
		header[4] = 0;
		header[5] = 0;
		header[6] = len >> 24;
		header[7] = len >> 16;
		header[8] = len >> 8;
		header[9] = len;
		hdr_len += 8;
	}

	/* Add masking value if needed */
	if (mask) {
		u32_t masking_value;

		masking_value = sys_rand32_get();

		header[hdr_len++] |= masking_value >> 24;
		header[hdr_len++] |= masking_value >> 16;
		header[hdr_len++] |= masking_value >> 8;
		header[hdr_len++] |= masking_value;

		ws_mask_pkt(pkt, masking_value);
	}

	if (len == 0) {
		if (hdr_len != net_pkt_append(pkt, hdr_len, header,
					      ctx->timeout)) {
			goto cannot_embed;
		}
	} else {
		if (!net_pkt_insert(pkt, pkt->frags, 0, hdr_len, header,
				    ctx->timeout)) {
		cannot_embed:
			ret = -ENOMEM;
			NET_DBG("Cannot embed data (len %d, hdr_len %d)",
				len, hdr_len);
			goto quit;
		}
	}

	net_pkt_set_appdatalen(pkt, net_pkt_appdatalen(pkt) + hdr_len);

	ret = http_send_msg_raw(ctx, pkt, user_send_data);
	if (ret < 0) {
		NET_DBG("Cannot send %zd bytes message (%d)",
			net_pkt_get_len(pkt), ret);
		goto quit;
	}

quit:
	if (alloc_here) {
		net_pkt_unref(pkt);
	}

	return ret;
}

u32_t ws_strip_header(struct net_pkt *pkt, bool *masked,
		      u32_t *mask_value)
{
	struct net_buf *frag;
	u32_t flag = 0;
	u16_t value;
	u16_t pos;
	u8_t len, skip;

	/* We can get the ws header like this because it is in first
	 * fragment
	 */
	frag = net_frag_read_be16(pkt->frags,
				  net_pkt_appdata(pkt) - pkt->frags->data,
				  &pos,
				  &value);
	if (!frag && pos == 0xffff) {
		return 0;
	}

	if (value & 0x8000) {
		flag |= WS_FLAG_FINAL;
	}

	switch (value & 0x0f00) {
	case 0x0100:
		flag |= WS_FLAG_TEXT;
		break;
	case 0x0200:
		flag |= WS_FLAG_BINARY;
		break;
	case 0x0800:
		flag |= WS_FLAG_CLOSE;
		break;
	case 0x0900:
		flag |= WS_FLAG_PING;
		break;
	case 0x0A00:
		flag |= WS_FLAG_PONG;
		break;
	}

	if (value & 0x0080) {
		*masked = true;

		frag = net_frag_read_be32(pkt->frags, pos, &pos, mask_value);
		if (!frag && pos == 0xffff) {
			return 0;
		}
	} else {
		*masked = false;
	}

	len = value & 0x007f;
	if (len < 126) {
		skip = 0;
	} else if (len == 126) {
		skip = 1;
	} else {
		skip = 2;
	}

	frag = net_frag_get_pos(pkt, pos + skip, &pos);
	if (!frag && pos == 0xffff) {
		return 0;
	}

	net_pkt_set_appdatalen(pkt, net_pkt_appdatalen(pkt) - 6 - skip);
	net_pkt_set_appdata(pkt, frag->data + pos);

	return flag;
}

static bool field_contains(const char *field, int field_len,
			   const char *str, int str_len)
{
	bool found = false;
	char c, skip;

	c = *str++;
	if (c == '\0') {
		return false;
	}

	str_len--;

	do {
		do {
			skip = *field++;
			field_len--;
			if (skip == '\0' || field_len == 0) {
				return false;
			}
		} while (skip != c);

		if (field_len < str_len) {
			return false;
		}

		if (strncasecmp(field, str, str_len) == 0) {
			found = true;
			break;
		}

	} while (field_len >= str_len);

	return found;
}

static bool check_ws_headers(struct http_ctx *ctx, struct http_parser *parser,
			     int *ws_sec_key, int *host, int *subprotocol)
{
	int i, count, connection = -1;
	int ws_sec_version = -1;

	if (!parser->upgrade || parser->method != HTTP_GET ||
	    parser->http_major != 1 || parser->http_minor != 1) {
		return false;
	}

	for (i = 0, count = 0; i < ctx->http.field_values_ctr; i++) {
		if (ctx->http.field_values[i].key_len == 0) {
			continue;
		}

		if (strncasecmp(ctx->http.field_values[i].key,
				"Sec-WebSocket-Key",
				sizeof("Sec-WebSocket-Key") - 1) == 0) {
			*ws_sec_key = i;
			continue;
		}

		if (strncasecmp(ctx->http.field_values[i].key,
				"Sec-WebSocket-Version",
				sizeof("Sec-WebSocket-Version") - 1) == 0) {
			if (strncmp(ctx->http.field_values[i].value,
				    "13", sizeof("13") - 1) == 0) {
				ws_sec_version = i;
			}

			continue;
		}

		if (strncasecmp(ctx->http.field_values[i].key,
				"Connection", sizeof("Connection") - 1) == 0) {
			if (field_contains(
				    ctx->http.field_values[i].value,
				    ctx->http.field_values[i].value_len,
				    "Upgrade", sizeof("Upgrade") - 1)) {
				connection = i;
			}

			continue;
		}

		if (strncasecmp(ctx->http.field_values[i].key, "Host",
				sizeof("Host") - 1) == 0) {
			*host = i;
			continue;
		}

		if (strncasecmp(ctx->http.field_values[i].key,
				"Sec-WebSocket-Protocol",
				sizeof("Sec-WebSocket-Protocol") - 1) == 0) {
			*subprotocol = i;
			continue;
		}
	}

	if (connection >= 0 && *ws_sec_key >= 0 && ws_sec_version >= 0 &&
	    *host >= 0) {
		return true;
	}

	return false;
}

static struct net_pkt *prepare_reply(struct http_ctx *ctx,
				     int ws_sec_key, int host, int subprotocol)
{
	char key_accept[32 + sizeof(WS_MAGIC) - 1];
	char accept[20];
	struct net_pkt *pkt;
	char tmp[64];
	int ret;
	size_t olen;

	pkt = net_app_get_net_pkt(&ctx->app_ctx, AF_UNSPEC, ctx->timeout);
	if (!pkt) {
		return NULL;
	}

	snprintk(tmp, sizeof(tmp), "HTTP/1.1 101 OK\r\n");
	if (!net_pkt_append_all(pkt, strlen(tmp), (u8_t *)tmp, ctx->timeout)) {
		goto fail;
	}

	snprintk(tmp, sizeof(tmp), "User-Agent: %s\r\n", ZEPHYR_USER_AGENT);
	if (!net_pkt_append_all(pkt, strlen(tmp), (u8_t *)tmp, ctx->timeout)) {
		goto fail;
	}

	snprintk(tmp, sizeof(tmp), "Upgrade: websocket\r\n");
	if (!net_pkt_append_all(pkt, strlen(tmp), (u8_t *)tmp, ctx->timeout)) {
		goto fail;
	}

	snprintk(tmp, sizeof(tmp), "Connection: Upgrade\r\n");
	if (!net_pkt_append_all(pkt, strlen(tmp), (u8_t *)tmp, ctx->timeout)) {
		goto fail;
	}

	olen = min(sizeof(key_accept),
		   ctx->http.field_values[ws_sec_key].value_len);
	strncpy(key_accept, ctx->http.field_values[ws_sec_key].value, olen);

	olen = min(sizeof(key_accept) -
		   ctx->http.field_values[ws_sec_key].value_len,
		   sizeof(WS_MAGIC) - 1);
	strncpy(key_accept + ctx->http.field_values[ws_sec_key].value_len,
		WS_MAGIC, olen);

	olen = ctx->http.field_values[ws_sec_key].value_len +
		sizeof(WS_MAGIC) - 1;

	mbedtls_sha1(key_accept, olen, accept);

	snprintk(tmp, sizeof(tmp), "Sec-WebSocket-Accept: ");

	ret = mbedtls_base64_encode(tmp + sizeof("Sec-WebSocket-Accept: ") - 1,
				    sizeof(tmp) -
				    (sizeof("Sec-WebSocket-Accept: ") - 1),
				    &olen, accept, sizeof(accept));
	if (ret) {
		if (ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
			NET_DBG("[%p] Too short buffer olen %zd", ctx, olen);
		}

		goto fail;
	}

	snprintk(tmp + sizeof("Sec-WebSocket-Accept: ") - 1 + olen,
		 sizeof(tmp) - (sizeof("Sec-WebSocket-Accept: ") - 1) - olen,
		 "\r\n\r\n");

	if (!net_pkt_append_all(pkt, strlen(tmp), (u8_t *)tmp, ctx->timeout)) {
		goto fail;
	}

	return pkt;

fail:
	net_pkt_unref(pkt);
	return NULL;
}

int ws_headers_complete(struct http_parser *parser)
{
	struct http_ctx *ctx = parser->data;
	int ws_sec_key = -1, host = -1, subprotocol = -1;

	if (check_ws_headers(ctx, parser, &ws_sec_key, &host,
			     &subprotocol)) {
		struct net_pkt *pkt;
		struct http_root_url *url;
		int ret;

		url = http_url_find(ctx, HTTP_URL_WEBSOCKET);
		if (!url) {
			url = http_url_find(ctx, HTTP_URL_STANDARD);
			if (url) {
				/* Normal HTTP URL was found */
				return 0;
			}

			/* If there is no URL to serve this websocket
			 * request, then just bail out.
			 */
			if (!ctx->http.urls) {
				NET_DBG("[%p] No URL handlers found", ctx);
				return 0;
			}

			url = &ctx->http.urls->default_url;
			if (url && url->is_used &&
			    ctx->http.urls->default_cb) {
				ret = ctx->http.urls->default_cb(ctx,
								WS_CONNECTION);
				if (ret == HTTP_VERDICT_ACCEPT) {
					goto accept;
				}
			}

			if (url->flags == HTTP_URL_WEBSOCKET) {
				goto fail;
			}
		}

		if (url->flags != HTTP_URL_WEBSOCKET) {
			return 0;
		}

	accept:
		NET_DBG("[%p] ws header %d fields found", ctx,
			ctx->http.field_values_ctr + 1);

		pkt = prepare_reply(ctx, ws_sec_key, host, subprotocol);
		if (!pkt) {
			goto fail;
		}

		net_pkt_set_appdatalen(pkt, net_buf_frags_len(pkt->frags));

		ret = net_app_send_pkt(&ctx->app_ctx, pkt, NULL, 0, 0,
				       INT_TO_POINTER(K_FOREVER));
		if (ret) {
			goto fail;
		}

		http_change_state(ctx, HTTP_STATE_HEADER_RECEIVED);

		/* We do not expect any HTTP data after this */
		return 2;

	fail:
		http_change_state(ctx, HTTP_STATE_CLOSED);
	}

	return 0;
}
