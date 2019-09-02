/*
 * Copyright (c) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 *
 * PPP over Ethernet driver.
 */

#define LOG_LEVEL CONFIG_NET_PPP_LOG_LEVEL
#include <logging/log.h>
LOG_MODULE_REGISTER(net_ppp, LOG_LEVEL);

#include <stdio.h>

#include <kernel.h>

#include <stdbool.h>
#include <errno.h>
#include <stddef.h>
#include <net/ppp.h>
#include <net/buf.h>
#include <net/net_pkt.h>
#include <net/net_if.h>
#include <net/net_core.h>
#include <net/ethernet.h>
#include <crc.h>

#include "../../subsys/net/ip/net_stats.h"
#include "../../subsys/net/ip/net_private.h"

#define PPPOE_STARTUP_DELAY K_MSEC(100)

enum pppoe_driver_state {
	STATE_DISCOVERY,
	STATE_SESSION,
};

struct pppoe_driver_context {
	/** PPP discover worker. */
	struct k_delayed_work discover;

	/* PPP interface */
	struct net_if *iface;

	/* Ethernet device where the packet is directed */
	struct device *eth_dev;

	u8_t mac_addr[6];
	struct net_linkaddr ll_addr;

#if defined(CONFIG_NET_STATISTICS_PPP)
	struct net_stats_ppp stats;
#endif
	int discovery_delay;

	enum pppoe_driver_state state;

	u8_t init_done : 1;
	u8_t next_escaped : 1;
};

static struct pppoe_driver_context pppoe_driver_context_data;

static const char *pppoe_driver_state_str(enum pppoe_driver_state state)
{
#if (CONFIG_NET_PPP_LOG_LEVEL >= LOG_LEVEL_DBG)
	switch (state) {
	case STATE_DISCOVERY:
		return "DISCOVERY";
	case STATE_SESSION:
		return "SESSION";
	}
#else
	ARG_UNUSED(state);
#endif

	return "";
}

static void pppoe_change_state(struct pppoe_driver_context *ctx,
			       enum pppoe_driver_state new_state)
{
	NET_ASSERT(ctx);

	if (ctx->state == new_state) {
		return;
	}

	NET_ASSERT(new_state >= STATE_DISCOVERY &&
		   new_state <= STATE_SESSION);

	NET_DBG("[%p] state %s (%d) => %s (%d)",
		ctx, pppoe_driver_state_str(ctx->state), ctx->state,
		pppoe_driver_state_str(new_state), new_state);

	ctx->state = new_state;
}

static bool pppoe_check_fcs(struct pppoe_driver_context *ppp,
			    struct net_pkt *pkt)
{
	struct net_buf *buf;
	u16_t crc;

	buf = pkt->buffer;
	if (!buf) {
		return false;
	}

	crc = crc16_ccitt(0xffff, buf->data, buf->len);

	buf = buf->frags;

	while (buf) {
		crc = crc16_ccitt(crc, buf->data, buf->len);
		buf = buf->frags;
	}

	if (crc != 0xf0b8) {
		LOG_DBG("Invalid FCS (0x%x)", crc);
#if defined(CONFIG_NET_STATISTICS_PPP)
		ppp->stats.chkerr++;
#endif
		return false;
	}

	return true;
}

static enum net_verdict pppoe_process_msg(struct pppoe_driver_context *ppp,
					  struct net_if *iface,
					  struct net_pkt *pkt)
{
	if (LOG_LEVEL >= LOG_LEVEL_DBG) {
		net_pkt_hexdump(pkt, "recv ppp");
	}

	if (IS_ENABLED(CONFIG_NET_PPP_VERIFY_FCS) &&
	    !pppoe_check_fcs(ppp, pkt)) {
#if defined(CONFIG_NET_STATISTICS_PPP)
		ppp->stats.drop++;
		ppp->stats.pkts.rx++;
#endif
		return NET_DROP;
	} else {
		/* Remove the Address (0xff), Control (0x03) and
		 * FCS fields (16-bit) as the PPP L2 layer does not need
		 * those bytes.
		 */
		u16_t addr_and_ctrl = net_buf_pull_be16(pkt->buffer);

		/* Currently we do not support compressed Address and Control
		 * fields so they must always be present.
		 */
		if (addr_and_ctrl != (0xff << 8 | 0x03)) {
#if defined(CONFIG_NET_STATISTICS_PPP)
			ppp->stats.drop++;
			ppp->stats.pkts.rx++;
#endif
			return NET_DROP;
		} else {
			/* Skip FCS bytes (2) */
			net_buf_frag_last(pkt->buffer)->len -= 2;

			/* Make sure we now start reading from PPP header in
			 * PPP L2 recv()
			 */
			net_pkt_cursor_init(pkt);
			net_pkt_set_overwrite(pkt, true);

			net_pkt_set_iface(pkt, ppp->iface);

			if (net_recv_data(ppp->iface, pkt) < 0) {
				return NET_DROP;
			}
		}
	}

	return NET_CONTINUE;
}

static bool calc_fcs(struct net_pkt *pkt, u16_t *fcs, u16_t protocol)
{
	struct net_buf *buf;
	u16_t crc;
	u16_t c;

	buf = pkt->buffer;
	if (!buf) {
		return false;
	}

	/* HDLC Address and Control fields */
	c = sys_cpu_to_be16(0xff << 8 | 0x03);

	crc = crc16_ccitt(0xffff, (const u8_t *)&c, sizeof(c));

	if (protocol > 0) {
		crc = crc16_ccitt(crc, (const u8_t *)&protocol,
				  sizeof(protocol));
	}

	while (buf) {
		crc = crc16_ccitt(crc, buf->data, buf->len);
		buf = buf->frags;
	}

	crc ^= 0xffff;
	*fcs = crc;

	return true;
}

static int pppoe_send(struct device *dev, struct net_pkt *pkt)
{
#if 0
	struct pppoe_driver_context *ppp = dev->driver_data;
	struct net_buf *buf = pkt->buffer;
	u16_t protocol = 0;
	int send_off = 0;
	u32_t sync_addr_ctrl;
	u16_t fcs, escaped;
	u8_t byte;
	int i, offset;

#if defined(CONFIG_NET_TEST)
	return 0;
#endif

	ARG_UNUSED(dev);

	if (!buf) {
		/* No data? */
		return -ENODATA;
	}

	/* If the packet is a normal network packet, we must add the protocol
	 * value here.
	 */
	if (!net_pkt_is_ppp(pkt)) {
		if (net_pkt_family(pkt) == AF_INET) {
			protocol = htons(PPP_IP);
		} else if (net_pkt_family(pkt) == AF_INET6) {
			protocol = htons(PPP_IPV6);
		} else {
			return -EPROTONOSUPPORT;
		}
	}

	if (!calc_fcs(pkt, &fcs, protocol)) {
		return -ENOMEM;
	}

	/* Sync, Address & Control fields */
	sync_addr_ctrl = sys_cpu_to_be32(0x7e << 24 | 0xff << 16 |
					 0x7d << 8 | 0x23);
	send_off = ppp_send_bytes(ppp, (const u8_t *)&sync_addr_ctrl,
				  sizeof(sync_addr_ctrl), send_off);

	if (protocol > 0) {
		escaped = htons(ppp_escape_byte(protocol, &offset));
		send_off = ppp_send_bytes(ppp, (u8_t *)&escaped + offset,
					  offset ? 1 : 2,
					  send_off);

		escaped = htons(ppp_escape_byte(protocol >> 8, &offset));
		send_off = ppp_send_bytes(ppp, (u8_t *)&escaped + offset,
					  offset ? 1 : 2,
					  send_off);
	}

	/* Note that we do not print the first four bytes and FCS bytes at the
	 * end so that we do not need to allocate separate net_buf just for
	 * that purpose.
	 */
	if (LOG_LEVEL >= LOG_LEVEL_DBG) {
		net_pkt_hexdump(pkt, "send ppp");
	}


	escaped = htons(ppp_escape_byte(fcs, &offset));
	send_off = ppp_send_bytes(ppp, (u8_t *)&escaped + offset,
				  offset ? 1 : 2,
				  send_off);

	escaped = htons(ppp_escape_byte(fcs >> 8, &offset));
	send_off = ppp_send_bytes(ppp, (u8_t *)&escaped + offset,
				  offset ? 1 : 2,
				  send_off);

	byte = 0x7e;
	send_off = ppp_send_bytes(ppp, &byte, 1, send_off);

	(void)ppp_send_flush(ppp, send_off);
#endif
	return 0;
}

static int pppoe_driver_init(struct device *dev)
{
	struct pppoe_driver_context *ppp = dev->driver_data;

	LOG_DBG("[%p] dev %p", ppp, dev);

	pppoe_change_state(ppp, STATE_DISCOVERY);

	return 0;
}

static struct net_pkt *pppoe_create_packet(struct net_if *iface,
					   u8_t code, u16_t session_id,
					   u16_t len, u8_t *tags)
{
	struct net_pkt *pkt;
	int ret;

	pkt = net_pkt_alloc_with_buffer(iface,
					sizeof(u8_t) + sizeof(code) +
					sizeof(session_id) + sizeof(len) +
					len + sizeof(u16_t) /* eof */,
					AF_UNSPEC, 0, K_NO_WAIT);
	if (!pkt) {
		LOG_DBG("Alloc failed");
		goto out;
	}

	ret = net_pkt_write_be32(pkt,
				 /* version and type are fixed */
				 (BIT(4) | BIT(0)) << 24 |
				 code << 16 | session_id);
	if (ret < 0) {
		goto free;
	}

	ret = net_pkt_write_be16(pkt, len);
	if (ret < 0) {
		goto free;
	}

	ret = net_pkt_write(pkt, tags, len);
	if (ret < 0) {
		goto free;
	}

	/* End-of-tag is the last one */
	ret = net_pkt_write_be16(pkt, 0x00);
	if (ret < 0) {
		goto free;
	}

	return pkt;

free:
	net_pkt_unref(pkt);

out:
	return NULL;
}

static struct net_pkt *pppoe_create_padi(struct net_if *iface,
					 u16_t len, u8_t *tags)
{
	struct net_pkt *pkt;

	/* The session (0x0000) for PADI packets is specified in RFC 2516 */
	pkt = pppoe_create_packet(iface, PPPOE_PADI, 0x0000, len, tags);

	net_pkt_lladdr_dst(pkt)->addr = net_eth_broadcast_addr()->addr;
	net_pkt_lladdr_dst(pkt)->len = sizeof(((struct net_eth_addr *)0)->addr);

	return pkt;
}

static void pppoe_discover(struct k_work *work)
{
	struct pppoe_driver_context *ppp =
		CONTAINER_OF(work, struct pppoe_driver_context, discover);

	struct net_pkt *pkt = NULL;
	int ret = -ENOENT;
	struct net_if *iface;

	iface = net_if_lookup_by_dev(ppp->eth_dev);
	if (!iface) {
		LOG_DBG("Cannot get Ethernet iface");
		goto resend;
	}

	pkt = pppoe_create_padi(iface,
				/* The terminating NULL is not transmitted */
				sizeof(CONFIG_NET_PPPOE_SERVICE_NAME) - 1,
				CONFIG_NET_PPPOE_SERVICE_NAME);
	if (!pkt) {
		LOG_DBG("Cannot create %s", "PADI");
		goto resend;
	}

	net_pkt_set_ppp(pkt, true);
	net_pkt_set_pppoe_discovery_type(pkt, true);

	net_pkt_lladdr_src(pkt)->addr = net_pkt_lladdr_if(pkt)->addr;
	net_pkt_lladdr_src(pkt)->len = net_pkt_lladdr_if(pkt)->len;

	ret = net_if_l2(iface)->send(iface, pkt);
	if (ret < 0) {
		LOG_DBG("Cannot send %s", "PADI");
		goto resend;
	}

resend:
	if (ret < 0 && pkt) {
		net_pkt_unref(pkt);
	}

	ppp->discovery_delay <<= 1;

	if (ppp->discovery_delay > CONFIG_NET_PPPOE_MAX_WAIT_IN_DISCOVERY) {
		ppp->discovery_delay = CONFIG_NET_PPPOE_MAX_WAIT_IN_DISCOVERY;
	}

	k_delayed_work_submit(&ppp->discover, K_SECONDS(ppp->discovery_delay));
}

static void pppoe_start_discovery(struct pppoe_driver_context *ppp)
{
	k_delayed_work_submit(&ppp->discover,
			      K_MSEC(CONFIG_NET_PPPOE_DELAY_STARTUP_MS));
}

static void pppoe_startup(struct k_work *work)
{
	struct pppoe_driver_context *ppp =
		CONTAINER_OF(work, struct pppoe_driver_context, discover);

	struct net_linkaddr *ll_addr;

	/* The MAC address is set to be the same as what Ethernet has as
	 * we are passing packets via that interface anyway
	 */
	ll_addr = net_if_get_link_addr(net_if_lookup_by_dev(ppp->eth_dev));
	if (ll_addr->addr) {
		net_if_set_link_addr(ppp->iface, ll_addr->addr, ll_addr->len,
				     NET_LINK_ETHERNET);
	} else {
		/* Ethernet is not yet ready, try again */
		k_delayed_work_submit(&ppp->discover,
				      PPPOE_STARTUP_DELAY);
		return;
	}

	/* Start the PPPoE Discovery procedure, RFC 2516 chapter 5 */
	k_delayed_work_init(&ppp->discover, pppoe_discover);
	ppp->discovery_delay = K_MSEC(1);
	pppoe_start_discovery(ppp);
}

static void pppoe_iface_init(struct net_if *iface)
{
	struct pppoe_driver_context *ppp =
		net_if_get_device(iface)->driver_data;

	LOG_DBG("[%p] iface %p", ppp, iface);

	net_ppp_init(iface);

	if (ppp->init_done) {
		return;
	}

	ppp->init_done = true;
	ppp->iface = iface;

	/* The PPP interface will go up after the Discovery has finished
	 * and we are in Session state.
	 */
	net_if_flag_set(iface, NET_IF_NO_AUTO_START);

	/* If user has not defined the Ethernet device, then take the first
	 * one.
	 */
	if (CONFIG_NET_PPPOE_ETH_DRV_NAME[0] == '\0') {
		struct net_if *eth_iface;

		eth_iface = net_if_get_first_by_type(
						&NET_L2_GET_NAME(ETHERNET));
		ppp->eth_dev = net_if_get_device(eth_iface);
	} else {
		ppp->eth_dev =
			device_get_binding(CONFIG_NET_PPPOE_ETH_DRV_NAME);
	}

	if (!ppp->eth_dev) {
		LOG_ERR("Ethernet dev not found");
	} else {
		LOG_DBG("Using %s Ethernet device", ppp->eth_dev->config->name);
	}

	/* The network interface startup is delayed a bit so that the
	 * Ethernet network interface is properly setup because we need
	 * the Ethernet to have MAC address set.
	 */
	k_delayed_work_init(&ppp->discover, pppoe_startup);
	k_delayed_work_submit(&ppp->discover, PPPOE_STARTUP_DELAY);
}

#if defined(CONFIG_NET_STATISTICS_PPP)
static struct net_stats_ppp *pppoe_get_stats(struct device *dev)
{
	struct pppoe_driver_context *context = dev->driver_data;

	return &context->stats;
}
#endif

static int pppoe_start(struct device *dev)
{
	struct pppoe_driver_context *context = dev->driver_data;

	net_ppp_carrier_on(context->iface);

	return 0;
}

static int pppoe_stop(struct device *dev)
{
	struct pppoe_driver_context *context = dev->driver_data;

	net_ppp_carrier_off(context->iface);

	return 0;
}

static const struct ppp_api pppoe_if_api = {
	.iface_api.init = pppoe_iface_init,

	.send = pppoe_send,
	.start = pppoe_start,
	.stop = pppoe_stop,
#if defined(CONFIG_NET_STATISTICS_PPP)
	.get_stats = pppoe_get_stats,
#endif
};

enum net_verdict net_pppoe_recv(struct net_if *iface, struct net_pkt *pkt)
{
	return pppoe_process_msg(&pppoe_driver_context_data, iface, pkt);
}

/* Note that Ethernet device must be setup before pppoe
 * as otherwise we cannot setup things properly in this driver.
 */
NET_DEVICE_INIT(pppoe, CONFIG_NET_PPPOE_DRV_NAME, pppoe_driver_init,
		&pppoe_driver_context_data, NULL,
		CONFIG_KERNEL_INIT_PRIORITY_DEVICE, &pppoe_if_api,
		PPP_L2, NET_L2_GET_CTX_TYPE(PPP_L2), PPPOE_MTU);
