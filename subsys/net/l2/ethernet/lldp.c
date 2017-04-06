/** @file
 * @brief LLDP related functions
 */

/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <net/ethernet.h>
#include <net/lldp.h>
#include <net/net_mgmt.h>
#include <net/nbuf.h>

#if defined(CONFIG_NET_DEBUG_LLDP)
#define SYS_LOG_DOMAIN "net/lldp"
#define NET_LOG_ENABLED 1
#endif

static struct k_delayed_work lldp_tx_work;
static struct net_if *eth_iface;

#if defined(CONFIG_NET_MGMT_EVENT)
static struct net_mgmt_event_callback cb;
#endif


static void lldp_tx(struct k_work *work)
{
	static const struct net_eth_addr lldp_multicast_eth_addr = {
	{ 0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e } };

	struct net_eth_context *ctx = net_if_l2_data(eth_iface);
	uint16_t pos;

	struct net_buf *b = net_nbuf_get_reserve_tx(
		net_if_get_ll_reserve(eth_iface, NULL), K_FOREVER);
	if (!b) {
	        NET_DBG("Unable to get TX buffer, not enough memory.\n");
	}

	struct net_buf *f = net_nbuf_get_frag(b, K_FOREVER);
	if (!f) {
	        NET_DBG("Unable to get DATA buffer, not enough memory.\n");
	}

	net_buf_frag_add(b, f);

	net_nbuf_write(b, f, 0, &pos, sizeof(struct net_lldpdu),
		(uint8_t*) ctx->lldpdu, K_FOREVER);

	struct net_eth_hdr *hdr = NET_ETH_BUF(b);
	hdr->type = htons(NET_ETH_PTYPE_LLDP);
	memcpy(hdr->dst.addr, lldp_multicast_eth_addr.addr,
		sizeof(struct net_eth_addr));
	memcpy(hdr->src.addr, net_if_get_link_addr(eth_iface)->addr,
		sizeof(struct net_eth_addr));

	eth_iface->l2->send(eth_iface, b);

	k_delayed_work_submit(&lldp_tx_work,
		CONFIG_NET_LLDP_TX_INTERVAL * 1000);
}

static void ethernet_iface_up(struct net_mgmt_event_callback *cb,
			      uint32_t mgmt_event, struct net_if *iface)
{
	if (eth_iface == iface) {
		k_delayed_work_init(&lldp_tx_work, lldp_tx);
		k_delayed_work_submit(&lldp_tx_work,
			CONFIG_NET_LLDP_TX_INTERVAL * 1000);
	}
}

int net_lldp_enable(struct net_if *iface, bool enable)
{
	if (!iface) {
		return -EINVAL;
	}

	/* FIXME: Implement disable routine for NET_EVENT_IF_DOWN. */
	if (enable) {
		eth_iface = iface;

		if (atomic_test_bit(iface->flags, NET_IF_UP)) {
			ethernet_iface_up(NULL, NET_EVENT_IF_UP, iface);
			return 0;
		}

#if defined(CONFIG_NET_MGMT_EVENT)
		net_mgmt_init_event_callback(&cb, ethernet_iface_up,
					     NET_EVENT_IF_UP);
		net_mgmt_add_event_callback(&cb);
#endif
	}

	return 0;
}
