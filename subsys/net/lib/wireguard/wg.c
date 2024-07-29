/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @file
 *  @brief Wireguard VPN implementation
 */

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(wireguard, CONFIG_WIREGUARD_LOG_LEVEL);

#include <zephyr/kernel.h>
#include <zephyr/random/random.h>
#include <zephyr/sys/slist.h>
#include <zephyr/sys/base64.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_mgmt.h>
#include <zephyr/net/net_event.h>
#include <zephyr/net/dummy.h>
#include <zephyr/net/virtual.h>
#include <zephyr/net/virtual_mgmt.h>
#include <zephyr/net/wireguard.h>

#include "net_private.h"
#include "udp_internal.h"
#include "wg_internal.h"

#if defined(CONFIG_WIREGUARD_TXRX_DEBUG)
#define DEBUG_TX 1
#define DEBUG_RX 1
#else
#define DEBUG_TX 0
#define DEBUG_RX 0
#endif

static const uint8_t zero_key[WG_PUBLIC_KEY_LEN];

static K_MUTEX_DEFINE(lock);

static struct wg_peer peers[CONFIG_WIREGUARD_MAX_PEER];
static sys_slist_t peer_list;
static sys_slist_t active_peers;

static struct wg_context {
	struct net_mgmt_event_callback wg_mgmt_cb;
	struct net_if *iface; /* control interface */
	int ifindex;          /* output network interface if set */
	uint8_t construction_hash[WG_HASH_LEN];
	uint8_t identifier_hash[WG_HASH_LEN];
	bool status;
} wg_ctx;

static enum net_verdict wg_input(struct net_conn *conn,
				 struct net_pkt *pkt,
				 union net_ip_header *ip_hdr,
				 union net_proto_header *proto_hdr,
				 void *user_data)
{
	struct wg_context *ctx = user_data;
	int ret;

	ARG_UNUSED(conn);
	ARG_UNUSED(ip_hdr);
	ARG_UNUSED(proto_hdr);

	net_pkt_set_wg_iface(pkt, net_pkt_iface(pkt));

	/* Feed the data to Wireguard control interface which
	 * will decrypt it and then pass it to the virtual interface
	 * handling that connection if such connection is found.
	 */
	ret = net_recv_data(ctx->iface, pkt);
	if (ret < 0) {
		return NET_DROP;
	}

	return NET_OK;
}

static void wg_iface_event_handler(struct net_mgmt_event_callback *cb,
				   uint32_t mgmt_event, struct net_if *iface)
{
	struct wg_context *context =
		CONTAINER_OF(cb, struct wg_context, wg_mgmt_cb);

	if (mgmt_event != NET_EVENT_IF_DOWN && mgmt_event != NET_EVENT_IF_UP) {
		return;
	}

	if (context->ifindex > 0 &&
	    context->ifindex != net_if_get_by_iface(iface)) {
		return;
	}

	if (mgmt_event == NET_EVENT_IF_DOWN) {
		NET_DBG("Interface %d going down", net_if_get_by_iface(iface));
	} else if (mgmt_event == NET_EVENT_IF_UP) {
		NET_DBG("Interface %d coming up", net_if_get_by_iface(iface));
	}
}

static uint16_t get_port(struct sockaddr *addr)
{
	uint16_t local_port;
	int max_count = 10;

	do {
		local_port = sys_rand16_get() | 0x8000;

		if (--max_count < 0) {
			NET_ERR("Cannot get Wireguard service port");
			local_port = 0;
			break;
		}
	} while (net_context_port_in_use(IPPROTO_UDP, local_port, addr));

	return local_port;
}

static void crypto_init(struct wg_context *ctx)
{
	wireguard_blake2s_ctx bl_ctx;

	wireguard_blake2s_init(&bl_ctx, WG_HASH_LEN, NULL, 0);
	wireguard_blake2s_update(&bl_ctx, CONSTRUCTION, sizeof(CONSTRUCTION));
	wireguard_blake2s_final(&bt_ctx, ctx->construction_hash);

	wireguard_blake2s_init(&bl_ctx, WIREGUARD_HASH_LEN, NULL, 0);
	wireguard_blake2s_update(&bl_ctx, ctx->construction_hash,
				 sizeof(ctx->construction_hash));
	wireguard_blake2s_update(&bl_ctx, IDENTIFIER, sizeof(IDENTIFIER));
	wireguard_blake2s_final(&bl_ctx, ctx->identifier_hash);
}

int wireguard_init(void)
{
	struct sockaddr local_addr = { 0 };
	const struct device *dev;
	struct wg_context *ctx;
	uint16_t port;
	int ret;

	dev = device_get_binding(WIREGUARD_CTRL_DEVICE);
	if (dev == NULL) {
		NET_DBG("No such device %s found, Wireguard is disabled!",
			WIREGUARD_CTRL_DEVICE);
		return -ENOENT;
	}

	ctx = dev->data;

	for (int i = 0; i < ARRAY_SIZE(peers); i++) {
		sys_slist_prepend(&peer_list, &peers[i].node);
	}

	if (WG_INTERFACE[0] != '\0') {
		ret = net_if_get_by_name(WG_INTERFACE);
		if (ret < 0) {
			NET_ERR("Cannot find interface \"%s\" (%d)",
				WG_INTERFACE, ret);
			return -ENOENT;
		}

		ctx->ifindex = ret;
	}

	crypto_init(ctx);

	if (IS_ENABLED(CONFIG_NET_IPV6)) {
		local_addr.sa_family = AF_INET6;

		/* Note that if IPv4 is enabled, then v4-to-v6-mapping option
		 * is set and the system will use the IPv6 socket to provide
		 * IPv4 connectivity.
		 */
	} else if (IS_ENABLED(CONFIG_NET_IPV4)) {
		local_addr.sa_family = AF_INET;
	}

	port = COND_CODE_1(CONFIG_WIREGUARD_SERVER,
			   (CONFIG_WIREGUARD_SERVER_PORT),
			   (get_port(&local_addr)));
	if (port == 0U) {
		NET_ERR("Cannot get free port.");
		return -ENOENT;
	}

	ret = net_udp_register(local_addr.sa_family,
			       NULL,
			       &local_addr,
			       0,
			       port,
			       NULL,
			       wg_input,
			       ctx,
			       NULL);
	if (ret < 0) {
		NET_ERR("Cannot register Wireguard service handler (%d)", ret);
		return ret;
	}

	net_mgmt_init_event_callback(&ctx->wg_mgmt_cb, wg_iface_event_handler,
				     NET_EVENT_IF_DOWN | NET_EVENT_IF_UP);
	net_mgmt_add_event_callback(&ctx->wg_mgmt_cb);

	return 0;
}

static void wg_ctrl_iface_init(struct net_if *iface)
{
	struct wg_context *ctx = net_if_get_device(iface)->data;
	int ret;

	ctx->iface = iface;

	ret = net_if_set_name(iface, "wg_ctrl");
	if (ret < 0) {
		NET_DBG("Cannot set interface name (%d)", ret);
	}

	/* The control interface is turned off by default, and it will
	 * turn on after the first VPN connection. User is not able to
	 * manually turn the control interface up if there are no VPN
	 * connections configured.
	 */
	net_if_flag_set(iface, NET_IF_NO_AUTO_START);
	net_if_flag_set(iface, NET_IF_IPV6_NO_MLD);
	net_if_flag_clear(iface, NET_IF_IPV6);
	net_if_flag_clear(iface, NET_IF_IPV4);
}

static enum net_verdict wg_ctrl_recv(struct net_if *iface, struct net_pkt *pkt)
{
	enum net_verdict verdict = NET_DROP;

	if (!pkt->buffer) {
		goto drop;
	}

	/* Make sure we received a proper packet, decrypt it and pass it to
	 * correct virtual interface.
	 */

drop:
	return verdict;
}

static int wg_ctrl_send(const struct device *dev, struct net_pkt *pkt)
{
	ARG_UNUSED(dev);

	/* Encrypt the packet and send to peer */

	net_pkt_unref(pkt);

	return 0;
}

static int wg_ctrl_start(const struct device *dev)
{
	struct wg_context *ctx = dev->data;
	int ret = 0;

	if (ctx->status) {
		return -EALREADY;
	}

	if (sys_slist_is_empty(&active_peers)) {
		return -ENODATA;
	}

	ctx->status = true;

	NET_DBG("Starting iface %d", net_if_get_by_iface(ctx->iface));

	return ret;
}

static int wg_ctrl_stop(const struct device *dev)
{
	struct wg_context *ctx = dev->data;

	if (!ctx->status) {
		return -EALREADY;
	}

	ctx->status = false;

	NET_DBG("Stopping iface %d", net_if_get_by_iface(ctx->iface));

	return 0;
}

static struct dummy_api wg_api = {
	.iface_api.init = wg_ctrl_iface_init,
	.recv = wg_ctrl_recv,
	.send = wg_ctrl_send,
	.start = wg_ctrl_start,
	.stop = wg_ctrl_stop,
};

/* Wireguard control interface is a dummy network interface that just
 * encrypts sent data and decrypts received data, and acts as a middle
 * man between the real network interface and the virtual network
 * interface (like wg0) where the application reads/writes the data.
 */
NET_DEVICE_INIT(wireguard,
		WIREGUARD_CTRL_DEVICE,
		NULL,    /* init fn */
		NULL,    /* pm */
		&wg_ctx, /* data */
		NULL,    /* config */
		CONFIG_KERNEL_INIT_PRIORITY_DEFAULT,
		&wg_api,
		DUMMY_L2,
		NET_L2_GET_CTX_TYPE(DUMMY_L2),
		WG_MTU);

/* Each Wireguard virtual interface is tied to one specific peer connection */
struct wg_iface_context {
	const char *name;
	struct net_if *iface;
	struct net_if *attached_to;
	union {
		sa_family_t family;
		struct net_addr peer;
	};

	union {
		const struct in_addr *my4addr;
		const struct in6_addr *my6addr;
	};

	bool is_used;
	bool status;
	bool init_done;
};

static void iface_init(struct net_if *iface)
{
	struct wg_iface_context *ctx = net_if_get_device(iface)->data;

	if (ctx->init_done) {
		return;
	}

	ctx->iface = iface;

	net_if_flag_set(iface, NET_IF_NO_AUTO_START);
	net_if_flag_set(iface, NET_IF_POINTOPOINT);
	(void)net_if_set_name(iface, ctx->name);

	(void)net_virtual_set_name(iface, "Wireguard VPN");
	(void)net_virtual_set_flags(iface, NET_L2_POINT_TO_POINT);

	ctx->init_done = true;
}

static enum virtual_interface_caps get_capabilities(struct net_if *iface)
{
	ARG_UNUSED(iface);

	return VIRTUAL_INTERFACE_VPN;
}

static int interface_start(const struct device *dev)
{
	struct wg_iface_context *ctx = dev->data;
	int ret = 0;

	if (ctx->status) {
		return -EALREADY;
	}

	ctx->status = true;

	NET_DBG("Starting iface %d", net_if_get_by_iface(ctx->iface));

	return ret;
}

static int interface_stop(const struct device *dev)
{
	struct wg_iface_context *ctx = dev->data;

	if (!ctx->status) {
		return -EALREADY;
	}

	ctx->status = false;

	NET_DBG("Stopping iface %d", net_if_get_by_iface(ctx->iface));

	return 0;
}

static int interface_attach(struct net_if *iface, struct net_if *lower_iface)
{
	struct wg_iface_context *ctx;

	if (net_if_get_by_iface(iface) < 0) {
		return -ENOENT;
	}

	ctx = net_if_get_device(iface)->data;
	ctx->attached_to = lower_iface;

	return 0;
}

static int interface_send(struct net_if *iface, struct net_pkt *pkt)
{
	struct wg_iface_context *ctx = net_if_get_device(iface)->data;

	if (ctx->attached_to == NULL) {
		return -ENOENT;
	}

	if (net_pkt_family(pkt) != AF_INET &&
	    net_pkt_family(pkt) != AF_INET6) {
		return -EINVAL;
	}

	if (DEBUG_TX) {
		char str[sizeof("TX iface xx")];

		snprintk(str, sizeof(str), "TX iface %d",
			 net_if_get_by_iface(net_pkt_iface(pkt)));

		net_pkt_hexdump(pkt, str);
	}

	return net_send_data(pkt);
}

static enum net_verdict interface_recv(struct net_if *iface,
				       struct net_pkt *pkt)
{
	if (DEBUG_RX) {
		char str[sizeof("RX iface xx")];

		snprintk(str, sizeof(str), "RX iface %d",
			 net_if_get_by_iface(iface));

		net_pkt_hexdump(pkt, str);
	}

	if (IS_ENABLED(CONFIG_NET_IPV6) && net_pkt_family(pkt) == AF_INET6) {
		return net_ipv6_input(pkt, false);
	}

	if (IS_ENABLED(CONFIG_NET_IPV4) && net_pkt_family(pkt) == AF_INET) {
		return net_ipv4_input(pkt, false);
	}

	return NET_CONTINUE;
}

static const struct virtual_interface_api wg_iface_api = {
	.iface_api.init = iface_init,

	.get_capabilities = get_capabilities,
	.start = interface_start,
	.stop = interface_stop,
	.attach = interface_attach,
	.send = interface_send,
	.recv = interface_recv,
	//.set_config = interface_set_config,
	//.get_config = interface_get_config,
};

#define WG_INTERFACE_INIT(x, _)						\
	static struct wg_iface_context wg_iface_context_data_##x = {	\
		.name =	"wg" #x,					\
	};								\
									\
	NET_VIRTUAL_INTERFACE_INIT_INSTANCE(wg_##x,			\
					    "WIREGUARD" #x,		\
					    x,				\
					    NULL,			\
					    NULL,			\
					    &wg_iface_context_data_##x,	\
					    NULL, /* config */		\
					    CONFIG_KERNEL_INIT_PRIORITY_DEFAULT, \
					    &wg_iface_api,		\
					    WG_MTU)

LISTIFY(CONFIG_WIREGUARD_MAX_PEER, WG_INTERFACE_INIT, (;), _);

/* Lock must be held when calling this function */
static struct wg_peer *peer_lookup_by_pubkey(const char *public_key)
{
	struct wg_peer *peer, *next;

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&active_peers,
					  peer, next, node) {
		if (memcmp(peer->public_key, public_key, WG_PUBLIC_KEY_LEN) == 0) {
			return peer;
		}
	}

	return NULL;
}

static struct wg_peer *peer_lookup_by_id(uint8_t id)
{
	struct wg_peer *peer, *next;

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&active_peers,
					  peer, next, node) {
		if (peer->id == id) {
			return peer;
		}
	}

	return NULL;
}

static bool extract_public_key(const char *str, uint8_t *out, size_t outlen)
{
	size_t len;

	if (base64_decode(out, outlen, &len, str, strlen(str)) < 0) {
		return false;
	}

	if (len != outlen) {
		return false;
	}

	return true;
}

static void iface_cb(struct net_if *iface, void *user_data)
{
	struct net_if **ret_iface = user_data;

	if ((net_if_l2(iface) != &NET_L2_GET_NAME(VIRTUAL))) {
		return;
	}

	if (net_virtual_get_iface_capabilities(iface) != VIRTUAL_INTERFACE_VPN) {
		return;
	}

	/* Ignore already attached interfaces */
	if (net_virtual_get_iface(iface) != NULL) {
		return;
	}

	if (*ret_iface == NULL) {
		*ret_iface = iface;
	}
}

int wireguard_peer_add(struct wireguard_peer_config *peer_config,
		       struct net_if **peer_iface)
{
	static int id;
	uint8_t public_key[WG_PUBLIC_KEY_LEN];
	struct net_if *iface = NULL;
	struct wg_peer *peer;
	sys_snode_t *node;
	int ret;

	if (peer_config->public_key == NULL) {
		return -EINVAL;
	}

	if (!extract_public_key(peer_config->public_key, public_key,
				WG_PUBLIC_KEY_LEN)) {
		NET_DBG("Invalid public_key base64 format.");
		return -EINVAL;
	}

	k_mutex_lock(&lock, K_FOREVER);

	peer = peer_lookup_by_pubkey(public_key);
	if (peer != NULL) {
		ret = -EALREADY;
		goto out;
	}

	/* Try to find out available virtual network interface */
	net_if_foreach(iface_cb, &iface);

	if (iface == NULL) {
		ret = -ENOMEM;
		NET_INFO("No available Wireguard interfaces found.");
		goto out;
	}

	ret = net_virtual_interface_attach(iface, wg_ctx.iface);
	if (ret < 0) {
		NET_DBG("Cannot attach %d to %d",
			net_if_get_by_iface(iface),
			net_if_get_by_iface(wg_ctx.iface));
		goto out;
	}

	/* We could find an interface, now allocate the peer */
	node = sys_slist_get(&peer_list);
	if (node == NULL) {
		(void)net_virtual_interface_attach(iface, NULL);
		ret = -ENOMEM;
		goto out;
	}

	sys_slist_prepend(&active_peers, node);

	peer = CONTAINER_OF(node, struct wg_peer, node);

	memcpy(peer->public_key, public_key, sizeof(peer->public_key));
	memcpy(&peer->allowed_ips, &peer_config->allowed_ips, sizeof(peer->allowed_ips));
	peer->mask_len = peer_config->mask_len;
	peer->id = ++id;
	peer->iface = iface;
	*peer_iface = peer->iface;

	net_if_up(peer->iface);

	ret = peer->id;
out:
	k_mutex_unlock(&lock);

	return ret;
}

int wireguard_peer_remove(int peer_id)
{
	struct wg_peer *peer;
	int ret;

	k_mutex_lock(&lock, K_FOREVER);

	if (sys_slist_is_empty(&active_peers)) {
		ret = -ENOENT;
		goto out;
	}

	peer = peer_lookup_by_id(peer_id);
	if (peer == NULL) {
		ret = -ENOENT;
		goto out;
	}

	if (sys_slist_find_and_remove(&active_peers, &peer->node) == false) {
		ret = -EFAULT;
		goto out;
	}

	sys_slist_prepend(&peer_list, &peer->node);

	peer->id = 0;

	/* Detach the virtual interface from the control interface and
	 * turn off the Wireguard virtual interface so that packets cannot be
	 * sent through it.
	 */
	(void)net_virtual_interface_attach(peer->iface, NULL);

	net_if_down(peer->iface);

	ret = 0;
out:
	k_mutex_unlock(&lock);

	return ret;
}

void wireguard_peer_foreach(wg_peer_cb_t cb, void *user_data)
{
	struct wg_peer *peer, *next;

	k_mutex_lock(&lock, K_FOREVER);

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&active_peers,
					  peer, next, node) {
		cb(peer, user_data);
	}

	k_mutex_unlock(&lock);
}
