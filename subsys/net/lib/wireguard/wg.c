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
#include "ipv4.h"
#include "ipv6.h"

#define WG_FUNCTION_PROTOTYPES
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

/* Each Wireguard virtual interface is tied to one specific wg_iface_context */
struct wg_iface_context {
	const char *name;
	struct net_if *iface;
	struct net_if *attached_to;
	struct wg_context *wg_ctx;
	struct wg_peer *peer;

	union {
		const struct in_addr *my4addr;
		const struct in6_addr *my6addr;
	};

	uint8_t public_key[WG_PUBLIC_KEY_LEN];
	uint8_t private_key[WG_PRIVATE_KEY_LEN];

	uint8_t cookie_secret[WG_HASH_LEN];
	k_timepoint_t cookie_secret_expires;

	uint8_t label_cookie_key[WG_SESSION_KEY_LEN];
	uint8_t label_mac1_key[WG_SESSION_KEY_LEN];

	bool is_used : 1;
	bool status : 1;
	bool init_done : 1;
};

static enum net_verdict wg_input(struct net_conn *conn,
				 struct net_pkt *pkt,
				 union net_ip_header *ip_hdr,
				 union net_proto_header *proto_hdr,
				 void *user_data)
{
	struct wg_context *ctx = user_data;
	int ret;

	ARG_UNUSED(conn);

	net_pkt_set_wg_iface(pkt, net_pkt_iface(pkt));
	net_pkt_set_wg_ip_hdr(pkt, ip_hdr);
	net_pkt_set_wg_udp_hdr(pkt, proto_hdr);

	if (DEBUG_RX) {
		char str[sizeof("RX ctrl iface xx")];

		snprintk(str, sizeof(str), "RX ctrl iface %d",
			 net_if_get_by_iface(net_pkt_iface(pkt)));

		net_pkt_hexdump(pkt, str);
	}

	/* Feed the data to Wireguard control interface which
	 * will decrypt it and then pass it to the virtual interface
	 * that is handling that connection if such connection is found.
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
	blake2s_ctx bl_ctx;

	wireguard_blake2s_init(&bl_ctx, WG_HASH_LEN, NULL, 0);
	wireguard_blake2s_update(&bl_ctx, CONSTRUCTION, sizeof(CONSTRUCTION));
	wireguard_blake2s_final(&bl_ctx, ctx->construction_hash);

	wireguard_blake2s_init(&bl_ctx, WG_HASH_LEN, NULL, 0);
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

	if (WIREGUARD_INTERFACE[0] != '\0') {
		ret = net_if_get_by_name(WIREGUARD_INTERFACE);
		if (ret < 0) {
			NET_ERR("Cannot find interface \"%s\" (%d)",
				WIREGUARD_INTERFACE, ret);
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
	NET_PKT_DATA_ACCESS_DEFINE(wg_access, struct wg_msg_hdr);
	enum net_verdict verdict = NET_DROP;
	struct sockaddr my_addr = { 0 };
	struct sockaddr addr = { 0 };
	union net_proto_header *udp_hdr;
	union net_ip_header *ip_hdr;
	struct wg_msg_hdr *hdr;
	struct wg_peer *peer;
	size_t len;
	bool ok;

	if (pkt->buffer == NULL) {
		goto drop;
	}

	/* Make sure we received a proper packet, decrypt it and pass it to
	 * correct virtual interface.
	 */

	len = net_pkt_get_len(pkt);

	ip_hdr = net_pkt_wg_ip_hdr(pkt);
	udp_hdr = net_pkt_wg_udp_hdr(pkt);

	if (net_pkt_family(pkt) == AF_INET) {
		if (len < NET_IPV4UDPH_LEN + sizeof(struct wg_msg_hdr)) {
			NET_DBG("DROP: Too short Wireguard header");
			goto drop;
		}

		net_pkt_cursor_init(pkt);

		if (net_pkt_skip(pkt, NET_IPV4UDPH_LEN)) {
			NET_DBG("DROP: Too short %s packet", "IPv4");
			goto drop;
		}

		memcpy(&net_sin(&addr)->sin_addr, &ip_hdr->ipv4->src,
		       sizeof(struct in_addr));
		net_sin(&addr)->sin_port = udp_hdr->udp->src_port;
		addr.sa_family = AF_INET;

		memcpy(&net_sin(&my_addr)->sin_addr, &ip_hdr->ipv4->dst,
		       sizeof(struct in_addr));
		net_sin(&my_addr)->sin_family = AF_INET;

	} else if (net_pkt_family(pkt) == AF_INET6) {
		if (len < NET_IPV6UDPH_LEN + sizeof(struct wg_msg_hdr)) {
			NET_DBG("DROP: Too short Wireguard header");
			goto drop;
		}

		net_pkt_cursor_init(pkt);

		if (net_pkt_skip(pkt, NET_IPV6UDPH_LEN)) {
			NET_DBG("DROP: Too short %s packet", "IPv6");
			goto drop;
		}

		memcpy(&net_sin6(&addr)->sin6_addr, &ip_hdr->ipv6->src,
		       sizeof(struct in6_addr));
		net_sin6(&addr)->sin6_port = udp_hdr->udp->src_port;
		addr.sa_family = AF_INET6;

		memcpy(&net_sin6(&my_addr)->sin6_addr, &ip_hdr->ipv6->dst,
		       sizeof(struct in6_addr));
		net_sin6(&my_addr)->sin6_family = AF_INET6;
	}

	hdr = (struct wg_msg_hdr *)net_pkt_get_data(pkt, &wg_access);
	if (!hdr) {
		NET_DBG("DROP: NULL Wireguard header");
		goto drop;
	}

	if (!(hdr->reserved[0] == 0 && hdr->reserved[1] == 0 &&
	      hdr->reserved[2] == 0)) {
		NET_DBG("DROP: Invalid Wireguard header");
		goto drop;
	}

	/* At this point we don't know if this came from a valid peer */
	peer = peer_lookup_by_addr(&addr);
	if (peer == NULL) {
		NET_DBG("DROP: Peer not found for address %s",
			net_sprint_addr(addr.sa_family,
					(const void *)&net_sin(&addr)->sin_addr));
		goto drop;
	}

	if (peer->ctx == NULL) {
		NET_DBG("Invalid configuration");
		goto drop;
	}

	if (hdr->type == MESSAGE_HANDSHAKE_INITIATION) {
		NET_PKT_DATA_ACCESS_DEFINE(access, struct msg_handshake_init);
		struct msg_handshake_init *msg;

		msg = (struct msg_handshake_init *)net_pkt_get_data(pkt, &access);
		if (!msg) {
			NET_DBG("DROP: Invalid %s Wireguard header", "handshake init");
			goto drop;
		}

		ok = wg_check_initiation_message(peer->ctx, msg, &addr);
		if (ok) {
			peer = wg_process_initiation_message(peer->ctx, msg);
			if (peer) {
				memcpy(&peer->endpoint, &addr, sizeof(peer->endpoint));

				wg_send_handshake_response(peer->ctx,
							   peer->ctx->wg_ctx->iface,
							   peer,
							   &my_addr);
			}
		}
	} else {
		NET_DBG("DROP: Invalid %s Wireguard header", "message type");
		goto drop;
	}

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
		NET_DBG("No active peers found. Interface stays disabled.");
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

static int init_iface_context(struct wg_iface_context *ctx,
			      const struct virtual_interface_config *config)
{
	int ret;

	if (config->private_key.len != WG_PRIVATE_KEY_LEN) {
		NET_DBG("Invalid private key length, was %zu expected %zu",
			config->private_key.len, WG_PRIVATE_KEY_LEN);
		return -EINVAL;
	}

	/* Generate public key from the private key */
	memcpy(ctx->private_key, config->private_key.data, WG_PRIVATE_KEY_LEN);

	/* Private key needs to be clamped */
	wg_clamp_private_key(ctx->private_key);

	ret = wg_generate_public_key(ctx->public_key, ctx->private_key);
	if (ret < 0) {
		crypto_zero(ctx->private_key, WG_PRIVATE_KEY_LEN);

		NET_DBG("Public key generation failed (%d)", ret);

		return 0;
	}

	wg_generate_cookie_secret(ctx, COOKIE_SECRET_MAX_AGE_MSEC);

	/* 5.4.4 Cookie MACs - The value Hash(Label-Mac1 || Spubm' )
	 * above can be pre-computed.
	 */
	wg_mac_key(ctx->label_mac1_key, ctx->public_key, LABEL_MAC1,
		   sizeof(LABEL_MAC1));

	/* 5.4.7 Under Load: Cookie Reply Message - The value
	 * Hash(Label-Cookie || Spubm) above can be pre-computed.
	 */
	wg_mac_key(ctx->label_cookie_key, ctx->public_key, LABEL_COOKIE,
		   sizeof(LABEL_COOKIE));

	return 0;
}

static int interface_set_config(struct net_if *iface,
				enum virtual_interface_config_type type,
				const struct virtual_interface_config *config)
{
	struct wg_iface_context *ctx = net_if_get_device(iface)->data;

	switch (type) {
	case VIRTUAL_INTERFACE_CONFIG_TYPE_PRIVATE_KEY:
		return init_iface_context(ctx, config);

	case VIRTUAL_INTERFACE_CONFIG_TYPE_MTU:
		NET_DBG("Interface %d MTU set to %d",
			net_if_get_by_iface(iface), config->mtu);
		net_if_set_mtu(iface, config->mtu);
		return 0;

	default:
		break;
	}

	return -ENOTSUP;
}

static const struct virtual_interface_api wg_iface_api = {
	.iface_api.init = iface_init,

	.get_capabilities = get_capabilities,
	.start = interface_start,
	.stop = interface_stop,
	.attach = interface_attach,
	.send = interface_send,
	.recv = interface_recv,
	.set_config = interface_set_config,
	//.get_config = interface_get_config,
};

#define WG_INTERFACE_INIT(x, _)						\
	static struct wg_iface_context wg_iface_context_data_##x = {	\
		.name =	"wg" #x,					\
		.wg_ctx = &wg_ctx,					\
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

static int create_ipv4_packet(struct net_if *iface,
			      struct sockaddr *dst,
			      uint8_t *packet,
			      size_t packet_len,
			      struct net_pkt **reply_pkt)
{
	const struct in_addr *src;
	struct net_pkt *pkt;
	int ret;

	pkt = net_pkt_alloc_with_buffer(iface,
					NET_UDPH_LEN + packet_len,
					AF_INET, IPPROTO_UDP,
					PKT_ALLOC_WAIT_TIME);
	if (pkt == NULL) {
		return -ENOMEM;
	}

	src = net_if_ipv4_select_src_addr(iface, &net_sin(dst)->sin_addr);

	ret = net_ipv4_create(pkt, src, &net_sin(dst)->sin_addr);
	if (ret < 0) {
		goto drop;
	}

	*reply_pkt = pkt;

	return 0;

drop:
	net_pkt_unref(pkt);
	return ret;
}

static int create_ipv6_packet(struct net_if *iface,
			      struct sockaddr *dst,
			      uint8_t *packet,
			      size_t packet_len,
			      struct net_pkt **reply_pkt)
{
	const struct in6_addr *src;
	struct net_pkt *pkt;
	int ret;

	pkt = net_pkt_alloc_with_buffer(iface,
					NET_UDPH_LEN + packet_len,
					AF_INET6, IPPROTO_UDP,
					PKT_ALLOC_WAIT_TIME);
	if (pkt == NULL) {
		return -ENOMEM;
	}

	src = net_if_ipv6_select_src_addr(iface, &net_sin6(dst)->sin6_addr);

	ret = net_ipv6_create(pkt, src, &net_sin6(dst)->sin6_addr);
	if (ret < 0) {
		goto drop;
	}

	*reply_pkt = pkt;

	return 0;
drop:
	net_pkt_unref(pkt);
	return ret;
}

static int create_packet(struct net_if *iface,
			 struct sockaddr *dst,
			 uint8_t *packet,
			 size_t packet_len,
			 struct net_pkt **reply)
{
	int ret;

	if (IS_ENABLED(CONFIG_NET_IPV4) && dst->sa_family == AF_INET) {
		ret = create_ipv4_packet(iface,
					 dst,
					 packet,
					 packet_len,
					 reply);

	} else if (IS_ENABLED(CONFIG_NET_IPV6) && dst->sa_family == AF_INET6) {
		ret = create_ipv6_packet(iface,
					 dst,
					 packet,
					 packet_len,
					 reply);
	} else {
		ret = -ENOTSUP;
		goto out;
	}

	if (ret < 0) {
		NET_DBG("Cannot create packet (%d)", ret);
		goto out;
	}

	net_pkt_write(*reply, packet, packet_len);
	net_pkt_cursor_init(*reply);

	if (IS_ENABLED(CONFIG_NET_IPV4) && dst->sa_family == AF_INET) {
		net_ipv4_finalize(*reply, IPPROTO_UDP);
	} else if (IS_ENABLED(CONFIG_NET_IPV6) && dst->sa_family == AF_INET6) {
		net_ipv6_finalize(*reply, IPPROTO_UDP);
	}

	ret = 0;
out:
	return ret;
}

#include "wg_crypto.c"

/* Lock must be held when calling these lookup functions */
static struct wg_peer *peer_lookup_by_pubkey(struct wg_iface_context *ctx,
					     const char *public_key)
{
	struct wg_peer *peer, *next;

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&active_peers, peer, next, node) {
		if ((ctx == NULL || peer->ctx == ctx) &&
		    memcmp(peer->key.public_key, public_key, WG_PUBLIC_KEY_LEN) == 0) {
			return peer;
		}
	}

	return NULL;
}

static struct wg_peer *peer_lookup_by_addr(struct sockaddr *addr)
{
	struct wg_peer *peer, *next;

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&active_peers, peer, next, node) {
		struct wg_allowed_ips *allowed;

		for (size_t i = 0; i < ARRAY_SIZE(peer->allowed_source_ips); i++) {
			allowed = &peer->allowed_source_ips[i];

			if (IS_ENABLED(CONFIG_NET_IPV4) && addr->sa_family == AF_INET &&
			    allowed->addr.family == AF_INET && allowed->is_valid) {
				uint32_t netmask;

				netmask = allowed->mask_len ?
					(0xFFFFFFFF >> (32 - allowed->mask_len)) : 0;

				if (((net_sin(addr)->sin_addr.s_addr & netmask) ==
				     (allowed->addr.in_addr.s_addr & netmask))) {
					return peer;
				}
			}

			if (IS_ENABLED(CONFIG_NET_IPV6) && addr->sa_family == AF_INET6 &&
			    allowed->addr.family == AF_INET6 && allowed->is_valid) {

				if (net_ipv6_is_prefix(net_sin6(addr)->sin6_addr.s6_addr,
						       allowed->addr.in6_addr.s6_addr,
						       allowed->mask_len)) {
					return peer;
				}
			}
		}
	}

	return NULL;
}

static struct wg_peer *peer_lookup_by_id(uint8_t id)
{
	struct wg_peer *peer, *next;

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&active_peers, peer, next, node) {
		if (peer->id == id) {
			return peer;
		}
	}

	return NULL;
}

static struct wg_peer *peer_lookup_by_receiver(struct wg_iface_context *ctx,
					       uint32_t receiver)
{
	struct wg_peer *peer, *next;

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&active_peers, peer, next, node) {
		if (peer->ctx == ctx &&
		    ((peer->session.keypair.current.is_valid &&
		     peer->session.keypair.current.local_index == receiver) ||
		    (peer->session.keypair.next.is_valid &&
		     peer->session.keypair.next.local_index == receiver) ||
		    (peer->session.keypair.prev.is_valid &&
		     peer->session.keypair.prev.local_index == receiver))) {
			return peer;
		}
	}

	return NULL;
}

static struct wg_peer *peer_lookup_by_handshake(struct wg_iface_context *ctx,
						uint32_t receiver)
{
	struct wg_peer *peer, *next;

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&active_peers, peer, next, node) {
		if (peer->ctx == ctx &&
		    peer->handshake.is_valid &&
		    peer->handshake.is_initiator == receiver &&
		    peer->handshake.local_index == receiver) {
			return peer;
		}
	}

	return NULL;
}

static struct wg_keypair *get_peer_keypair_for_index(struct wg_peer *peer,
						     uint32_t idx)
{
	if (peer->session.keypair.current.is_valid &&
	    peer->session.keypair.current.local_index == idx) {
		return &peer->session.keypair.current;
	} else if (peer->session.keypair.next.is_valid &&
		   peer->session.keypair.next.local_index == idx) {
		return &peer->session.keypair.next;
	} else if (peer->session.keypair.prev.is_valid &&
		   peer->session.keypair.prev.local_index == idx) {
		return &peer->session.keypair.prev;
	}

	return NULL;
}

static bool is_index_used(struct wg_iface_context *ctx, uint32_t index)
{
	struct wg_peer *peer, *next;
	bool found = false;

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&active_peers, peer, next, node) {
		found = (peer->ctx == ctx &&
			 (index == peer->session.keypair.current.local_index ||
			  index == peer->session.keypair.prev.local_index ||
			  index == peer->session.keypair.next.local_index ||
			  index == peer->handshake.local_index));
	}

	return found;
}

static uint32_t generate_unique_index(struct wg_iface_context *ctx)
{
	uint32_t index;

	do {
		do {
			(void)sys_csrand_get(&index, sizeof(index));
		} while ((index == 0) || (index == 0xFFFFFFFF));

	} while (is_index_used(ctx, index));

	return index;
}

static bool extract_public_key(const char *str, uint8_t *out, size_t outlen)
{
	size_t len = 0U;
	int ret;

	ret = base64_decode(out, outlen, &len, str, strlen(str));
	if (ret < 0) {
		NET_DBG("base64 decode failed, olen %zd (%d)", len, ret);
		return false;
	}

	if (len != outlen) {
		NET_DBG("Invalid length %zd vs %zd", len, outlen);
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

static bool wg_peer_init(struct wg_iface_context *ctx,
			 struct wg_peer *peer,
			 const uint8_t *public_key,
			 const uint8_t *preshared_key)
{
	bool is_valid = false;
	int ret;

	memset(peer, 0, sizeof(struct wg_peer));

	if (ctx == NULL) {
		return false;
	}

	memcpy(peer->key.public_key, public_key, WG_PUBLIC_KEY_LEN);

	if (preshared_key != NULL) {
		memcpy(peer->key.preshared, preshared_key, WG_SESSION_KEY_LEN);
	} else {
		crypto_zero(peer->key.preshared, WG_SESSION_KEY_LEN);
	}

	ret = wireguard_x25519(peer->key.public_dh, ctx->private_key,
			       peer->key.public_key);
	if (ret == 0) {
		memset(&peer->handshake, 0, sizeof(struct wg_handshake));
		peer->handshake.is_valid = false;

		peer->cookie_secret_expires = sys_timepoint_calc(K_MSEC(COOKIE_SECRET_MAX_AGE_MSEC));
		memset(&peer->cookie, 0, WG_COOKIE_LEN);

		wg_mac_key(peer->label_mac1_key, peer->key.public_key,
			   LABEL_MAC1, sizeof(LABEL_MAC1));
		wg_mac_key(peer->label_cookie_key, peer->key.public_key,
			   LABEL_COOKIE, sizeof(LABEL_COOKIE));
		is_valid = true;
	} else {
		NET_DBG("Cannot calculate DH public key for peer");
		crypto_zero(peer->key.public_dh, WG_PUBLIC_KEY_LEN);
	}

	return is_valid;
}

static int peer_add_addr(struct wg_peer *peer, struct sockaddr *addr, uint8_t mask_len)
{
	struct wg_allowed_ips *allowed;
	size_t free_count = 0;
	int ret = -ENOMEM;

	for (size_t i = 0; i < ARRAY_SIZE(peer->allowed_source_ips); i++) {
		allowed = &peer->allowed_source_ips[i];

		if (IS_ENABLED(CONFIG_NET_IPV4) && addr->sa_family == AF_INET &&
		    allowed->addr.family == AF_INET && allowed->is_valid) {
			if (net_ipv4_addr_cmp(&net_sin(addr)->sin_addr,
					      &allowed->addr.in_addr) &&
			    allowed->mask_len == mask_len) {
				return 0;
			}
		}

		if (IS_ENABLED(CONFIG_NET_IPV6) && addr->sa_family == AF_INET6 &&
		    allowed->addr.family == AF_INET6 && allowed->is_valid) {
			if (net_ipv6_addr_cmp(&net_sin6(addr)->sin6_addr,
					      &allowed->addr.in6_addr) &&
			    allowed->mask_len == mask_len) {
				return 0;
			}
		}

		if (!allowed->is_valid) {
			free_count++;
		}
	}

	if (free_count == 0) {
		return -ENOMEM;
	}

	for (size_t i = 0; i < ARRAY_SIZE(peer->allowed_source_ips); i++) {
		allowed = &peer->allowed_source_ips[i];

		if (allowed->is_valid) {
			continue;
		}

		if (IS_ENABLED(CONFIG_NET_IPV4) && addr->sa_family == AF_INET) {
			net_ipaddr_copy(&allowed->addr.in_addr,
					&net_sin(addr)->sin_addr);
			allowed->mask_len = mask_len;
			allowed->is_valid = true;
			allowed->addr.family = AF_INET;
			return 0;
		}

		if (IS_ENABLED(CONFIG_NET_IPV6) && addr->sa_family == AF_INET6) {
			net_ipaddr_copy(&allowed->addr.in6_addr,
					&net_sin6(addr)->sin6_addr);
			allowed->mask_len = mask_len;
			allowed->is_valid = true;
			allowed->addr.family = AF_INET6;
			return 0;
		}
	}

	return ret;
}

int wireguard_peer_add(struct wireguard_peer_config *peer_config,
		       struct net_if **peer_iface)
{
	static int id;
	uint8_t public_key[WG_PUBLIC_KEY_LEN];
	struct wg_iface_context *ctx;
	struct net_if *iface = NULL;
	struct wg_peer *peer;
	sys_snode_t *node;
	int ret;

	if (peer_config->public_key == NULL) {
		NET_DBG("Public key not set");
		return -EINVAL;
	}

	if (!extract_public_key(peer_config->public_key, public_key,
				sizeof(public_key))) {
		NET_DBG("Invalid public_key base64 format");
		return -EINVAL;
	}

	k_mutex_lock(&lock, K_FOREVER);

	peer = peer_lookup_by_pubkey(NULL, public_key);
	if (peer != NULL) {
		ret = -EALREADY;
		goto out;
	}

	/* Try to find out available virtual network interface */
	net_if_foreach(iface_cb, &iface);

	if (iface == NULL) {
		ret = -ENOMEM;
		NET_INFO("No available Wireguard interfaces found");
		goto out;
	}

	/* We could find an interface, now allocate the peer */
	node = sys_slist_get(&peer_list);
	if (node == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	peer = CONTAINER_OF(node, struct wg_peer, node);

	ctx = net_if_get_device(iface)->data;

	if (!wg_peer_init(ctx, peer, public_key, peer_config->preshared_key)) {
		NET_DBG("Peer init failed");
		ret = -EINVAL;
		sys_slist_prepend(&peer_list, node);
		goto out;
	}

	ret = net_virtual_interface_attach(iface, wg_ctx.iface);
	if (ret < 0) {
		NET_DBG("Cannot attach %d to %d",
			net_if_get_by_iface(iface),
			net_if_get_by_iface(wg_ctx.iface));
		sys_slist_prepend(&peer_list, node);
		goto out;
	}

	ret = peer_add_addr(peer, &peer_config->allowed_ip, peer_config->mask_len);
	if (ret != 0) {
		NET_DBG("Peer allowed address could not be added (%d)", ret);
	}

	sys_slist_prepend(&active_peers, node);

	memcpy(&peer->cfg_endpoint, &peer_config->endpoint_ip,
	       sizeof(peer->cfg_endpoint));
	peer->id = ++id;
	peer->iface = iface;
	*peer_iface = peer->iface;
	peer->ctx = ctx;

	net_if_up(peer->iface);

	ret = peer->id;
out:
	k_mutex_unlock(&lock);

	return ret;
}

static void wg_peer_cleanup(struct wg_peer *peer)
{
	memset(&peer->key, 0, sizeof(peer->key));

	peer->id = 0;
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

	wg_peer_cleanup(peer);

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
