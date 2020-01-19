/*
 * Copyright (c) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(net_rpcap, CONFIG_NET_RPCAP_LOG_LEVEL);

#include <sys/fdtable.h>
#include <net/net_core.h>
#include <net/net_pkt.h>
#include <net/net_context.h>
#include <net/socket.h>
#include <net/rpcap.h>

#include "rpcap_internal.h"

#define BUF_TIMEOUT K_MSEC(50)

int zrpcap_start(struct net_if *iface, int *ctx)
{
	if (!ctx) {
		return -EINVAL;
	}

	if (!net_if_flag_is_set(iface, NET_IF_PCAP_SUPPORTED)) {
		return -ENOTSUP;
	}

	net_if_flag_set(iface, NET_IF_PCAP_ENABLED);

	return 0;
}

static struct net_context *get_net_ctx(int ctx)
{
	const struct fd_op_vtable *vtable;

	return z_get_fd_obj_and_vtable(ctx, &vtable);
}

int zrpcap_stop(int ctx)
{
	struct net_context *net_ctx;

	net_ctx = get_net_ctx(ctx);
	if (net_ctx == NULL) {
		return -ENOENT;
	}

	if (!net_if_flag_is_set(net_context_get_iface(net_ctx),
				NET_IF_PCAP_SUPPORTED)) {
		return -ENOTSUP;
	}

	/* TODO: count the enabled flags and turn off capturing flag
	 * when all users are stopped
	 */
	if (!net_if_flag_is_set(net_context_get_iface(net_ctx),
				NET_IF_PCAP_ENABLED)) {
		return -EALREADY;
	}

	net_if_flag_clear(net_context_get_iface(net_ctx), NET_IF_PCAP_ENABLED);

	(void)zsock_close(ctx);

	return 0;
}

static struct net_pkt *zrpcap_clone(struct net_if *iface,
				    struct net_pkt *pkt)
{
	struct net_pkt_cursor backup;
	struct net_pkt *clone_pkt;

	clone_pkt = net_pkt_alloc_with_buffer(iface,
					      net_pkt_get_len(pkt),
					      net_pkt_family(pkt), 0,
					      BUF_TIMEOUT);
	if (!clone_pkt) {
		return NULL;
	}

	net_pkt_cursor_backup(pkt, &backup);
	net_pkt_cursor_init(pkt);

	if (net_pkt_copy(clone_pkt, pkt, net_pkt_get_len(pkt))) {
		net_pkt_cursor_restore(pkt, &backup);
		net_pkt_unref(clone_pkt);
		return NULL;
	}

	net_pkt_cursor_restore(pkt, &backup);

	net_pkt_cursor_init(clone_pkt);
	net_pkt_set_pcap(clone_pkt, true);

	return clone_pkt;
}

int zrpcap_capture_packet(int ctx, struct net_pkt *pkt,
			  enum zrpcap_direction direction, u32_t linktype)
{
	struct net_pkt *pcap_pkt;
	struct net_context *net_ctx;

	net_ctx = get_net_ctx(ctx);
	if (net_ctx == NULL) {
		return -ENOENT;
	}

	if (!net_if_flag_is_set(net_context_get_iface(net_ctx),
				NET_IF_PCAP_SUPPORTED)) {
		return -ENOTSUP;
	}

	if (!net_if_flag_is_set(net_context_get_iface(net_ctx),
				NET_IF_PCAP_ENABLED)) {
		return -ENOENT;
	}

	/* Clone the packet and add PCAP header to it */
	pcap_pkt = zrpcap_clone(net_context_get_iface(net_ctx), pkt);


	/* Send the packet to client */


	return 0;
}

void zrpcap_init(void)
{
}
