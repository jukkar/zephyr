/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __NET_STATS_H__
#define __NET_STATS_H__

#if defined(CONFIG_NET_STATISTICS)

#include <net/net_ip.h>
#include <net/net_stats.h>
#include <net/net_if.h>

extern struct net_stats net_stats;

#if defined(CONFIG_NET_STATISTICS_PER_INTERFACE)
#define SET_STAT(cmd) cmd
#define GET_STAT(iface, s) (iface ? iface->stats.s : net_stats.s)
#define GET_STAT_ADDR(iface, s) (iface ? &iface->stats.s : &net_stats.s)
#else
#define SET_STAT(cmd)
#define GET_STAT(iface, s) net_stats.s
#define GET_STAT_ADDR(iface, s) &GET_STAT(iface, s)
#endif

/* Core stats */

static inline void net_stats_update_processing_error(struct net_if *iface)
{
	SET_STAT(iface->stats.processing_error++);
	net_stats.processing_error++;
}

static inline void net_stats_update_ip_errors_protoerr(struct net_if *iface)
{
	SET_STAT(iface->stats.ip_errors.protoerr++);
	net_stats.ip_errors.protoerr++;
}

static inline void net_stats_update_ip_errors_vhlerr(struct net_if *iface)
{
	SET_STAT(iface->stats.ip_errors.vhlerr++);
	net_stats.ip_errors.vhlerr++;
}

static inline void net_stats_update_bytes_recv(struct net_if *iface,
					       u32_t bytes)
{
	SET_STAT(iface->stats.bytes.received += bytes);
	net_stats.bytes.received += bytes;
}

static inline void net_stats_update_bytes_sent(struct net_if *iface,
					       u32_t bytes)
{
	SET_STAT(iface->stats.bytes.sent += bytes);
	net_stats.bytes.sent += bytes;
}
#else
#define net_stats_update_processing_error(iface)
#define net_stats_update_ip_errors_protoerr(iface)
#define net_stats_update_ip_errors_vhlerr(iface)
#define net_stats_update_bytes_recv(iface, bytes)
#define net_stats_update_bytes_sent(iface, bytes)
#endif /* CONFIG_NET_STATISTICS */

#if defined(CONFIG_NET_STATISTICS_IPV6)
/* IPv6 stats */

static inline void net_stats_update_ipv6_sent(struct net_if *iface)
{
	SET_STAT(iface->stats.ipv6.sent++);
	net_stats.ipv6.sent++;
}

static inline void net_stats_update_ipv6_recv(struct net_if *iface)
{
	SET_STAT(iface->stats.ipv6.recv++);
	net_stats.ipv6.recv++;
}

static inline void net_stats_update_ipv6_drop(struct net_if *iface)
{
	SET_STAT(iface->stats.ipv6.drop++);
	net_stats.ipv6.drop++;
}
#else
#define net_stats_update_ipv6_drop(iface)
#define net_stats_update_ipv6_sent(iface)
#define net_stats_update_ipv6_recv(iface)
#endif /* CONFIG_NET_STATISTICS_IPV6 */

#if defined(CONFIG_NET_STATISTICS_IPV6_ND)
/* IPv6 Neighbor Discovery stats*/

static inline void net_stats_update_ipv6_nd_sent(struct net_if *iface)
{
	SET_STAT(iface->stats.ipv6_nd.sent++);
	net_stats.ipv6_nd.sent++;
}

static inline void net_stats_update_ipv6_nd_recv(struct net_if *iface)
{
	SET_STAT(iface->stats.ipv6_nd.recv++);
	net_stats.ipv6_nd.recv++;
}

static inline void net_stats_update_ipv6_nd_drop(struct net_if *iface)
{
	SET_STAT(iface->stats.ipv6_nd.drop++);
	net_stats.ipv6_nd.drop++;
}
#else
#define net_stats_update_ipv6_nd_sent(iface)
#define net_stats_update_ipv6_nd_recv(iface)
#define net_stats_update_ipv6_nd_drop(iface)
#endif /* CONFIG_NET_STATISTICS_IPV6_ND */

#if defined(CONFIG_NET_STATISTICS_IPV4)
/* IPv4 stats */

static inline void net_stats_update_ipv4_drop(struct net_if *iface)
{
	SET_STAT(iface->stats.ipv4.drop++);
	net_stats.ipv4.drop++;
}

static inline void net_stats_update_ipv4_sent(struct net_if *iface)
{
	SET_STAT(iface->stats.ipv4.sent++);
	net_stats.ipv4.sent++;
}

static inline void net_stats_update_ipv4_recv(struct net_if *iface)
{
	SET_STAT(iface->stats.ipv4.recv++);
	net_stats.ipv4.recv++;
}
#else
#define net_stats_update_ipv4_drop(iface)
#define net_stats_update_ipv4_sent(iface)
#define net_stats_update_ipv4_recv(iface)
#endif /* CONFIG_NET_STATISTICS_IPV4 */

#if defined(CONFIG_NET_STATISTICS_ICMP)
/* Common ICMPv4/ICMPv6 stats */
static inline void net_stats_update_icmp_sent(struct net_if *iface)
{
	SET_STAT(iface->stats.icmp.sent++);
	net_stats.icmp.sent++;
}

static inline void net_stats_update_icmp_recv(struct net_if *iface)
{
	SET_STAT(iface->stats.icmp.recv++);
	net_stats.icmp.recv++;
}

static inline void net_stats_update_icmp_drop(struct net_if *iface)
{
	SET_STAT(iface->stats.icmp.drop++);
	net_stats.icmp.drop++;
}
#else
#define net_stats_update_icmp_sent(iface)
#define net_stats_update_icmp_recv(iface)
#define net_stats_update_icmp_drop(iface)
#endif /* CONFIG_NET_STATISTICS_ICMP */

#if defined(CONFIG_NET_STATISTICS_UDP)
/* UDP stats */
static inline void net_stats_update_udp_sent(struct net_if *iface)
{
	SET_STAT(iface->stats.udp.sent++);
	net_stats.udp.sent++;
}

static inline void net_stats_update_udp_recv(struct net_if *iface)
{
	SET_STAT(iface->stats.udp.recv++);
	net_stats.udp.recv++;
}

static inline void net_stats_update_udp_drop(struct net_if *iface)
{
	SET_STAT(iface->stats.udp.drop++);
	net_stats.udp.drop++;
}

static inline void net_stats_update_udp_chkerr(struct net_if *iface)
{
	SET_STAT(iface->stats.udp.chkerr++);
	net_stats.udp.chkerr++;
}
#else
#define net_stats_update_udp_sent(iface)
#define net_stats_update_udp_recv(iface)
#define net_stats_update_udp_drop(iface)
#define net_stats_update_udp_chkerr(iface)
#endif /* CONFIG_NET_STATISTICS_UDP */

#if defined(CONFIG_NET_STATISTICS_TCP)
/* TCP stats */
static inline void net_stats_update_tcp_sent(struct net_if *iface, u32_t bytes)
{
	SET_STAT(iface->stats.tcp.bytes.sent += bytes);
	net_stats.tcp.bytes.sent += bytes;
}

static inline void net_stats_update_tcp_recv(struct net_if *iface, u32_t bytes)
{
	SET_STAT(iface->stats.tcp.bytes.received += bytes);
	net_stats.tcp.bytes.received += bytes;
}

static inline void net_stats_update_tcp_resent(struct net_if *iface,
					       u32_t bytes)
{
	SET_STAT(iface->stats.tcp.resent += bytes);
	net_stats.tcp.resent += bytes;
}

static inline void net_stats_update_tcp_seg_sent(struct net_if *iface)
{
	SET_STAT(iface->stats.tcp.sent++);
	net_stats.tcp.sent++;
}

static inline void net_stats_update_tcp_seg_recv(struct net_if *iface)
{
	SET_STAT(iface->stats.tcp.recv++);
	net_stats.tcp.recv++;
}

static inline void net_stats_update_tcp_seg_drop(struct net_if *iface)
{
	SET_STAT(iface->stats.tcp.drop++);
	net_stats.tcp.drop++;
}

static inline void net_stats_update_tcp_seg_rst(struct net_if *iface)
{
	SET_STAT(iface->stats.tcp.rst++);
	net_stats.tcp.rst++;
}

static inline void net_stats_update_tcp_seg_conndrop(struct net_if *iface)
{
	SET_STAT(iface->stats.tcp.conndrop++);
	net_stats.tcp.conndrop++;
}

static inline void net_stats_update_tcp_seg_connrst(struct net_if *iface)
{
	SET_STAT(iface->stats.tcp.connrst++);
	net_stats.tcp.connrst++;
}

static inline void net_stats_update_tcp_seg_chkerr(struct net_if *iface)
{
	SET_STAT(iface->stats.tcp.chkerr++);
	net_stats.tcp.chkerr++;
}

static inline void net_stats_update_tcp_seg_ackerr(struct net_if *iface)
{
	SET_STAT(iface->stats.tcp.ackerr++);
	net_stats.tcp.ackerr++;
}

static inline void net_stats_update_tcp_seg_rsterr(struct net_if *iface)
{
	SET_STAT(iface->stats.tcp.rsterr++);
	net_stats.tcp.rsterr++;
}

static inline void net_stats_update_tcp_seg_rexmit(struct net_if *iface)
{
	SET_STAT(iface->stats.tcp.rexmit++);
	net_stats.tcp.rexmit++;
}
#else
#define net_stats_update_tcp_sent(iface, bytes)
#define net_stats_update_tcp_resent(iface, bytes)
#define net_stats_update_tcp_recv(iface, bytes)
#define net_stats_update_tcp_seg_sent(iface)
#define net_stats_update_tcp_seg_recv(iface)
#define net_stats_update_tcp_seg_drop(iface)
#define net_stats_update_tcp_seg_rst(iface)
#define net_stats_update_tcp_seg_conndrop(iface)
#define net_stats_update_tcp_seg_connrst(iface)
#define net_stats_update_tcp_seg_chkerr(iface)
#define net_stats_update_tcp_seg_ackerr(iface)
#define net_stats_update_tcp_seg_rsterr(iface)
#define net_stats_update_tcp_seg_rexmit(iface)
#endif /* CONFIG_NET_STATISTICS_TCP */

static inline void net_stats_update_per_proto_recv(struct net_if *iface,
						   enum net_ip_protocol proto)
{
	if (IS_ENABLED(CONFIG_NET_UDP) && proto == IPPROTO_UDP) {
		net_stats_update_udp_recv(iface);
	} else if (IS_ENABLED(CONFIG_NET_TCP) && proto == IPPROTO_TCP) {
		net_stats_update_tcp_seg_recv(iface);
	}
}

static inline void net_stats_update_per_proto_drop(struct net_if *iface,
						   enum net_ip_protocol proto)
{
	if (IS_ENABLED(CONFIG_NET_UDP) && proto == IPPROTO_UDP) {
		net_stats_update_udp_drop(iface);
	} else if (IS_ENABLED(CONFIG_NET_TCP) && proto == IPPROTO_TCP) {
		net_stats_update_tcp_seg_drop(iface);
	}
}

#if defined(CONFIG_NET_STATISTICS_RPL)
/* RPL stats */
static inline void net_stats_update_rpl_resets(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.resets++);
	net_stats.rpl.resets++;
}

static inline void net_stats_update_rpl_mem_overflows(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.mem_overflows++);
	net_stats.rpl.mem_overflows++;
}

static inline void net_stats_update_rpl_parent_switch(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.parent_switch++);
	net_stats.rpl.parent_switch++;
}

static inline void net_stats_update_rpl_local_repairs(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.local_repairs++);
	net_stats.rpl.local_repairs++;
}

static inline void net_stats_update_rpl_global_repairs(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.global_repairs++);
	net_stats.rpl.global_repairs++;
}

static inline void net_stats_update_rpl_root_repairs(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.root_repairs++);
	net_stats.rpl.root_repairs++;
}

static inline void net_stats_update_rpl_malformed_msgs(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.malformed_msgs++);
	net_stats.rpl.malformed_msgs++;
}

static inline void net_stats_update_rpl_forward_errors(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.forward_errors++);
	net_stats.rpl.forward_errors++;
}

static inline void net_stats_update_rpl_loop_errors(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.loop_errors++);
	net_stats.rpl.loop_errors++;
}

static inline void net_stats_update_rpl_loop_warnings(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.loop_warnings++);
	net_stats.rpl.loop_warnings++;
}

static inline void net_stats_update_rpl_dis_sent(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.dis.sent++);
	net_stats.rpl.dis.sent++;
}

static inline void net_stats_update_rpl_dio_sent(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.dio.sent++);
	net_stats.rpl.dio.sent++;
}

static inline void net_stats_update_rpl_dao_sent(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.dao.sent++);
	net_stats.rpl.dao.sent++;
}

static inline void net_stats_update_rpl_dao_forwarded(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.dao.forwarded++);
	net_stats.rpl.dao.forwarded++;
}

static inline void net_stats_update_rpl_dao_ack_sent(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.dao_ack.sent++);
	net_stats.rpl.dao_ack.sent++;
}

static inline void net_stats_update_rpl_dao_ack_recv(struct net_if *iface)
{
	SET_STAT(iface->stats.rpl.dao_ack.recv++);
	net_stats.rpl.dao_ack.recv++;
}
#else
#define net_stats_update_rpl_resets(iface)
#define net_stats_update_rpl_mem_overflows(iface)
#define net_stats_update_rpl_parent_switch(iface)
#define net_stats_update_rpl_local_repairs(iface)
#define net_stats_update_rpl_global_repairs(iface)
#define net_stats_update_rpl_root_repairs(iface)
#define net_stats_update_rpl_malformed_msgs(iface)
#define net_stats_update_rpl_forward_errors(iface)
#define net_stats_update_rpl_loop_errors(iface)
#define net_stats_update_rpl_loop_warnings(iface)
#define net_stats_update_rpl_dis_sent(iface)
#define net_stats_update_rpl_dio_sent(iface)
#define net_stats_update_rpl_dao_sent(iface)
#define net_stats_update_rpl_dao_forwarded(iface)
#define net_stats_update_rpl_dao_ack_sent(iface)
#define net_stats_update_rpl_dao_ack_recv(iface)
#endif /* CONFIG_NET_STATISTICS_RPL */

#if defined(CONFIG_NET_STATISTICS_MLD)
static inline void net_stats_update_ipv6_mld_recv(struct net_if *iface)
{
	SET_STAT(iface->stats.ipv6_mld.recv++);
	net_stats.ipv6_mld.recv++;
}

static inline void net_stats_update_ipv6_mld_sent(struct net_if *iface)
{
	SET_STAT(iface->stats.ipv6_mld.sent++);
	net_stats.ipv6_mld.sent++;
}

static inline void net_stats_update_ipv6_mld_drop(struct net_if *iface)
{
	SET_STAT(iface->stats.ipv6_mld.drop++);
	net_stats.ipv6_mld.drop++;
}
#else
#define net_stats_update_ipv6_mld_recv(iface)
#define net_stats_update_ipv6_mld_sent(iface)
#define net_stats_update_ipv6_mld_drop(iface)
#endif /* CONFIG_NET_STATISTICS_MLD */

#if (NET_TC_COUNT > 1) && defined(CONFIG_NET_STATISTICS)
static inline void net_stats_update_tc_sent_pkt(struct net_if *iface, u8_t tc)
{
	SET_STAT(iface->stats.tc.sent[tc].pkts++);
	net_stats.tc.sent[tc].pkts++;
}

static inline void net_stats_update_tc_sent_bytes(struct net_if *iface,
						  u8_t tc, size_t bytes)
{
	SET_STAT(iface->stats.tc.sent[tc].bytes += bytes);
	net_stats.tc.sent[tc].bytes += bytes;
}

static inline void net_stats_update_tc_sent_priority(struct net_if *iface,
						     u8_t tc, u8_t priority)
{
	SET_STAT(iface->stats.tc.sent[tc].priority = priority);
	net_stats.tc.sent[tc].priority = priority;
}

static inline void net_stats_update_tc_recv_pkt(struct net_if *iface, u8_t tc)
{
	SET_STAT(iface->stats.tc.recv[tc].pkts++);
	net_stats.tc.recv[tc].pkts++;
}

static inline void net_stats_update_tc_recv_bytes(struct net_if *iface,
						  u8_t tc, size_t bytes)
{
	SET_STAT(iface->stats.tc.recv[tc].bytes += bytes);
	net_stats.tc.recv[tc].bytes += bytes;
}

static inline void net_stats_update_tc_recv_priority(struct net_if *iface,
						     u8_t tc, u8_t priority)
{
	SET_STAT(iface->stats.tc.recv[tc].priority = priority);
	net_stats.tc.recv[tc].priority = priority;
}
#else
#define net_stats_update_tc_sent_pkt(iface, tc)
#define net_stats_update_tc_sent_bytes(iface, tc, bytes)
#define net_stats_update_tc_sent_priority(iface, tc, priority)
#define net_stats_update_tc_recv_pkt(iface, tc)
#define net_stats_update_tc_recv_bytes(iface, tc, bytes)
#define net_stats_update_tc_recv_priority(iface, tc, priority)
#endif /* NET_TC_COUNT > 1 */

#if defined(CONFIG_NET_PKT_TIMESTAMP) && defined(CONFIG_NET_STATISTICS)
#define _NET_STATS_AVG_SAMPLES 100

static inline
void _net_stats_update_pkt_timestamp(struct net_stats_ts_data *data,
				     u32_t ts)
{
	if (ts == UINT32_MAX || ts == 0) {
		return;
	}

	/* Do not calculate highest or lowest number into rolling average */

	if (ts < data->low || data->low == 0) {
		data->low = ts;
		return;
	}

	if (ts > data->high) {
		data->high = ts;
		return;
	}

	if (data->average) {
		if (ts > (10 * data->average)) {
			/* If the time is too large, just skip it */
			return;
		}

		data->average = (data->average *
				 (_NET_STATS_AVG_SAMPLES - 1) + ts) /
			_NET_STATS_AVG_SAMPLES;
	} else {
		data->average = ts;
	}
}

static inline void net_stats_update_pkt_tx_timestamp(u8_t tc, u32_t ts)
{
	_net_stats_update_pkt_timestamp(&net_stats.ts.tx[tc].time, ts);
}

static inline void net_stats_update_pkt_rx_timestamp(u8_t tc, u32_t ts)
{
	_net_stats_update_pkt_timestamp(&net_stats.ts.rx[tc].time, ts);
}
#else
#define net_stats_update_pkt_tx_timestamp(ts)
#define net_stats_update_pkt_rx_timestamp(ts)
#endif /* CONFIG_NET_PKT_TIMESTAMP */

#if defined(CONFIG_NET_STATISTICS_PERIODIC_OUTPUT)
/* A simple periodic statistic printer, used only in net core */
void net_print_statistics_all(void);
void net_print_statistics_iface(struct net_if *iface);
void net_print_statistics(void);
#else
#define net_print_statistics_all()
#define net_print_statistics_iface(iface)
#define net_print_statistics()
#endif

#endif /* __NET_STATS_H__ */
