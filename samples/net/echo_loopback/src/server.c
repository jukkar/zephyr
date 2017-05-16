/* server.c - Networking echo client/server combined */

/*
 * Copyright (c) 2017 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if 1
#define SYS_LOG_DOMAIN "echo-srv"
#define NET_SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define NET_LOG_ENABLED 1
#endif

#include <zephyr.h>
#include <sections.h>
#include <errno.h>
#include <stdio.h>

#include <net/net_pkt.h>
#include <net/net_if.h>
#include <net/net_core.h>
#include <net/net_context.h>
#include <net/net_mgmt.h>

void panic(const char *msg);

#define MAX_DBG_PRINT 64

#define MY_PORT 4242
#define PEER_PORT 8484

#if defined(CONFIG_NET_IPV6)

/* Default IP address if not found in config file */
#define PEER_IP6ADDR { { { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, \
			   0, 0, 0, 0, 0, 0, 0, 0x1 } } }
#define MY_IP6ADDR { { { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,	\
			 0, 0, 0, 0, 0, 0, 0, 0x1 } } }

#define MY_PREFIX_LEN 64

static struct net_context *server_udp_recv4;
static struct net_context *server_udp_recv6;
static struct net_context *server_tcp_recv4;
static struct net_context *server_tcp_recv6;

static struct in6_addr in6addr_my = MY_IP6ADDR;

static struct sockaddr_in6 my_addr6 = {
	.sin6_family = AF_INET6,
	.sin6_port = htons(MY_PORT),
};

static struct sockaddr_in6 peer_addr6 = {
	.sin6_family = AF_INET6,
	.sin6_port = htons(PEER_PORT),
};
#endif /* CONFIG_NET_IPV6 */

#if defined(CONFIG_NET_IPV4)
#define MY_IP4ADDR { { { 192, 0, 2, 1 } } }
#define PEER_IP4ADDR { { { 192, 0, 2, 2 } } }

static struct in_addr in4addr_my = MY_IP4ADDR;

static struct sockaddr_in my_addr4 = {
	.sin_family = AF_INET,
	.sin_port = htons(MY_PORT),
};

static struct sockaddr_in peer_addr4 = {
	.sin_family = AF_INET,
	.sin_port = htons(PEER_PORT),
};
#endif /* CONFIG_NET_IPV4 */

#define WAIT_TIME  (2 * MSEC_PER_SEC)

static void server_init(void)
{
	char buf[NET_IPV6_ADDR_LEN];

#if defined(CONFIG_NET_IPV6)
#if defined(CONFIG_NET_APP_SETTINGS)
	if (net_addr_pton(AF_INET6,
			  CONFIG_NET_APP_MY_IPV6_ADDR,
			  &my_addr6.sin6_addr) < 0) {
		NET_ERR("Invalid IPv6 address %s",
			CONFIG_NET_APP_MY_IPV6_ADDR);

		net_ipaddr_copy(&my_addr6.sin6_addr, &in6addr_my);
	}

	NET_DBG("Server IPv6 address %s",
		net_addr_ntop(AF_INET6, &my_addr6.sin6_addr,
			      (char *)buf, sizeof(buf)));

	net_ipaddr_copy(&peer_addr6.sin6_addr, &in6addr_my);

	NET_DBG("Server peer IPv6 address %s",
		net_addr_ntop(AF_INET6, &peer_addr6.sin6_addr,
			      (char *)buf, sizeof(buf)));
#endif

	do {
		struct net_if_addr *ifaddr;

		ifaddr = net_if_ipv6_addr_add(net_if_get_default(),
					      &my_addr6.sin6_addr,
					      NET_ADDR_MANUAL, 0);
	} while (0);
#endif

#if defined(CONFIG_NET_IPV4)
#if defined(CONFIG_NET_APP_SETTINGS)
	if (net_addr_pton(AF_INET,
			  CONFIG_NET_APP_MY_IPV4_ADDR,
			  &my_addr4.sin_addr) < 0) {
		NET_ERR("Invalid IPv4 address %s",
			CONFIG_NET_APP_MY_IPV4_ADDR);

		net_ipaddr_copy(&my_addr4.sin_addr, &in4addr_my);
	}

	NET_DBG("Server IPv4 address %s",
		net_addr_ntop(AF_INET, &my_addr4.sin_addr,
			      (char *)buf, sizeof(buf)));

	net_ipaddr_copy(&peer_addr4.sin_addr, &in4addr_my);

	NET_DBG("Server peer IPv4 address %s",
		net_addr_ntop(AF_INET, &peer_addr4.sin_addr,
			      (char *)buf, sizeof(buf)));
#endif

	net_if_ipv4_addr_add(net_if_get_default(), &my_addr4.sin_addr,
			     NET_ADDR_MANUAL, 0);
#endif
}

static inline bool get_context_server(struct net_context **udp_recv4,
				      struct net_context **udp_recv6,
				      struct net_context **tcp_recv4,
				      struct net_context **tcp_recv6)
{
	int ret;

#if defined(CONFIG_NET_IPV6)
	net_ipaddr_copy(&my_addr6.sin6_addr, &in6addr_my);
	my_addr6.sin6_family = AF_INET6;
	my_addr6.sin6_port = htons(MY_PORT);
#endif

#if defined(CONFIG_NET_IPV4)
	net_ipaddr_copy(&my_addr4.sin_addr, &in4addr_my);
	my_addr4.sin_family = AF_INET;
	my_addr4.sin_port = htons(MY_PORT);
#endif

#if defined(CONFIG_NET_IPV6) && defined(CONFIG_NET_UDP)
	ret = net_context_get(AF_INET6, SOCK_DGRAM, IPPROTO_UDP, udp_recv6);
	if (ret < 0) {
		NET_ERR("Cannot get network context for IPv6 UDP (%d)",
			ret);
		return false;
	}

	ret = net_context_bind(*udp_recv6, (struct sockaddr *)&my_addr6,
			       sizeof(struct sockaddr_in6));
	if (ret < 0) {
		NET_ERR("Cannot bind IPv6 UDP port %d (%d)",
			ntohs(my_addr6.sin6_port), ret);
		return false;
	}
#endif

#if defined(CONFIG_NET_IPV4) && defined(CONFIG_NET_UDP)
	ret = net_context_get(AF_INET, SOCK_DGRAM, IPPROTO_UDP, udp_recv4);
	if (ret < 0) {
		NET_ERR("Cannot get network context for IPv4 UDP (%d)",
			ret);
		return false;
	}

	ret = net_context_bind(*udp_recv4, (struct sockaddr *)&my_addr4,
			       sizeof(struct sockaddr_in));
	if (ret < 0) {
		NET_ERR("Cannot bind IPv4 UDP port %d (%d)",
			ntohs(my_addr4.sin_port), ret);
		return false;
	}
#endif

#if defined(CONFIG_NET_IPV6) && defined(CONFIG_NET_TCP)
	if (tcp_recv6) {
		ret = net_context_get(AF_INET6, SOCK_STREAM, IPPROTO_TCP,
				      tcp_recv6);
		if (ret < 0) {
			NET_ERR("Cannot get network context "
				"for IPv6 TCP (%d)", ret);
			return false;
		}

		ret = net_context_bind(*tcp_recv6,
				       (struct sockaddr *)&my_addr6,
				       sizeof(struct sockaddr_in6));
		if (ret < 0) {
			NET_ERR("Cannot bind IPv6 TCP port %d (%d)",
				ntohs(my_addr6.sin6_port), ret);
			return false;
		}

		ret = net_context_listen(*tcp_recv6, 0);
		if (ret < 0) {
			NET_ERR("Cannot listen IPv6 TCP (%d)", ret);
			return false;
		}
	}
#endif

#if defined(CONFIG_NET_IPV4) && defined(CONFIG_NET_TCP)
	if (tcp_recv4) {
		ret = net_context_get(AF_INET, SOCK_STREAM, IPPROTO_TCP,
				      tcp_recv4);
		if (ret < 0) {
			NET_ERR("Cannot get network context for IPv4 TCP");
			return false;
		}

		ret = net_context_bind(*tcp_recv4,
				       (struct sockaddr *)&my_addr4,
				       sizeof(struct sockaddr_in));
		if (ret < 0) {
			NET_ERR("Cannot bind IPv4 TCP port %d",
				ntohs(my_addr4.sin_port));
			return false;
		}

		ret = net_context_listen(*tcp_recv4, 0);
		if (ret < 0) {
			NET_ERR("Cannot listen IPv4 TCP");
			return false;
		}
	}
#endif

	return true;
}

static struct net_pkt *server_build_reply_buf(const char *name,
					      struct net_context *context,
					      struct net_pkt *pkt)
{
	struct net_buf *tmp;
	struct net_pkt *reply_pkt;
	int header_len;

	NET_INFO("%s received %d bytes", name, net_pkt_appdatalen(pkt));

	if (net_pkt_appdatalen(pkt) == 0) {
		return NULL;
	}

	reply_pkt = net_pkt_get_tx(context, K_FOREVER);

	NET_ASSERT(reply_pkt);

	tmp = pkt->frags;

	/* First fragment will contain IP header so move the data
	 * down in order to get rid of it.
	 */
	header_len = net_pkt_appdata(pkt) - tmp->data;

	/* After this pull, the tmp->data points directly to application
	 * data.
	 */
	net_buf_pull(tmp, header_len);

	/* Note that we cannot use the original data bufs here as those bufs
	 * are still used in client side TCP and will be released when we
	 * send ACK. So here we need to copy the data to be sent to client.
	 */
	while (tmp) {
		struct net_buf *frag;

		frag = net_pkt_get_data(context, K_FOREVER);

		if (!net_buf_headroom(tmp)) {
			/* If there is no link layer headers in the
			 * received fragment, then get rid of that also
			 * in the sending fragment. We end up here
			 * if MTU is larger than fragment size, this
			 * is typical for ethernet.
			 */
			net_buf_push(frag, net_buf_headroom(frag));

			frag->len = 0; /* to make fragment empty */

			/* Make sure to set the reserve so that
			 * in sending side we add the link layer
			 * header if needed.
			 */
			net_pkt_set_ll_reserve(reply_pkt, 0);
		}

		NET_ASSERT(net_buf_tailroom(frag) >= tmp->len);

		memcpy(net_buf_add(frag, tmp->len), tmp->data, tmp->len);

		net_pkt_frag_add(reply_pkt, frag);

		tmp = tmp->frags;
	}

	return reply_pkt;
}

static void pkt_sent(struct net_context *context,
		     int status, void *token, void *user_data)
{
	if (!status) {
		NET_INFO("Sent %d bytes", POINTER_TO_UINT(token));
	}
}

#if defined(CONFIG_NET_UDP)
static void server_udp_received(struct net_context *context,
				struct net_pkt *pkt,
				int status,
				void *user_data)
{
	struct net_pkt *reply_pkt;
	struct sockaddr dst_addr;
	socklen_t addrlen;
	sa_family_t family = net_pkt_family(pkt);
	static char dbg[MAX_DBG_PRINT + 1];
	int ret;

	snprintk(dbg, MAX_DBG_PRINT, "UDP IPv%c",
		 family == AF_INET6 ? '6' : '4');

	reply_pkt = server_build_reply_buf(dbg, context, pkt);

	net_pkt_unref(pkt);

	if (!reply_pkt) {
		return;
	}

	if (family == AF_INET6) {
#if defined(CONFIG_NET_IPV6)
		addrlen = sizeof(struct sockaddr_in6);
		net_ipaddr_copy(&net_sin6(&dst_addr)->sin6_addr,
				&peer_addr6.sin6_addr);
		net_sin6(&dst_addr)->sin6_port = htons(PEER_PORT);
		net_sin6(&dst_addr)->sin6_family = AF_INET6;
#endif
	} else {
#if defined(CONFIG_NET_IPV4)
		addrlen = sizeof(struct sockaddr_in);
		net_ipaddr_copy(&net_sin(&dst_addr)->sin_addr,
				&peer_addr4.sin_addr);
		net_sin(&dst_addr)->sin_port = htons(PEER_PORT);
		net_sin(&dst_addr)->sin_family = AF_INET;
#endif
	}

	ret = net_context_sendto(reply_pkt, &dst_addr, addrlen,
				 pkt_sent, 0,
				 UINT_TO_POINTER(net_buf_frags_len(
							 reply_pkt->frags)),
				 user_data);
	if (ret < 0) {
		NET_ERR("Cannot send data to peer (%d)", ret);
		net_pkt_unref(reply_pkt);
	}
}

static void server_setup_udp_recv(struct net_context *udp_recv4,
				  struct net_context *udp_recv6)
{
	int ret;

#if defined(CONFIG_NET_IPV6)
	ret = net_context_recv(udp_recv6, server_udp_received, 0, NULL);
	if (ret < 0) {
		NET_ERR("Cannot receive IPv6 UDP packets");
	}
#endif /* CONFIG_NET_IPV6 */

#if defined(CONFIG_NET_IPV4)
	ret = net_context_recv(udp_recv4, server_udp_received, 0, NULL);
	if (ret < 0) {
		NET_ERR("Cannot receive IPv4 UDP packets");
	}
#endif /* CONFIG_NET_IPV4 */
}
#endif /* CONFIG_NET_UDP */

#if defined(CONFIG_NET_TCP)
static void server_tcp_received(struct net_context *context,
				struct net_pkt *pkt,
				int status,
				void *user_data)
{
	static char dbg[MAX_DBG_PRINT + 1];
	struct net_pkt *reply_pkt;
	sa_family_t family;
	int ret;

	if (!pkt) {
		/* EOF condition */
		return;
	}

	family = net_pkt_family(pkt);

	snprintk(dbg, MAX_DBG_PRINT, "TCP IPv%c",
		 family == AF_INET6 ? '6' : '4');

	reply_pkt = server_build_reply_buf(dbg, context, pkt);

	net_pkt_unref(pkt);

	if (!reply_pkt) {
		return;
	}

	ret = net_context_send(reply_pkt, pkt_sent, K_NO_WAIT,
			       UINT_TO_POINTER(net_buf_frags_len(
						       reply_pkt->frags)),
			       NULL);
	if (ret < 0) {
		NET_ERR("Cannot send data to peer (%d)", ret);
		net_pkt_unref(reply_pkt);

		panic("Cannot send data");
	}
}

static void tcp_accepted(struct net_context *context,
			 struct sockaddr *addr,
			 socklen_t addrlen,
			 int error,
			 void *user_data)
{
	int ret;

	NET_DBG("Accept called, context %p error %d", context, error);

	ret = net_context_recv(context, server_tcp_received, 0, NULL);
	if (ret < 0) {
		NET_ERR("Cannot receive TCP packet (family %d)",
			net_context_get_family(context));
	}
}

static void setup_tcp_accept(struct net_context *tcp_recv4,
			     struct net_context *tcp_recv6)
{
	int ret;

#if defined(CONFIG_NET_IPV6)
	ret = net_context_accept(tcp_recv6, tcp_accepted, 0, NULL);
	if (ret < 0) {
		NET_ERR("Cannot receive IPv6 TCP packets (%d)", ret);
	}
#endif /* CONFIG_NET_IPV6 */

#if defined(CONFIG_NET_IPV4)
	ret = net_context_accept(tcp_recv4, tcp_accepted, 0, NULL);
	if (ret < 0) {
		NET_ERR("Cannot receive IPv4 TCP packets (%d)", ret);
	}
#endif /* CONFIG_NET_IPV4 */
}
#endif /* CONFIG_NET_TCP */

void server_startup(void)
{
	server_init();

	/* Server setup */
	if (!get_context_server(&server_udp_recv4, &server_udp_recv6,
				&server_tcp_recv4, &server_tcp_recv6)) {
		panic("Cannot get network contexts for server");
	}

#if defined(CONFIG_NET_TCP)
	setup_tcp_accept(server_tcp_recv4, server_tcp_recv6);
#endif

#if defined(CONFIG_NET_UDP)
	server_setup_udp_recv(server_udp_recv4, server_udp_recv6);
#endif

	NET_INFO("Server starting to wait data");
}
