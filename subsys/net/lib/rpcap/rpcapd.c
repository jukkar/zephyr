/*
 * Copyright (c) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(net_rpcapd, CONFIG_NET_RPCAP_LOG_LEVEL);

#include <toolchain/common.h>
#include <kernel.h>
#include <fcntl.h>
#include <net/socket.h>
#include <net/net_core.h>
#include <net/net_if.h>
#include <net/rpcap.h>

#include "net_private.h"
#include "rpcap_internal.h"

#define RPCAPD_DEFAULT_PORT CONFIG_NET_RPCAPD_LISTENING_PORT
#define THREAD_PRIORITY K_PRIO_COOP(8)

K_MEM_SLAB_DEFINE(rpcapd_rx_pkts, sizeof(struct net_pkt),
		  CONFIG_NET_RPCAPD_PKT_RX_COUNT, 4);
K_MEM_SLAB_DEFINE(rpcapd_tx_pkts, sizeof(struct net_pkt),
		  CONFIG_NET_RPCAPD_PKT_TX_COUNT, 4);

NET_BUF_POOL_FIXED_DEFINE(rpcapd_rx_bufs, CONFIG_NET_RPCAPD_BUF_RX_COUNT,
			  CONFIG_NET_RPCAPD_BUF_DATA_SIZE, NULL);
NET_BUF_POOL_FIXED_DEFINE(rpcapd_tx_bufs, CONFIG_NET_RPCAPD_BUF_TX_COUNT,
			  CONFIG_NET_RPCAPD_BUF_DATA_SIZE, NULL);

K_THREAD_STACK_DEFINE(handler_stack, CONFIG_NET_RPCAPD_HANDLER_STACK_SIZE);
static struct k_thread handler_thread;
static k_tid_t handler_tid;

#if defined(CONFIG_NET_RPCAPD_MODE_PASSIVE)
#if defined(CONFIG_NET_IPV4)
static int rpcapd_sock_v4;
#endif

#if defined(CONFIG_NET_IPV6)
static int rpcapd_sock_v6;
#endif
#endif /* CONFIG_NET_RPCAPD_MODE_PASSIVE */

#if defined(CONFIG_NET_RPCAPD_MODE_ACTIVE)
static struct sockaddr peer_addr;
static socklen_t peer_addr_len;
static int rpcapd_sock;
#endif

/* Is the configuration of the system ok */
static bool rpcapd_ok;

#if defined(CONFIG_NET_RPCAPD_MODE_ACTIVE)
static int create_connector(struct sockaddr *peer_addr,
			    socklen_t *peer_addr_len)
{
#if defined(CONFIG_NET_IPV6)
	struct sockaddr_in6 *peer_addr6;
	struct sockaddr_in6 local_addr6 = {
		.sin6_family = AF_INET6,
		.sin6_port = 0,
	};
#endif
#if defined(CONFIG_NET_IPV4)
	struct sockaddr_in *peer_addr4;
	struct sockaddr_in local_addr4 = {
		.sin_family = AF_INET,
		.sin_port = 0,
	};
#endif
	struct sockaddr *local_addr = NULL;
	socklen_t addr_len = 0;
	
	if (CONFIG_NET_RPCAPD_REMOTE_HOST[0] == '\0') {
		NET_ERR("Remote host not set");
		return -EINVAL;
	}

	ret = net_ipaddr_parse(CONFIG_NET_RPCAPD_REMOTE_HOST,
			       sizeof(CONFIG_NET_RPCAPD_REMOTE_HOST) - 1,
			       peer_addr);
	if (!ret) {
		NET_DBG("Cannot parse \"%s\"", CONFIG_NET_RPCAPD_REMOTE_HOST);
		return;
	}

#if defined(CONFIG_NET_IPV6)
	if (peer_addr->sa_family == AF_INET6) {
		peer_addr6 = net_sin6(peer_addr);
		if (peer_addr6->sin6_port == 0) {
			peer_addr6->sin6_port = htons(RPCAP_DEFAULT_PORT);
		}

		local_addr = (struct sockaddr *)&local_addr6;
		*peer_addr_len = sizeof(struct sockaddr_in6);
	} else
#endif
#if defined(CONFIG_NET_IPV4)
	if (peer_addr->sa_family == AF_INET) {
		peer_addr4 = net_sin(peer_addr);
		if (peer_addr4->sin_port == 0) {
			peer_addr4->sin_port = htons(RPCAP_DEFAULT_PORT);
		}

		local_addr = (struct sockaddr *)&local_addr4;
		*peer_addr_len = sizeof(struct sockaddr_in);
	} else
#endif
	{
		NET_DBG("Invalid family %d", peer_addr.sa_family);
		return -EINVAL;
	}

	ret = zsock_socket(peer_addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (ret < 0) {
		ret = -errno;
		NET_DBG("Cannot %s socket (%d)", "create", ret);
		return ret;
	}

	rpcapd_sock = ret;

	ret = zsock_bind(rpcapd_sock, local_addr, addr_len);
	if (ret < 0) {
		ret = -errno;
		NET_DBG("Cannot %s socket (%d)", "bind", ret);
		(void)zsock_close(rpcapd_sock);
		return ret;
	}

	return 0;
}
#endif /* CONFIG_NET_RPCAPD_MODE_ACTIVE */

#if defined(CONFIG_NET_RPCAPD_MODE_PASSIVE)
static int setup_listen_sock(int sock, sa_family_t family,
			     struct sockaddr *local_addr, socklen_t addr_len)
{
	int ret;

	ret = zsock_bind(sock, local_addr, addr_len);
	if (ret < 0) {
		ret = -errno;
		NET_DBG("Cannot %s context (%d)", "bind", ret);
		return ret;
	}

	ret = zsock_listen(sock, 1);
	if (ret < 0) {
		ret = -errno;
		NET_DBG("Cannot %s context (%d)", "listen", ret);
		return ret;
	}

	return 0;
}

static int create_listener(void)
{
#if defined(CONFIG_NET_IPV6)
	struct sockaddr_in6 local_addr6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(RPCAPD_DEFAULT_PORT),
	};
#endif
#if defined(CONFIG_NET_IPV4)
	struct sockaddr_in local_addr4 = {
		.sin_family = AF_INET,
		.sin_port = htons(RPCAPD_DEFAULT_PORT),
	};
#endif
	int ret;

#if defined(CONFIG_NET_IPV6) && defined(CONFIG_NET_IPV4)
#define NUM_FDS 2

	ret = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ret < 0) {
		NET_DBG("Cannot %s socket (%d)", "create IPv4", ret);
		return ret;
	}

	rpcapd_sock_v4 = ret;

	ret = zsock_socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (ret < 0) {
		ret = -errno;
		NET_DBG("Cannot %s socket (%d)", "create IPv6", ret);
		(void)zsock_close(rpcapd_sock_v4);
		return ret;
	}

	rpcapd_sock_v6 = ret;

	ret = setup_listen_sock(rpcapd_sock_v4, AF_INET,
				(struct sockaddr *)&local_addr4,
				sizeof(local_addr4));
	if (ret < 0) {
		(void)zsock_close(rpcapd_sock_v6);
		(void)zsock_close(rpcapd_sock_v4);
		return ret;
	}

	ret = setup_listen_sock(rpcapd_sock_v6, AF_INET6,
				(struct sockaddr *)&local_addr6,
				sizeof(local_addr6));
	if (ret < 0) {
		(void)zsock_close(rpcapd_sock_v6);
		(void)zsock_close(rpcapd_sock_v4);
		return ret;
	}
#endif /* IPv6 && IPV4 */

#if defined(CONFIG_NET_IPV6) && !defined(CONFIG_NET_IPV4)
#define NUM_FDS 1

	ret = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (ret < 0) {
		ret = -errno;
		NET_DBG("Cannot %s socket (%d)", "create IPv6", ret);
		return ret;
	}

	rpcapd_sock_v6 = ret;

	ret = setup_listen_sock(rpcapd_sock_v6, AF_INET6, &net_ctx6,
				(struct sockaddr *)&local_addr6,
				sizeof(local_addr6));
	if (ret < 0) {
		(void)zsock_close(rpcapd_sock_v6);
		return ret;
	}
#endif /* IPv6 && !IPv4 */

#if !defined(CONFIG_NET_IPV6) && defined(CONFIG_NET_IPV4)
#define NUM_FDS 1

	ret = zsock_socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ret < 0) {
		ret = -errno;
		NET_DBG("Cannot %s socket (%d)", "create IPv4", ret);
		return ret;
	}

	rpcapd_sock_v4 = ret;

	ret = setup_listen_sock(rpcapd_sock_v4, AF_INET,
				(struct sockaddr *)&local_addr4,
				sizeof(local_addr4));
	if (ret < 0) {
		(void)zsock_close(rpcapd_sock_v4);
		return ret;
	}
#endif  /* !IPv6 && IPv4 */

	return 0;
}

static void setup_header(struct zrpcap_msg_header *hdr,
			 u8_t version,
			 u8_t type,
			 u16_t value,
			 u32_t len)
{
	memset(hdr, 0, sizeof(*hdr));

	hdr->version = version;
	hdr->type = type;
	hdr->value = htons(value);
	hdr->len = htonl(len);
}

static const char *iface2str(struct net_if *iface)
{
#ifdef CONFIG_NET_L2_IEEE802154
	if (net_if_l2(iface) == &NET_L2_GET_NAME(IEEE802154)) {
		return "IEEE 802.15.4";
	}
#endif

#ifdef CONFIG_NET_L2_ETHERNET
	if (net_if_l2(iface) == &NET_L2_GET_NAME(ETHERNET)) {
		return "Ethernet";
	}
#endif

#ifdef CONFIG_NET_L2_PPP
	if (net_if_l2(iface) == &NET_L2_GET_NAME(PPP)) {
		return "PPP";
	}
#endif

#ifdef CONFIG_NET_L2_DUMMY
	if (net_if_l2(iface) == &NET_L2_GET_NAME(DUMMY)) {
		return "Dummy";
	}
#endif

#ifdef CONFIG_NET_L2_OPENTHREAD
	if (net_if_l2(iface) == &NET_L2_GET_NAME(OPENTHREAD)) {
		return "OpenThread";
	}
#endif

#ifdef CONFIG_NET_L2_BT
	if (net_if_l2(iface) == &NET_L2_GET_NAME(BLUETOOTH)) {
		return "Bluetooth";
	}
#endif

#ifdef CONFIG_NET_OFFLOAD
	if (net_if_is_ip_offloaded(iface)) {
		return "IP Offload";
	}
#endif

#ifdef CONFIG_NET_L2_CANBUS
	if (net_if_l2(iface) == &NET_L2_GET_NAME(CANBUS)) {
		return "CANBUS";
	}
#endif

#ifdef CONFIG_NET_L2_CANBUS_RAW
	if (net_if_l2(iface) == &NET_L2_GET_NAME(CANBUS_RAW)) {
		return "CANBUS_RAW";
	}
#endif

	return "<unknown type>";
}

struct ifaces {
	int fd;
	u8_t *buf;
	size_t buf_len;
	size_t pos;
};

static void calc_total_len_cb(struct net_if *iface, void *user_data)
{
	size_t *total_len = user_data;
	int ipv6_count, ipv4_count;
	struct net_if_ipv6 *ipv6;
	struct net_if_ipv4 *ipv4;
	const char *description;
	char name[sizeof("123")]; /* Max number of network interfaces 999 */
	int i, desc_len, name_len;

	description = iface2str(iface);

	memset(name, 0, sizeof(name));
	snprintk(name, sizeof(name) - 1, "%d", net_if_get_by_iface(iface));

	name_len = strlen(name);
	desc_len = strlen(description);

	if (net_if_config_ipv6_get(iface, &ipv6) == 0) {
		for (i = 0, ipv6_count = 0; i < NET_IF_MAX_IPV6_ADDR; i++) {
			if (ipv6->unicast[i].is_used) {
				ipv6_count++;
			}
		}
	}

	if (net_if_config_ipv4_get(iface, &ipv4) == 0) {
		for (i = 0, ipv4_count = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
			if (ipv4->unicast[i].is_used) {
				ipv4_count++;
			}
		}
	}

	(*total_len) += name_len + desc_len + (ipv4_count + ipv6_count) *
				sizeof(struct zrpcap_findalldevs_ifaddr);
}

#define CHECK_AND_SEND(len)						\
	/* Is the reply going to fit the buffer */			\
	if ((ifaces->pos + len) >= ifaces->buf_len) {			\
		zsock_send(ifaces->fd, ifaces->buf, ifaces->pos, 0);	\
		ifaces->pos = 0;					\
	}


static void send_iface_data_cb(struct net_if *iface, void *user_data)
{
	struct ifaces *ifaces = user_data;
	struct net_if_ipv6 *ipv6 = NULL;
	struct net_if_ipv4 *ipv4 = NULL;
	struct zrpcap_find_all_iface iface_reply;
	int ipv6_count, ipv4_count;
	const char *description;
	char name[sizeof("123")];
	int i, desc_len, name_len;
	u16_t tmp;

	/* Check the total number of IP addresses the network interface has.
	 * We need to go through them later when sending to peer.
	 */
	if (net_if_config_ipv6_get(iface, &ipv6) == 0) {
		for (i = 0, ipv6_count = 0; i < NET_IF_MAX_IPV6_ADDR; i++) {
			if (ipv6->unicast[i].is_used) {
				ipv6_count++;
			}
		}
	}

	if (net_if_config_ipv4_get(iface, &ipv4) == 0) {
		for (i = 0, ipv4_count = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
			if (ipv4->unicast[i].is_used) {
				ipv4_count++;
			}
		}
	}

	description = iface2str(iface);

	memset(name, 0, sizeof(name));
	snprintk(name, sizeof(name) - 1, "%d", net_if_get_by_iface(iface));

	name_len = strlen(name);
	desc_len = strlen(description);

	iface_reply.iface_name_len = htons(name_len);
	iface_reply.description_len = htons(desc_len);
	iface_reply.iface_flags = 0;
	iface_reply.num_addr = htons(ipv4_count + ipv6_count);
	iface_reply.dummy = 0;

	CHECK_AND_SEND(sizeof(iface_reply));
	memcpy(&ifaces->buf[ifaces->pos], &iface_reply, sizeof(iface_reply));
	ifaces->pos += sizeof(iface_reply);

	CHECK_AND_SEND(name_len);
	memcpy(&ifaces->buf[ifaces->pos], name, name_len);
	ifaces->pos += name_len;

	CHECK_AND_SEND(desc_len);
	memcpy(&ifaces->buf[ifaces->pos], description, desc_len);
	ifaces->pos += desc_len;

	for (i = 0; ipv6 && i < NET_IF_MAX_IPV6_ADDR; i++) {
		int padding;

		if (!ipv6->unicast[i].is_used) {
			continue;
		}

		/* There are lot of data to send. The fields in struct
		 * zrpcap_findalldevs_ifaddr fields.
		 *    Network address
		 *    Netmask
		 *    Broadcast address
		 *    Point-to-point destination address
		 */
		/* Network address */
		/* Family */
		CHECK_AND_SEND(sizeof(u16_t));
		tmp = htons(RPCAP_AF_INET6);
		UNALIGNED_PUT(tmp, &ifaces->buf[ifaces->pos]);
		ifaces->pos += sizeof(u16_t);

		/* Port number */
		CHECK_AND_SEND(sizeof(u16_t));
		UNALIGNED_PUT(0, &ifaces->buf[ifaces->pos]);
		ifaces->pos += sizeof(u16_t);

		/* Flow id */
		CHECK_AND_SEND(sizeof(u32_t));
		UNALIGNED_PUT(0, &ifaces->buf[ifaces->pos]);
		ifaces->pos += sizeof(u32_t);

		/* IPv6 address */
		CHECK_AND_SEND(sizeof(struct in6_addr));
		memcpy(&ifaces->buf[ifaces->pos],
		       ipv6->unicast[i].address.in6_addr.s6_addr,
		       sizeof(struct in6_addr));
		ifaces->pos += sizeof(struct in6_addr);

		/* Scope id */
		CHECK_AND_SEND(sizeof(u32_t));
		UNALIGNED_PUT(0, &ifaces->buf[ifaces->pos]);
		ifaces->pos += sizeof(u32_t);

		/* Padding */
		padding = sizeof(struct zrpcap_sockaddr) -
					sizeof(struct zrpcap_sockaddr_in6);
		CHECK_AND_SEND(padding);
		memset(&ifaces->buf[ifaces->pos], 0, padding);
		ifaces->pos += padding;

		/* Netmask */
		CHECK_AND_SEND(sizeof(struct zrpcap_sockaddr));
		memset(&ifaces->buf[ifaces->pos], 0,
		       sizeof(struct zrpcap_sockaddr));
		ifaces->pos += sizeof(struct zrpcap_sockaddr);

		/* Broadcast address */
		CHECK_AND_SEND(sizeof(struct zrpcap_sockaddr));
		memset(&ifaces->buf[ifaces->pos], 0,
		       sizeof(struct zrpcap_sockaddr));
		ifaces->pos += sizeof(struct zrpcap_sockaddr);

		/* P2P dest address */
		CHECK_AND_SEND(sizeof(struct zrpcap_sockaddr));
		memset(&ifaces->buf[ifaces->pos], 0,
		       sizeof(struct zrpcap_sockaddr));
		ifaces->pos += sizeof(struct zrpcap_sockaddr);
	}

	for (i = 0; ipv4 && i < NET_IF_MAX_IPV4_ADDR; i++) {
		int padding;

		if (!ipv4->unicast[i].is_used) {
			continue;
		}

		/* Network Address */
		/* Family */
		CHECK_AND_SEND(sizeof(u16_t));
		tmp = htons(RPCAP_AF_INET);
		UNALIGNED_PUT(tmp, &ifaces->buf[ifaces->pos]);
		ifaces->pos += sizeof(u16_t);

		/* Port number */
		CHECK_AND_SEND(sizeof(u16_t));
		UNALIGNED_PUT(0, &ifaces->buf[ifaces->pos]);
		ifaces->pos += sizeof(u16_t);

		/* IPv4 address */
		CHECK_AND_SEND(sizeof(struct in_addr));
		memcpy(&ifaces->buf[ifaces->pos],
		       ipv4->unicast[i].address.in_addr.s4_addr,
		       sizeof(struct in_addr));
		ifaces->pos += sizeof(struct in_addr);

		/* IPv4 padding (zero field IPv4 rpcap sockaddr_in) */
		CHECK_AND_SEND(8);
		memset(&ifaces->buf[ifaces->pos], 0, 8);
		ifaces->pos += 8;

		/* Padding */
		padding = sizeof(struct zrpcap_sockaddr) -
					sizeof(struct zrpcap_sockaddr_in);
		CHECK_AND_SEND(padding);
		memset(&ifaces->buf[ifaces->pos], 0, padding);
		ifaces->pos += padding;

		/* Netmask */
		/* Family */
		CHECK_AND_SEND(sizeof(u16_t));
		tmp = htons(RPCAP_AF_INET);
		UNALIGNED_PUT(tmp, &ifaces->buf[ifaces->pos]);
		ifaces->pos += sizeof(u16_t);

		/* Port number */
		CHECK_AND_SEND(sizeof(u16_t));
		UNALIGNED_PUT(0, &ifaces->buf[ifaces->pos]);
		ifaces->pos += sizeof(u16_t);

		/* Netmask IPv4 address */
		CHECK_AND_SEND(sizeof(struct in_addr));
		memcpy(&ifaces->buf[ifaces->pos], &ipv4->netmask,
		       sizeof(struct in_addr));
		ifaces->pos += sizeof(struct in_addr);

		/* IPv4 padding (zero field IPv4 rpcap sockaddr_in) */
		CHECK_AND_SEND(8);
		memset(&ifaces->buf[ifaces->pos], 0, 8);
		ifaces->pos += 8;

		/* Padding */
		padding = sizeof(struct zrpcap_sockaddr) -
					sizeof(struct zrpcap_sockaddr_in);
		CHECK_AND_SEND(padding);
		memset(&ifaces->buf[ifaces->pos], 0, padding);
		ifaces->pos += padding;

		/* Broadcast address */
		CHECK_AND_SEND(sizeof(struct zrpcap_sockaddr));
		memset(&ifaces->buf[ifaces->pos], 0,
		       sizeof(struct zrpcap_sockaddr));
		ifaces->pos += sizeof(struct zrpcap_sockaddr);

		/* P2P dest address */
		CHECK_AND_SEND(sizeof(struct zrpcap_sockaddr));
		memset(&ifaces->buf[ifaces->pos], 0,
		       sizeof(struct zrpcap_sockaddr));
		ifaces->pos += sizeof(struct zrpcap_sockaddr);
	}
}

static int handle_iface_req(int client_sock, struct zrpcap_msg_header *hdr,
			    u8_t *buf, size_t buf_len, size_t pos)
{
	struct ifaces ifaces;
	size_t total_len = 0;

	/* It is unfortunate but we need to go through all the network
	 * interfaces twice. We cannot store all the network interface
	 * data as they consume too much memory. So the RPCAP header, which
	 * has the total length, is sent while we are still reading network
	 * interface data.
	 */
	net_if_foreach(calc_total_len_cb, &total_len);

	setup_header(hdr, RPCAP_MIN_VERSION, RPCAP_MSG_FINDALLIF_REPLY,
		     0, total_len);

	ifaces.fd = client_sock;
	ifaces.buf = buf;
	ifaces.buf_len = buf_len;
	ifaces.pos = pos;

	net_if_foreach(send_iface_data_cb, &ifaces);
}

static int handle_auth_req(int client_sock, struct zrpcap_msg_header *hdr,
			   u8_t *buf, size_t buf_len, size_t pos)
{
	struct zrpcap_msg_auth_reply auth_reply;

	if (pos < (sizeof(*hdr) + sizeof(struct zrpcap_msg_auth_req))) {
		return -EAGAIN;
	}

	setup_header(hdr, RPCAP_MIN_VERSION, RPCAP_MSG_AUTH_REPLY,
		     0, sizeof(auth_reply));

	auth_reply.min_version = RPCAP_MIN_VERSION;
	auth_reply.max_version = RPCAP_MAX_VERSION;

	memcpy((u8_t *)hdr + sizeof(*hdr), &auth_reply, sizeof(auth_reply));

	zsock_send(client_sock, buf, sizeof(*hdr) + sizeof(auth_reply), 0);

	return 0;
}

static void process_request(int client_sock,
			    struct sockaddr *client_addr,
			    socklen_t client_addr_len)
{
	size_t pos = 0;
	struct zrpcap_msg_header *hdr;
	char buf[sizeof(struct zrpcap_findalldevs_ifaddr)];
	int len, ret;

	if (CONFIG_NET_RPCAPD_CONNECTION_FROM[0]) {
		char addr[NET_IPV6_ADDR_LEN];
		char *ptr;

		ptr = net_addr_ntop(client_addr->sa_family,
				    client_addr, addr, sizeof(addr));
		if (!ptr || strncmp(addr, CONFIG_NET_RPCAPD_CONNECTION_FROM,
				    sizeof(addr))) {
			NET_INFO("Unauthorized client access");
			goto closing;
		}
	}

	do {
		if (pos == 0) {
			memset(buf, 0, sizeof(buf));
		}

		len = zsock_recv(client_sock, &buf[pos], sizeof(buf) - pos, 0);
		if (len > 0) {
			pos += len;

			if (pos < sizeof(struct zrpcap_msg_header)) {
				continue;
			}

			hdr = (struct zrpcap_msg_header *)buf;

			if (hdr->version != RPCAP_MIN_VERSION) {
				goto closing;
			}

			NET_DBG("hdr version %d type %d value %d len %d",
				hdr->version, hdr->type, ntohs(hdr->value),
				ntohl(hdr->len));

			switch (hdr->type) {
			case RPCAP_MSG_AUTH_REQ:
				ret = handle_auth_req(client_sock, hdr,
						      buf, sizeof(buf), pos);
				if (ret == -EAGAIN) {
					continue;
				}

				pos = 0;
				break;

			case RPCAP_MSG_FINDALLIF_REQ:
				ret = handle_iface_req(client_sock, hdr,
						       buf, sizeof(buf), pos);
				if (ret == -EAGAIN) {
					continue;
				}

				pos = 0;
				break;
			}

		} else if (len == 0) {
			goto closing;
		} else {
			NET_DBG("Connection error (%d)", -errno);
		}
	} while (len > 0);

closing:
	NET_INFO("Connection from %s:%d closed",
		 log_strdup(net_sprint_addr(client_addr->sa_family,
					    &net_sin((const struct sockaddr *)
						     client_addr)->sin_addr)),
		 ntohs(((struct sockaddr_in *)client_addr)->sin_port));

	(void)zsock_close(client_sock);
}
#endif /* CONFIG_NET_RPCAPD_MODE_PASSIVE */

static void rpcapd_handler(void *active_sock,
			   void *passive_v6_sock,
			   void *passive_v4_sock)
{
	int ret;

#if defined(CONFIG_NET_RPCAPD_MODE_ACTIVE)
	int sock = POINTER_TO_INT(active_sock);

	while (true) {
		ret = zsock_connect(sock, &peer_addr, peer_addr_len);
		if (ret < 0) {
			NET_DBG("Cannot %s socket (%d)", "connect", ret);
			(void)zsock_close(sock);
			break;
		}
	}
#endif /* ACTIVE */

#if defined(CONFIG_NET_RPCAPD_MODE_PASSIVE)
	struct zsock_pollfd pollfds[NUM_FDS];
	int sock1 = -1;
	int sock2 = -1;
	int fd_count = 0;
	int i;

	if (sock1) {
		sock1 = POINTER_TO_INT(passive_v6_sock);

		pollfds[fd_count].fd = sock1;
		pollfds[fd_count++].events = ZSOCK_POLLIN;
	}

	if (sock2) {
		sock2 = POINTER_TO_INT(passive_v4_sock);

		pollfds[fd_count].fd = sock2;
		pollfds[fd_count++].events = ZSOCK_POLLIN;
	}

	while (true) {
		struct sockaddr_storage client_addr;
		socklen_t client_addr_len = sizeof(client_addr);

		memset(&client_addr, 0, sizeof(client_addr));

		ret = zsock_poll(pollfds, fd_count, K_FOREVER);
		if (ret < 0) {
			NET_DBG("poll error %d", errno);
			continue;
		}

		for (i = 0; i < fd_count; i++) {
			int fd;

			if (!(pollfds[i].revents & ZSOCK_POLLIN)) {
				continue;
			}

			fd = pollfds[i].fd;

			ret = zsock_accept(fd, (struct sockaddr *)&client_addr,
					   &client_addr_len);
			if (ret < 0) {
				NET_DBG("Cannot %s context (%d)", "accept",
					-errno);
				continue;
			}

			NET_INFO("Connection from %s:%d",
				 log_strdup(net_sprint_addr(
					client_addr.ss_family,
					&net_sin((const struct sockaddr *)
						     &client_addr)->sin_addr)),
				 ntohs(((struct sockaddr_in *)&client_addr)->
							      sin_port));

			process_request(ret,
					(struct sockaddr *)&client_addr,
					client_addr_len);
			break;
		}
	}
#endif /* PASSIVE */
}

static void setup_socket(void)
{
	int ret;

	if (rpcapd_ok) {
		return;
	}

#if defined(CONFIG_NET_RPCAPD_MODE_ACTIVE)
	ret = create_connector(&peer_addr, &peer_addr_len);
#endif

#if defined(CONFIG_NET_RPCAPD_MODE_PASSIVE)
	ret = create_listener();
#endif

	if (ret < 0) {
		NET_ERR("Cannot setup sockets (%d), RPCAP disabled.", ret);
		return;
	}

	rpcapd_ok = true;

	handler_tid = k_thread_create(&handler_thread,
				      handler_stack,
				      K_THREAD_STACK_SIZEOF(handler_stack),
				      (k_thread_entry_t)rpcapd_handler,
#if defined(CONFIG_NET_RPCAPD_MODE_ACTIVE)
				      INT_TO_POINTER(rpcapd_sock),
#else
				      NULL,
#endif /* ACTIVE */
#if defined(CONFIG_NET_RPCAPD_MODE_PASSIVE)
#if defined(CONFIG_NET_IPV6)
				      INT_TO_POINTER(rpcapd_sock_v6),
#else
				      NULL,
#endif /* IPV6 */
#if defined(CONFIG_NET_IPV4)
				      INT_TO_POINTER(rpcapd_sock_v4),
#else
				      NULL,
#endif /* IPV4 */
#endif /* PASSIVE */
				      THREAD_PRIORITY, 0, K_NO_WAIT);

	(void)k_thread_name_set(handler_tid, "rpcapd");
}

void zrpcapd_init(void)
{
	BUILD_ASSERT_MSG(CONFIG_NET_RPCAPD_PKT_RX_COUNT > 0,
		"Minimum value for CONFIG_NET_RPCAPD_PKT_RX_COUNT is 1");

	BUILD_ASSERT_MSG(CONFIG_NET_RPCAPD_PKT_TX_COUNT > 0,
		"Minimum value for CONFIG_NET_RPCAPD_PKT_TX_COUNT is 1");

	BUILD_ASSERT_MSG(CONFIG_NET_RPCAPD_BUF_RX_COUNT > 0,
		"Minimum value for CONFIG_NET_RPCAPD_BUF_RX_COUNT is 1");

	BUILD_ASSERT_MSG(CONFIG_NET_RPCAPD_BUF_TX_COUNT > 0,
		"Minimum value for CONFIG_NET_RPCAPD_BUF_TX_COUNT is 1");

	zrpcap_init();

	setup_socket();
}
