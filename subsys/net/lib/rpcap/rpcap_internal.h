/*
 * Copyright (c) 2020 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/** @cond INTERNAL_HIDDEN */

#define RPCAP_MIN_VERSION 0
#define RPCAP_MAX_VERSION 0

/* Flag indicating a reply message */
#define RPCAP_MSG_REPLY          0x80

/* Messages types */
#define RPCAP_MSG_ERROR             1
#define RPCAP_MSG_FINDALLIF_REQ     2
#define RPCAP_MSG_OPEN_REQ          3
#define RPCAP_MSG_STARTCAP_REQ      4
#define RPCAP_MSG_UPDATEFILTER_REQ  5
#define RPCAP_MSG_CLOSE             6
#define RPCAP_MSG_PACKET            7
#define RPCAP_MSG_AUTH_REQ          8
#define RPCAP_MSG_STATS_REQ         9
#define RPCAP_MSG_ENDCAP_REQ        10
#define RPCAP_MSG_SETSAMPLING_REQ   11

#define RPCAP_MSG_FINDALLIF_REPLY			\
	(RPCAP_MSG_FINDALLIF_REQ | RPCAP_MSG_REPLY)
#define RPCAP_MSG_OPEN_REPLY				\
	(RPCAP_MSG_OPEN_REQ | RPCAP_MSG_REPLY)
#define RPCAP_MSG_STARTCAP_REPLY			\
	(RPCAP_MSG_STARTCAP_REQ | RPCAP_MSG_REPLY)
#define RPCAP_MSG_UPDATEFILTER_REPLY			\
	(RPCAP_MSG_UPDATEFILTER_REQ | RPCAP_MSG_REPLY)
#define RPCAP_MSG_AUTH_REPLY				\
	(RPCAP_MSG_AUTH_REQ | RPCAP_MSG_REPLY)
#define RPCAP_MSG_STATS_REPLY				\
	(RPCAP_MSG_STATS_REQ | RPCAP_MSG_REPLY)
#define RPCAP_MSG_ENDCAP_REPLY				\
	(RPCAP_MSG_ENDCAP_REQ | RPCAP_MSG_REPLY)
#define RPCAP_MSG_SETSAMPLING_REPLY			\
	(RPCAP_MSG_SETSAMPLING_REQ | RPCAP_MSG_REPLY)

#define RPCAP_STARTCAPREQ_FLAG_PROMISC		0x00000001
#define RPCAP_STARTCAPREQ_FLAG_DGRAM		0x00000002
#define RPCAP_STARTCAPREQ_FLAG_SERVEROPEN	0x00000004
#define RPCAP_STARTCAPREQ_FLAG_INBOUND		0x00000008
#define RPCAP_STARTCAPREQ_FLAG_OUTBOUND		0x00000010
/** @endcond */

/** RPCAP message header */
struct zrpcap_msg_header {
	/**
	 * RPCAP version number
	 */
	u8_t version;

	/**
	 * RPCAP message type
	 */
	u8_t type;

	/**
	 * Message dependent value
	 */
	u16_t value;

	/**
	 * Payload length
	 */
	u32_t len;
} __packed;

struct zrpcap_msg_auth_req {
	/**
	 * Authentication type
	 */
	u16_t type;

	/**
	 * Dummy, set to zero
	 */
	u16_t dummy;

	/**
	 * Username len
	 */
	u16_t username_len;

	/**
	 * Password len
	 */
	u16_t passwd_len;
} __packed;

struct zrpcap_msg_auth_reply {
	/**
	 * Minimum version supported
	 */
	u8_t min_version;

	/**
	 * Maximum version supported
	 */
	u8_t max_version;
} __packed;

struct zrpcap_find_all_iface {
	/**
	 * Network interface name length
	 */
	u16_t iface_name_len;

	/**
	 * Network interface description length
	 */
	u16_t description_len;

	/**
	 * Network interface flags
	 */
	u32_t iface_flags;

	/**
	 * Number of network addresses
	 */
	u16_t num_addr;

	/**
	 * Dummy, must be set to 0
	 */
	u16_t dummy;
} __packed;

/* Note that this is in format expected by Windows */
struct zrpcap_sockaddr {
	/**
	 * Address family
	 */
	u16_t family;

	/**
	 * Address data
	 */
	char data[128-2];
} __packed;

/* Value on all OSes, originally in Windows */
#define RPCAP_AF_INET 2

/* Format of an IPv4 address as sent over the wire */
struct zrpcap_sockaddr_in {
	/**
	 * Address family
	 */
	u16_t family;

	/**
	 * Port number
	 */
	u16_t port;

	/**
	 * IPv4 address
	 */
	u32_t addr;

	/**
	 * Padding
	 */
	u8_t zero[8];
} __packed;

/* Value originally on Windows */
#define RPCAP_AF_INET6 23

/* Format of an IPv6 address as sent over the wire */
struct zrpcap_sockaddr_in6 {
	/**
	 * Address family
	 */
	u16_t family;

	/**
	 * Port number
	 */
	u16_t port;

	/**
	 * IPv6 flow information
	 */
	u32_t flowinfo;

	/**
	 * IPv6 address
	 */
	u8_t addr[16];

	/**
	 * Scope zone index
	 */
	u32_t scope_id;
};

/* Format of the message for the address listing (findalldevs command) */
struct zrpcap_findalldevs_ifaddr {
	/**
	 * Network address
	 */
	struct zrpcap_sockaddr addr;

	/**
	 * Netmask for that address
	 */
	struct zrpcap_sockaddr netmask;

	/**
	 * Broadcast address for that address
	 */
	struct zrpcap_sockaddr bcast_addr;

	/**
	 * P2P destination address for that address
	 */
	struct zrpcap_sockaddr dest_addr;
} __packed;

#if 0
	/**
	 * GMT to local correction. For Zephyr this is always 0.
	 */
	s32_t thiszone;

	/**
	 * Accuracy of timestamps. Currently this is set to 0.
	 */
	u32_t sigfigs;

	/**
	 * Max length of captured packets in octets
	 */
	u32_t snaplen;

	/**
	 * Data link type (LINKTYPE_*)
	 */
	u32_t linktype;
#endif

/**
 * Individual packet header
 */
struct zrpcap_pkt_header {
	/**
	 * Timestamp seconds
	 */
	u32_t ts_sec;

	/**
	 * Timestamp microseconds
	 */
	u32_t ts_usec;

	/**
	 * Number of octets of the saved packet
	 */
	u32_t capture_len;

	/**
	 * Actual length of the packet
	 */
	u32_t pkt_len;

	/**
	 * Ordinal number of the packet (starts from 1)
	 */
	u32_t pkt_num;
} __packed;

/** ZPCAP context */
struct zrpcap_context {
	/**
	 * Network interface where capture is done
	 */
	struct net_if *iface;

	/**
	 * Is this context in use
	 */
	u8_t is_used : 1;
};
