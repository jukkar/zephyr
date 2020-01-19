/*
 * Copyright (c) 2020 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#ifndef ZEPHYR_INCLUDE_NET_RPCAP_H_
#define ZEPHYR_INCLUDE_NET_RPCAP_H_

#include <net/net_if.h>
#include <net/net_pkt.h>

/**
 * @brief RPCAP (remote packet capture) support functions
 * @defgroup rpcap RPCAP support functions
 * @ingroup networking
 * @{
 */

/**
 * Note that this library is only meant for debugging purposes so it does
 * not provide all the features that libpcap library is providing.
 */

#ifdef __cplusplus
extern "C" {
#endif

struct zrpcap_context;

/**
 * Direction of the packet from our point of view
 */
enum zrpcap_direction {
	ZRPCAP_D_INOUT = 0,  /* unknown or not applicable direction */
	ZRPCAP_D_IN,         /* receive (RX)  */
	ZRPCAP_D_OUT         /* transmit (TX) */
};

/*
 * Linktypes of the captured packet. Note that below is just a subset
 * of all available link types. Caveat emptor; if there is a value here,
 * it does not necessarily mean that Zephyr is able to capture such a
 * packet. The device driver needs to have support for these for both
 * TX and RX.
 */

#define ZPCAP_LINKTYPE_NULL           0
#define ZPCAP_LINKTYPE_ETHERNET       1
#define ZPCAP_LINKTYPE_SLIP           8

/*
 * PPP, as per RFC 1661 and RFC 1662. If the first 2 bytes are 0xff and 0x03,
 * then it is PPP in HDLC-like framing, with the PPP header following those
 * two bytes. Otherwise it's PPP without framing, and the packet begins with
 * the PPP header.
 */
#define ZPCAP_LINKTYPE_PPP            9

/*
 * PPP in HDLC-like framing, as per RFC 1662. The first byte will be 0xFF
 * for PPP in HDLC-like framing.
 */
#define ZPCAP_LINKTYPE_PPP_HDLC       50

/*
 * The packet begins with an IPv4 or IPv6 header, with the "version" field of
 * the header indicating whether it's an IPv4 or IPv6 header.
 */
#define ZPCAP_LINKTYPE_RAW            101

/*
 * IEEE 802.11 wireless LAN.
 */
#define ZPCAP_LINKTYPE_IEEE802_11     105

/*
 * Linux "cooked" capture encapsulation.
 */
#define ZPCAP_LINKTYPE_LINUX_SLL      113

/*
 * Reserved for private use.  If you have some link-layer header type
 * that you want to use within your organization, with the capture files
 * using that link-layer header type not ever be sent outside your
 * organization, you can use these values.
 *
 * Do *NOT* use these in capture files that you expect anybody not using
 * your private versions of capture-file-reading tools to read; in
 * particular, do *NOT* use them in products.
 */
#define ZPCAP_LINKTYPE_USER0          147
#define ZPCAP_LINKTYPE_USER1          148
#define ZPCAP_LINKTYPE_USER2          149
#define ZPCAP_LINKTYPE_USER3          150
#define ZPCAP_LINKTYPE_USER4          151
#define ZPCAP_LINKTYPE_USER5          152
#define ZPCAP_LINKTYPE_USER6          153
#define ZPCAP_LINKTYPE_USER7          154
#define ZPCAP_LINKTYPE_USER8          155
#define ZPCAP_LINKTYPE_USER9          156
#define ZPCAP_LINKTYPE_USER10         157
#define ZPCAP_LINKTYPE_USER11         158
#define ZPCAP_LINKTYPE_USER12         159
#define ZPCAP_LINKTYPE_USER13         160
#define ZPCAP_LINKTYPE_USER14         161
#define ZPCAP_LINKTYPE_USER15         162

/*
 * Bluetooth HCI UART transport layer. The frame contains an HCI packet
 * indicator byte followed by an HCI packet of the specified packet type.
 */
#define ZPCAP_LINKTYPE_BLUETOOTH_HCI_H4       187

/*
 * IEEE 802.15.4, with address fields padded, as is done by Linux drivers
 */
#define ZPCAP_LINKTYPE_IEEE802_15_4_LINUX     191

/*
 * IEEE 802.15.4, exactly as it appears in the spec (no padding),
 * and with the FCS at the end of the frame.
 *
 * This should only be used if the FCS is present at the end of the
 * frame; if the frame has no FCS, LINKTYPE_IEEE802_15_4_NOFCS should be
 * used instead.
 */
#define ZPCAP_LINKTYPE_IEEE802_15_4_WITHFCS   195

/*
 * The frame contains a 4-byte direction field, in network byte order,
 * the low-order bit of which is set if the frame was sent from the host
 * to the controller and clear if the frame was received by the host from
 * the controller, followed by an HCI packet indicator byte, followed by an
 * HCI packet of the specified packet type.
 */
#define ZPCAP_LINKTYPE_BLUETOOTH_HCI_H4_WITH_PHDR   201

/*
 * PPP, as per RFC 1661 and RFC 1662, preceded with a one-byte pseudo-header
 * with a zero value meaning "received by this host" and a non-zero value
 * meaning "sent by this host". If the first 2 bytes are 0xff and 0x03, then
 * it is PPP in HDLC-like framing, with the PPP header following those two
 * bytes, otherwise it is PPP without framing, and the packet begins with
 * the PPP header.
 */
#define ZPCAP_LINKTYPE_PPP_WITH_DIR    204

/*
 * CAN (Controller Area Network) frames, with a pseudo-header followed by the
 * frame payload.
 */
#define ZPCAP_LINKTYPE_CAN_SOCKETCAN   227

/*
 * The packet begins with an IPv4 header.
 */
#define ZPCAP_LINKTYPE_IPV4            228

/*
 * The packet begins with an IPv6 header.
 */
#define ZPCAP_LINKTYPE_IPV6            229

/*
 * IEEE 802.15.4 without the FCS at the end of the frame.
 */
#define ZPCAP_LINKTYPE_IEEE802_15_4_NOFCS  230

/*
 * USB packets, beginning with a USBPcap header.
 */
#define ZPCAP_LINKTYPE_USBPCAP         249

/*
 * Bluetooth Low Energy air interface Link Layer packets, in the format
 * described in section 2.1 "PACKET FORMAT" of volume 6 of the Bluetooth
 * Specification Version 4.0 (see PDF page 2200), but without the Preamble.
 */
#define ZPCAP_LINKTYPE_BLUETOOTH_LE_LL 251

/*
 * Bluetooth Low Energy link-layer packets.
 */
#define ZPCAP_LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR  256

/*
 * USB 2.0, 1.1, or 1.0 packet, beginning with a PID, as described by
 * Chapter 8 "Protocol Layer" of the the Universal Serial Bus Specification
 * Revision 2.0.
 */
#define ZPCAP_LINKTYPE_USB_2_0         288

/**
 * Start capturing packets.
 *
 * @param iface Network interface where to start capturing packets.
 * @param ctx Packet capture context, this is returned to the caller.
 *
 * @return 0 if capturing was started, <0 if the capture cannot start
 */
#if defined(CONFIG_NET_RPCAP)
int zrpcap_start(struct net_if *iface, int *ctx);
#else
static inline int zrpcap_start(struct net_if *iface, int *ctx)
{
	ARG_UNUSED(iface);
	ARG_UNUSED(ctx);

	return -ENOTSUP;
}
#endif

/**
 * Stop capturing packets.
 *
 * @param ctx Packet capture context
 *
 * @return 0 if capturing was stopped, <0 if the capture cannot be stopped
 *         or is not supported
 */
#if defined(CONFIG_NET_RPCAP)
int zrpcap_stop(int ctx);
#else
static inline int zrpcap_stop(int ctx)
{
	ARG_UNUSED(ctx);

	return -ENOTSUP;
}
#endif


/**
 * Capture a packet.
 *
 * @param ctx Packet capture context
 * @param pkt Network packet to capture
 * @param direction Is this RX or TX packet
 * @param linktype Type of the captured data
 *
 * @return 0 if the packet was captured properly, <0 if there was an error
 */
#if defined(CONFIG_NET_RPCAP)
int zrpcap_capture_packet(int ctx,
			  struct net_pkt *pkt,
			  enum zrpcap_direction direction,
			  u32_t linktype);
#else
int zrpcap_capture_packet(int ctx,
			  struct net_pkt *pkt,
			  enum zrpcap_direction direction,
			  u32_t linktype)
{
	ARG_UNUSED(ctx);
	ARG_UNUSED(pkt);
	ARG_UNUSED(direction);
	ARG_UNUSED(linktype);

	return -ENOTSUP;
}
#endif

/** @cond INTERNAL_HIDDEN */
#if defined(CONFIG_NET_RPCAP)
void zrpcap_init(void);
#else
#define zrpcap_init()
#endif
/** @endcond */

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_NET_RPCAP_H_ */
