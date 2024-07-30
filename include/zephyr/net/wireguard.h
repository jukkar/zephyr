/**
 * @file
 * @brief Wireguard VPN
 *
 */

/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_NET_WG_H_
#define ZEPHYR_INCLUDE_NET_WG_H_

/**
 * @brief Wireguard VPN service
 * @defgroup wg_vpn_service Wireguard VPN service
 * @ingroup networking
 * @{
 */

#include <sys/types.h>
#include <zephyr/types.h>
#include <zephyr/net/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Default Wireguard VPN service port */
#if defined(CONFIG_WIREGUARD_SERVER)
#define WIREGUARD_DEFAULT_SERVICE_PORT CONFIG_WIREGUARD_SERVER_PORT
#else
#define WIREGUARD_DEFAULT_SERVICE_PORT 51820
#endif

#if defined(CONFIG_WIREGUARD)
#define WIREGUARD_INTERFACE CONFIG_WIREGUARD_INTERFACE
#else
#define WIREGUARD_INTERFACE ""
#endif

/** Timestamp length (64-bit seconds and 32-bit nanoseconds) */
#define WIREGUARD_TIMESTAMP_LEN (sizeof(uint64_t) + sizeof(uint32_t))

/**
 * @brief Wireguard peer configuration information.
 *
 * Stores the Wireguard VPN peer connection information.
 */
struct wireguard_peer_config {
	/** Public key in base64 format */
	const char *public_key;

	/** Optional pre-shared key (32 bytes), set to NULL if not to be used */
	const uint8_t *preshared_key;

	/** What is the largest timestamp we have seen during handshake in order
	 * to avoid replays.
	 */
	uint8_t timestamp[WIREGUARD_TIMESTAMP_LEN];

	/** Allowed IP address */
	struct sockaddr allowed_ip;
	/** Netmask (for IPv4) or Prefix (for IPv6) length */
	uint8_t mask_len;

	/** End-point address (when connecting) */
	struct sockaddr endpoint_ip;

	/** Default keep alive time for this peer */
	uint16_t keepalive;
};

/**
 * @brief Add a Wireguard peer to the system.
 *
 * @details If successfull, a virtual network interface is
 *          returned which can be used to communicate with the peer.
 *
 * @param peer_config Peer configuration data.
 * @param peer_iface A pointer to network interface is returned to the
 *        caller if adding the peer was successfull.
 *
 * @return >0 peer id on success, a negative errno otherwise.
 */
int wireguard_peer_add(struct wireguard_peer_config *peer_config,
		       struct net_if **peer_iface);

/**
 * @brief Remove a Wireguard peer from the system.
 *
 * @details If successfull, the virtual network interface is
 *          also removed and user is no longer be able to communicate
 *          with the peer.
 *
 * @param peer_id Peer id returned by wireguard_peer_add()
 *
 * @return 0 on success, a negative errno otherwise.
 */
int wireguard_peer_remove(int peer_id);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_NET_WG_H_ */
