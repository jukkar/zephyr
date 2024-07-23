/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* Authentication algorithm is chacha20pol1305 which is 128bit (16 byte) long */
#define WG_AUTHTAG_LEN 16U

/* Hash algorithm is blake2s which creates 32 byte long hashes */
#define WG_HASH_LEN 32U

/* Public key algorithm is curve22519 which uses 32 byte long keys */
#define WG_PUBLIC_KEY_LEN 32U

/* Public key algo is curve22519 which uses 32 byte keys */
#define WG_PRIVATE_KEY_LEN 32U

/* Symmetric session keys are chacha20/poly1305 which uses 32 byte long keys */
#define WG_SESSION_KEY_LEN 32U

#define WG_COOKIE_LEN 16U
#define WG_COOKIE_NONCE_LEN 24U

#define MESSAGE_INVALID               0
#define MESSAGE_HANDSHAKE_INITIATION  1
#define MESSAGE_HANDSHAKE_RESPONSE    2
#define MESSAGE_COOKIE_REPLY          3
#define MESSAGE_TRANSPORT_DATA        4

#define WIREGUARD_CTRL_DEVICE "WIREGUARD_CTRL"

#define WG_MTU 1420U

/* 5.4.2 First Message: Initiator to Responder */
struct message_handshake_initiation {
	uint8_t type;
	uint8_t reserved[3];
	uint32_t sender;
	uint8_t ephemeral[32];
	uint8_t enc_static[32 + WG_AUTHTAG_LEN];
	uint8_t enc_timestamp[WG_TIMESTAMP_LEN + WG_AUTHTAG_LEN];
	uint8_t mac1[WG_COOKIE_LEN];
	uint8_t mac2[WG_COOKIE_LEN];
} __packed;

/* 5.4.3 Second Message: Responder to Initiator */
struct message_handshake_response {
	uint8_t type;
	uint8_t reserved[3];
	uint32_t sender;
	uint32_t receiver;
	uint8_t ephemeral[32];
	uint8_t enc_empty[WG_AUTHTAG_LEN];
	uint8_t mac1[WG_COOKIE_LEN];
	uint8_t mac2[WG_COOKIE_LEN];
} __packed;

/* 5.4.7 Under Load: Cookie Reply Message */
struct message_cookie_reply {
	uint8_t type;
	uint8_t reserved[3];
	uint32_t receiver;
	uint8_t nonce[WG_COOKIE_NONCE_LEN];
	uint8_t enc_cookie[WG_COOKIE_LEN + WG_AUTHTAG_LEN];
} __packed;

/* 5.4.6 Subsequent Messages: Transport Data Messages */
struct message_transport_data {
	uint8_t type;
	uint8_t reserved[3];
	uint32_t receiver;
	uint8_t counter[8];
	uint8_t enc_packet[]; /* Encrypted data follows */
} __packed;


struct wg_peer {
	sys_snode_t node;
	uint8_t public_key[WG_PUBLIC_KEY_LEN];
	struct net_if *iface;
	struct sockaddr allowed_ips;
	uint8_t mask_len;
	int id;
};

typedef void (*wg_peer_cb_t)(struct wg_peer *peer, void *user_data);

void wireguard_peer_foreach(wg_peer_cb_t cb, void *user_data);
