/** @file
 @brief Network service monitor handler
 */

/*
 * Copyright (c) 2017 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef __NET_SERVICE_H
#define __NET_SERVICE_H

#include <stdint.h>
#include <net/net_mgmt.h>

/** Various states that the service can be in. */
enum net_service_state {
	NET_SERVICE_STATE_IDLE          = NET_EVENT_SERVICE_IDLE,
	NET_SERVICE_STATE_CONNECTING    = NET_EVENT_SERVICE_CONNECTING,
	NET_SERVICE_STATE_CONNECTED     = NET_EVENT_SERVICE_CONNECTED,
	NET_SERVICE_STATE_DISCONNECTING = NET_EVENT_SERVICE_DISCONNECTING,
};

/**
 * @brief Network service monitor.
 */
struct net_service {
	/**
	 * Entity that this change is related to, typically this is
	 * the network interface.
	 */
	void *entity;

	/**
	 * State of this entity.
	 */
	enum net_service_state state;
};

#if defined(CONFIG_NET_SERVICE_MONITOR)
/**
 * @brief Initialize service monitoring.
 */
void net_service_init(void);

/**
 * @brief Change the service state of the system.
 *
 * @param iface Network interface if this state change is related to it.
 * @param new_state New service state
 */
void net_service_change_state(struct net_service *entity,
			      enum net_service_state new_state);

#else /* CONFIG_NET_SERVICE_MONITOR */
#define net_service_init(...)
#define net_service_change_state(...)
#endif /* CONFIG_NET_SERVICE_MONITOR */

#endif /* __NET_SERVICE_H */
