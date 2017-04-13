/*
 * Copyright (c) 2017 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(CONFIG_NET_DEBUG_SERVICE)
#define SYS_LOG_DOMAIN "net/svc"
#define NET_LOG_ENABLED 1
#endif

#include <init.h>
#include <kernel.h>
#include <sections.h>
#include <string.h>
#include <net/net_core.h>
#include <net/nbuf.h>
#include <net/net_if.h>
#include <net/net_mgmt.h>

#include "net_private.h"
#include "ipv6.h"

/** Network interface management monitor */
static struct net_mgmt_event_callback mgmt;

/** Current state of the service */
enum net_service_state system_service_state = NET_SERVICE_STATE_IDLE;

const char *net_service_state2str(enum net_service_state state)
{
	switch (state) {
	case NET_SERVICE_STATE_IDLE:
		return "IDLE";
	case NET_SERVICE_STATE_CONNECTING:
		return "CONNECTING";
	case NET_SERVICE_STATE_CONNECTED:
		return "CONNECTED";
	case NET_SERVICE_STATE_DISCONNECTING:
		return "DISCONNECTING";
	}

	return "<invalid state>";
}

#if defined(CONFIG_NET_DEBUG_SERVICE)

#define I(state) NET_SERVICE_STATE_##state & NET_EVENT_SERVICE_CMD_##state
#define S(state) \
	(1 << (NET_SERVICE_STATE_##state & NET_EVENT_SERVICE_CMD_##state))

static void validate_state_transition(enum net_service_state current,
				      enum net_service_state new)
{
	static const uint16_t valid_transitions[] = {
		[I(IDLE)] = S(CONNECTING),
		[I(CONNECTING)] = S(CONNECTED) | S(IDLE),
		[I(CONNECTED)] = S(DISCONNECTING),
		[I(DISCONNECTING)] = S(IDLE),
	};

	if (!(valid_transitions[current & ~_NET_EVENT_SERVICE_BASE] & 1 <<
	      (new & ~_NET_EVENT_SERVICE_BASE))) {
		NET_DBG("Invalid state transition %s => %s",
			net_service_state2str(current),
			net_service_state2str(new));
	}
}

static void check_state_change(struct net_service *service,
			       enum net_service_state old_state,
			       enum net_service_state new_state)
{
	NET_DBG("service %p %s (%ld) => %s (%ld)", service,
		net_service_state2str(old_state),
		old_state & ~_NET_EVENT_SERVICE_BASE,
		net_service_state2str(new_state),
		new_state & ~_NET_EVENT_SERVICE_BASE);

#if defined(CONFIG_NET_DEBUG_SERVICE)
	validate_state_transition(old_state, new_state);
#endif
}

#else
#define check_state_change(...)
#endif /* CONFIG_NET_DEBUG_SERVICE */

void net_service_change_state(struct net_service *service,
			      enum net_service_state new_state)
{
	if (service) {
		if (service->state == new_state) {
			return;
		}

		check_state_change(service, service->state, new_state);

		net_mgmt_event_notify(new_state, service->entity);
	}

	if (system_service_state == new_state) {
		return;
	}

	check_state_change(NULL, system_service_state, new_state);

	/* TODO: We would need to track the states here and change
	 * the global state only when needed.
	 */

	net_mgmt_event_notify(new_state, NULL);
	system_service_state = new_state;
}

#if defined(CONFIG_NET_IPV4)
static void ipv4_addr_add_handler(struct net_mgmt_event_callback *cb,
				  uint32_t mgmt_event,
				  struct net_if *iface)
{
	int i;

	for (i = 0; i < NET_IF_MAX_IPV4_ADDR; i++) {
		struct net_if_addr *addr;

		addr = &iface->ipv4.unicast[i];
		if (addr->is_used &&
		    addr->address.family == AF_INET) {
			net_service_change_state(&iface->service,
						 NET_SERVICE_STATE_CONNECTED);
			break;
		}
	}
}
#endif /* CONFIG_NET_IPV4 */

#if defined(CONFIG_NET_IPV6_DAD)
static void ipv6_dad_ok_handler(struct net_mgmt_event_callback *cb,
				uint32_t mgmt_event,
				struct net_if *iface)
{
	int i;

	for (i = 0; i < NET_IF_MAX_IPV6_ADDR; i++) {
		struct net_if_addr *addr;

		addr = &iface->ipv6.unicast[i];
		if (addr->is_used &&
		    addr->addr_state == NET_ADDR_PREFERRED &&
		    addr->address.family == AF_INET6) {
			net_service_change_state(&iface->service,
						 NET_SERVICE_STATE_CONNECTED);
			break;
		}
	}
}
#endif /* CONFIG_NET_IPV6*/

static void service_handler(struct net_mgmt_event_callback *cb,
			    uint32_t mgmt_event,
			    struct net_if *iface)
{
#if defined(CONFIG_NET_IPV4)
	if (mgmt_event == NET_EVENT_IPV4_ADDR_ADD) {
		ipv4_addr_add_handler(cb, mgmt_event, iface);
		return;
	}
#endif

#if defined(CONFIG_NET_IPV6_DAD)
	if (mgmt_event == NET_EVENT_IPV6_DAD_SUCCEED) {
		ipv6_dad_ok_handler(cb, mgmt_event, iface);
		return;
	}
#endif
}

void net_service_init(void)
{
	uint32_t event = 0;

#if defined(CONFIG_NET_IPV4)
	event |= NET_EVENT_IPV4_ADDR_ADD;
#endif

#if defined(CONFIG_NET_IPV6_DAD)
	event |= NET_EVENT_IPV6_DAD_SUCCEED;
#endif

	if (event) {
		net_mgmt_init_event_callback(&mgmt,
					     service_handler,
					     event);

		net_mgmt_add_event_callback(&mgmt);
	}

	net_service_change_state(NULL, NET_EVENT_SERVICE_IDLE);
}
