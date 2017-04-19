/* echo-loopback.c - Networking echo client/server combined */

/*
 * Copyright (c) 2016 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if 1
#define SYS_LOG_DOMAIN "echo-lo"
#define NET_SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define NET_LOG_ENABLED 1
#endif

#include <zephyr.h>
#include <sections.h>
#include <errno.h>
#include <stdio.h>

#include <net/net_if.h>
#include <net/net_core.h>
#include <net/net_context.h>
#include <net/net_mgmt.h>

void server_startup(void);
void client_startup(void);

#define STARTUP_STACKSIZE 700

NET_STACK_DEFINE(STARTUP, startup_stack, STARTUP_STACKSIZE,
		 STARTUP_STACKSIZE);

#if defined(CONFIG_NET_MGMT_EVENT)
static struct net_mgmt_event_callback cb;
#endif

void panic(const char *msg)
{
	NET_ERR("Panic: %s", msg);
	for (;;) {
		k_sleep(K_FOREVER);
	}
}

void startup(void)
{
	NET_INFO("Run echo loopback");

	server_startup();
	client_startup();

	k_sleep(K_FOREVER);
}

static void event_iface_up(struct net_mgmt_event_callback *cb,
			   uint32_t mgmt_event, struct net_if *iface)
{
	k_thread_spawn(startup_stack, STARTUP_STACKSIZE,
		       (k_thread_entry_t)startup,
		       NULL, NULL, NULL, K_PRIO_COOP(7), 0, 0);
}

void main(void)
{
	struct net_if *iface = net_if_get_default();

#if defined(CONFIG_NET_MGMT_EVENT)
	/* Subscribe to NET_IF_UP if interface is not ready */
	if (!atomic_test_bit(iface->flags, NET_IF_UP)) {
		net_mgmt_init_event_callback(&cb, event_iface_up,
					     NET_EVENT_IF_UP);
		net_mgmt_add_event_callback(&cb);
		return;
	}
#endif

	event_iface_up(NULL, NET_EVENT_IF_UP, iface);
}
