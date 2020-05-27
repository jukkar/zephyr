/** @file
 * @brief Network user mode support initialization
 *
 * Initialize the network IP stack so that it can work in user mode. Default
 * is to run network stack in kernel mode. Create one thread for reading data
 * from application (TX) or from network device driver (RX).
 */

/*
 * Copyright (c) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(net_user_mode, CONFIG_NET_USER_MODE_LOG_LEVEL);

#include <kernel.h>
#include <net/net_user_mode.h>

#include "net_private.h"
#include "net_user_mode_private.h"

static struct k_mem_domain net_domain;
K_APPMEM_PARTITION_DEFINE(net_partition);

K_THREAD_STACK_DEFINE(net_user_mode_stack,
		      CONFIG_NET_USER_MODE_STACK_SIZE);
static struct k_thread net_user_mode_thread;

static K_MEM_POOL_DEFINE(net_user_mode_mem_pool, sizeof(uintptr_t),
			 CONFIG_NET_USER_MODE_MAX_DATA_SIZE,
			 CONFIG_NET_USER_MODE_MAX_TX_MSG +
			 CONFIG_NET_USER_MODE_MAX_RX_MSG,
			 sizeof(uintptr_t));

K_MSGQ_DEFINE(net_user_mode_tx_msgq, sizeof(struct net_user_mode),
	      CONFIG_NET_USER_MODE_MAX_TX_MSG, sizeof(uintptr_t));
K_MSGQ_DEFINE(net_user_mode_rx_msgq, sizeof(struct net_user_mode),
	      CONFIG_NET_USER_MODE_MAX_RX_MSG, sizeof(uintptr_t));

void net_mem_domain_add_thread(struct k_thread *thread)
{
	if (!thread->mem_domain_info.mem_domain) {
		k_mem_domain_add_thread(&net_domain, thread);
	}
}

void net_mem_domain_remove_thread(struct k_thread *thread)
{
	k_mem_domain_remove_thread(thread);
}

static void net_mem_domain_init(void)
{
	struct k_mem_partition *parts[] = {
#if IS_ENABLED(Z_LIBC_PARTITION_EXISTS)
                &z_libc_partition,
#endif
                &net_partition,
	};

	k_mem_domain_init(&net_domain, ARRAY_SIZE(parts), parts);
}

void net_access_grant_rx(struct k_thread *thread)
{
	const char *name = k_thread_name_get(thread);

	if (!name) {
		name = "?";
	}

	NET_DBG("Thread %s (%p) added to net_domain for %s",
		log_strdup(name), thread, "RX");

	net_mem_domain_add_thread(thread);

	NET_DBG("Adding %s access to %s (%p)", "net_pkt", log_strdup(name),
		thread);
	net_pkt_access_grant_rx(thread);

	NET_DBG("Adding %s access to %s (%p)", "net_tc", log_strdup(name),
		thread);
	net_tc_access_grant_rx(thread);

	NET_DBG("Adding %s access to %s (%p)", "net_if", log_strdup(name),
		thread);
	net_if_access_grant_rx(thread);

	NET_DBG("Adding %s access to %s (%p)", "net_context", log_strdup(name),
		thread);
	net_context_access_grant(thread);

	NET_DBG("Adding %s access to %s (%p)", "net_ipv6", log_strdup(name),
		thread);
	net_ipv6_access_grant(thread);
}

void net_access_grant_tx(struct k_thread *thread)
{
	const char *name = k_thread_name_get(thread);

	if (!name) {
		name = "?";
	}

	NET_DBG("Thread %s (%p) added to net_domain for %s",
		log_strdup(name), thread, "TX");

	net_mem_domain_add_thread(thread);

	NET_DBG("Adding %s access to %s (%p)", "net_pkt", log_strdup(name),
		thread);
	net_pkt_access_grant_tx(thread);

	NET_DBG("Adding %s access to %s (%p)", "net_tc", log_strdup(name),
		thread);
	net_tc_access_grant_tx(thread);

	NET_DBG("Adding %s access to %s (%p)", "net_if", log_strdup(name),
		thread);
	net_if_access_grant_tx(thread);

	NET_DBG("Adding %s access to %s (%p)", "net_context", log_strdup(name),
		thread);
	net_context_access_grant(thread);

	NET_DBG("Adding %s access to %s (%p)", "net_ipv6", log_strdup(name),
		thread);
	net_ipv6_access_grant(thread);
}

void net_access_grant_app(struct k_thread *thread)
{
	net_mem_domain_add_thread(thread);

	net_pkt_access_grant_tx(thread);
	net_tc_access_grant_tx(thread);
	net_if_access_grant_tx(thread);
	net_context_access_grant(thread);
}

static void net_user_mode_handler(void)
{
	net_init_rest();
}

int net_user_mode_init(void)
{
	net_mem_domain_init();

	net_if_device_init();

	(void)k_thread_create(&net_user_mode_thread,
			      net_user_mode_stack,
			      K_THREAD_STACK_SIZEOF(net_user_mode_stack),
			      (k_thread_entry_t)net_user_mode_handler,
			      NULL, NULL, NULL,
			      K_PRIO_COOP(CONFIG_NET_USER_MODE_PRIO),
			      K_USER, K_FOREVER);

	k_thread_name_set(&net_user_mode_thread, "net_user_mode");
	k_thread_resource_pool_assign(&net_user_mode_thread,
				      &net_user_mode_mem_pool);
	net_access_grant_tx(&net_user_mode_thread);
	net_access_grant_rx(&net_user_mode_thread);

	k_thread_start(&net_user_mode_thread);

	return 0;
}
