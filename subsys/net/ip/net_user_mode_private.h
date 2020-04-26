/** @file
 *  @brief User mode networking support
 */

/*
 * Copyright (c) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __NET_USER_MODE_PRIVATE_H
#define __NET_USER_MODE_PRIVATE_H

#include <stddef.h>
#include <zephyr/types.h>
#include <stdbool.h>

#include <net/net_user_mode.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Structs and defines when network stack is running in user mode */
struct net_user_mode {
	union {
		struct {
			int family;
			int type;
			int proto;
		} call_socket;

		struct {
			int sock;
		} call_close;

		struct {
			int sock;
			int how;
		} call_shutdown;
	};
};

#if defined(CONFIG_NET_USER_MODE)
int net_user_mode_init(void);
void net_access_grant_rx(struct k_thread *thread);
void net_access_grant_tx(struct k_thread *thread);
void net_tc_access_grant_tx(struct k_thread *thread);
void net_tc_access_grant_rx(struct k_thread *thread);
void net_pkt_access_grant_tx(struct k_thread *thread);
void net_pkt_access_grant_rx(struct k_thread *thread);
void net_if_access_grant_tx(struct k_thread *thread);
void net_if_access_grant_rx(struct k_thread *thread);
#else
static inline int net_user_mode_init(void)
{
	return 0;
}

static inline void net_access_grant_rx(struct k_thread *thread)
{
	ARG_UNUSED(thread);
}

static inline void net_access_grant_tx(struct k_thread *thread)
{
	ARG_UNUSED(thread);
}

static inline void net_tc_access_grant_tx(struct k_thread *thread)
{
	ARG_UNUSED(thread);
}

static inline void net_tc_access_grant_rx(struct k_thread *thread)
{
	ARG_UNUSED(thread);
}

static inline void net_pkt_access_grant_tx(struct k_thread *thread)
{
	ARG_UNUSED(thread);
}

static inline void net_pkt_access_grant_rx(struct k_thread *thread)
{
	ARG_UNUSED(thread);
}

static inline void net_if_access_grant_tx(struct k_thread *thread)
{
	ARG_UNUSED(thread);
}

static inline void net_if_access_grant_rx(struct k_thread *thread)
{
	ARG_UNUSED(thread);
}
#endif /* CONFIG_NET_USER_MODE */

#ifdef __cplusplus
}
#endif

#endif /* __NET_USER_MODE_PRIVATE_H */
