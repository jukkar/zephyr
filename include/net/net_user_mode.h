/** @file
 *  @brief User mode networking support
 */

/*
 * Copyright (c) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef __NET_USER_MODE_H
#define __NET_USER_MODE_H

#include <stddef.h>
#include <zephyr/types.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(CONFIG_NET_USER_MODE)
#include <app_memory/app_memdomain.h>

extern struct k_mem_partition net_partition;

#define Z_NET_PARTITION_EXISTS 1

#define NET_BMEM K_APP_BMEM(net_partition)
#define NET_DMEM K_APP_DMEM(net_partition)

#define NET_THREAD_FLAGS K_USER

#else /* CONFIG_NET_USER_MODE */

#define NET_THREAD_FLAGS 0

#define NET_BMEM
#define NET_DMEM

#endif /* CONFIG_NET_USER_MODE */

/**
 * @brief Add a thread to network memory domain
 *
 * @details Mark a thread to be able to access networking memory. This
 * is used in user mode only.
 *
 * @param thread Pointer to the thread
 */
#if defined(CONFIG_NET_USER_MODE)
void net_mem_domain_add_thread(struct k_thread *thread);
#else
static inline void net_mem_domain_add_thread(struct k_thread *thread)
{
	ARG_UNUSED(thread);
}
#endif

/**
 * @brief Remove a thread from network memory domain.
 *
 * @param thread ID of thread going to be removed from network memory domain.
 */
#if defined(CONFIG_NET_USER_MODE)
void net_mem_domain_remove_thread(struct k_thread *thread);
#else
static inline void net_mem_domain_remove_thread(struct k_thread *thread)
{
	ARG_UNUSED(thread);
}
#endif

/**
 * @brief Grant application access to networking domain.
 *
 * @param thread ID of thread granting the access.
 */
#if defined(CONFIG_NET_USER_MODE)
void net_access_grant_app(struct k_thread *thread);
#else
static inline void net_access_grant_app(struct k_thread *thread)
{
	ARG_UNUSED(thread);
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* __NET_USER_MODE_H */
