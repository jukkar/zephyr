/*
 * Copyright (c) 2020 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */


#ifndef ZEPHYR_INCLUDE_NET_RPCAPD_H_
#define ZEPHYR_INCLUDE_NET_RPCAPD_H_

#include <net/rpcap.h>

/**
 * @brief RPCAPD (remote packet capture daemon) support functions
 * @defgroup rpcapd RPCAP daemon support functions
 * @ingroup networking
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize rcap daemon
 *
 * @details For passive connections, this will cause listening sockets
 *          to be created. For active connections, the daemon will
 *          connect to peer to get commands.
 */
#if defined(CONFIG_NET_RPCAPD)
void zrpcapd_init(void);
#else
#define zrpcapd_init()
#endif

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_NET_RPCAPD_H_ */
