/*
 * Copyright (c) 2020, Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(rpcapd, LOG_LEVEL_DBG);

#include <zephyr.h>
#include <net/rpcapd.h>

int main(void)
{
	LOG_INF("Starting rpcap daemon");

	zrpcapd_init();

	return 0;
}
