# SPDX-License-Identifier: Apache-2.0

zephyr_include_directories(.)

zephyr_library()
zephyr_library_sources_ifdef(CONFIG_NET_RPCAP rpcap.c)
zephyr_library_sources_ifdef(CONFIG_NET_RPCAPD rpcapd.c)
zephyr_library_include_directories(${ZEPHYR_BASE}/subsys/net/ip)
