/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(wifi_supplicant);

#include "events.h"

int supplicant_send_wifi_mgmt_event(const char *ifname, enum net_event_wifi_cmd event, int status)
{
	struct net_if *iface;

	iface = net_if_lookup_by_name(ifname);
	if (!iface) {
		LOG_ERR("Could not find iface for %s", ifname);
		return -ENODEV;
	}

	switch (event) {
	case NET_EVENT_WIFI_CMD_CONNECT_RESULT:
		wifi_mgmt_raise_connect_result_event(iface, status);
		break;
	case NET_EVENT_WIFI_CMD_DISCONNECT_RESULT:
		wifi_mgmt_raise_disconnect_result_event(iface, status);
		break;
	default:
		LOG_ERR("Unsupported event %d", event);
		return -EINVAL;
	}

	return 0;
}

int supplicant_generate_state_event(struct net_if *iface, enum net_event_supplicant_cmd event, int status)
{
	switch (event) {
	case NET_EVENT_SUPPLICANT_CMD_READY:
		net_mgmt_event_notify(NET_EVENT_SUPPLICANT_READY, iface);
		break;
	case NET_EVENT_SUPPLICANT_CMD_NOT_READY:
		net_mgmt_event_notify(NET_EVENT_SUPPLICANT_NOT_READY, iface);
		break;
	case NET_EVENT_SUPPLICANT_CMD_IFACE_ADDED:
		net_mgmt_event_notify(NET_EVENT_SUPPLICANT_IFACE_ADDED, iface);
		break;
	case NET_EVENT_SUPPLICANT_CMD_IFACE_REMOVING:
		net_mgmt_event_notify(NET_EVENT_SUPPLICANT_IFACE_REMOVING, iface);
		break;
	case NET_EVENT_SUPPLICANT_CMD_IFACE_REMOVED:
		net_mgmt_event_notify_with_info(NET_EVENT_SUPPLICANT_IFACE_REMOVED,
						iface, INT_TO_POINTER(status), sizeof(status));
		break;
	default:
		LOG_ERR("Unsupported event %d", event);
		return -EINVAL;
	}

	return 0;
}
