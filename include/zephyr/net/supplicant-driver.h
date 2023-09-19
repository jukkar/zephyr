/*
 * Copyright (c) 2023 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(CONFIG_WIFI_SUPPLICANT_HOSTAP)
#include <drivers/driver.h>
#else
struct wpa_driver_ops {
};
#endif

