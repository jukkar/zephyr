/*
 * Copyright (c) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Public APIs for UART MUX drivers
 */

#ifndef ZEPHYR_INCLUDE_DRIVERS_UART_MUX_H_
#define ZEPHYR_INCLUDE_DRIVERS_UART_MUX_H_

/**
 * @brief UART Mux Interface
 * @defgroup uart_mux_interface UART Mux Interface
 * @ingroup io_interfaces
 * @{
 */

#include <device.h>
#include <drivers/uart.h>

#ifdef __cplusplus
extern "C" {
#endif

struct gsm_dlci;

/**
 * @typedef uart_mux_attach_cb_t
 * @brief Define the user callback function which is called when
 * the UART mux is attached properly.
 *
 * @param mux UART mux device
 * @param connected True if DLCI is connected, false otherwise.
 * @param user_data Arbitrary user data.
 */
typedef void (*uart_mux_attach_cb_t)(struct device *mux, int dlci_address,
				     bool connected, void *user_data);

/** @brief UART mux driver API structure. */
__subsystem struct uart_mux_driver_api {
	/**
	 * The uart_driver_api must be placed in first position in this
	 * struct so that we are compatible with uart API. Note that currently
	 * not all of the UART API functions are implemented.
	 */
	struct uart_driver_api uart_api;

	/* Configure the GSM 07.10 MUX via these functions */

	/**
	 * Configure mux driver. If configuration needs to be set, then this
	 * function must be called before attach()
	 */
	//void (*config)(struct device *mux, const struct uart_mux_config *cfg);

	/**
	 * Attach the mux to this UART. The API will call the callback after
	 * the DLCI is created or not.
	 */
	int (*attach)(struct device *mux, struct device *uart,
		      int dlci_address, uart_mux_attach_cb_t cb,
		      void *user_data);
};

/**
 * @brief Attach physical/real UART to UART muxing device.
 *
 * @param mux UART mux device structure.
 * @param uart Real UART device structure.
 * @param dlci_address DLCI id for the virtual muxing channel
 * @param timeout Amount of time to wait for the channel creation.
 *
 * @retval 0 No errors, the attachment was successful
 * @retval <0 Error
 */
static inline int uart_mux_attach(struct device *mux, struct device *uart,
				  int dlci_address, uart_mux_attach_cb_t cb,
				  void *user_data)
{
	const struct uart_mux_driver_api *api =
		(const struct uart_mux_driver_api *)mux->driver_api;

	return api->attach(mux, uart, dlci_address, cb, user_data);
}

/**
 * @brief Get UART related to a specific DLCI channel
 *
 * @param dlci_address DLCI address, value >0 and <63
 *
 * @return UART device if found, NULL otherwise
 */
__syscall struct device *uart_mux_find(int dlci_address);

/**
 * @brief Allocate muxing UART device.
 *
 * @detail This will return next available uart mux driver that will mux the
 *         data when read or written. This device corresponds to one DLCI
 *         channel. User must call this to allocate the DLCI and the attach
 *         call to succeed.
 *
 * @retval device New UART device that will automatically mux data sent
 *         to it.
 * @retval NULL if error
 */
struct device *uart_mux_alloc(void);

#ifdef __cplusplus
}
#endif

#include <syscalls/uart_mux.h>

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_DRIVERS_UART_MUX_H_ */
