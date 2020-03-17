/*
 * Copyright (c) 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <kernel.h>
#include <drivers/uart.h>
#include <ztest.h>

#define UART_DEVICE_NAME_0 CONFIG_UART_MUX_DEVICE_NAME "_0"

#define UART_MUX_DEVICE_NAME_0 CONFIG_UART_MUX_DEVICE_NAME "_0"
#define UART_MUX_DEVICE_NAME_1 CONFIG_UART_MUX_DEVICE_NAME "_1"
#define UART_MUX_DEVICE_NAME_NOT_FOUND CONFIG_UART_MUX_DEVICE_NAME "_2"

static struct device *uart_mux_dev_0;
static struct device *uart_mux_dev_1;
static struct device *uart_mux_dev_not_found;

static const u8_t TEST_BUF[] = {
	'T', 'e', 's', 't', ' ', 'b', 'u', 'f', '\0'
};

void set_permissions(void)
{
#if 0
	struct device *uart_mux_0 =
		device_get_binding(UART_MUX_DEVICE_NAME_0);
	struct device *uart_mux_1 =
		device_get_binding(UART_MUX_DEVICE_NAME_1);

	k_thread_access_grant(k_current_get(), &tx_done, &tx_aborted,
			      &rx_rdy, &rx_buf_released, &rx_disabled,
			      uart_mux_0, uart_mux_1);
#endif
}

/* The system receives muxed data from this UART */
static void test_uart_setup(void)
{
	uart_mux_dev_0 = device_get_binding(UART_MUX_DEVICE_NAME_0);
	uart_mux_dev_1 = device_get_binding(UART_MUX_DEVICE_NAME_1);
	uart_mux_dev_not_found =
		device_get_binding(UART_MUX_DEVICE_NAME_NOT_FOUND);

	zassert_not_null(uart_mux_dev_0, "Dev %s not found",
			 UART_MUX_DEVICE_NAME_0);

	zassert_not_null(uart_mux_dev_1, "Dev %s not found",
			 UART_MUX_DEVICE_NAME_1);

	zassert_is_null(uart_mux_dev_not_found, "Dev %s was found",
			UART_MUX_DEVICE_NAME_NOT_FOUND);

}

/* User writes data into these UARTs setup here */
static void test_uart_mux_setup(void)
{
	uart_mux_dev_0 = device_get_binding(UART_MUX_DEVICE_NAME_0);
	uart_mux_dev_1 = device_get_binding(UART_MUX_DEVICE_NAME_1);
	uart_mux_dev_not_found =
		device_get_binding(UART_MUX_DEVICE_NAME_NOT_FOUND);

	zassert_not_null(uart_mux_dev_0, "Dev %s not found",
			 UART_MUX_DEVICE_NAME_0);

	zassert_not_null(uart_mux_dev_1, "Dev %s not found",
			 UART_MUX_DEVICE_NAME_1);

	zassert_is_null(uart_mux_dev_not_found, "Dev %s was found",
			UART_MUX_DEVICE_NAME_NOT_FOUND);

}

static void test_uart_mux_write(void)
{
	const u8_t *buf = TEST_BUF;
	size_t buf_len = sizeof(TEST_BUF);

	do {
		uart_poll_out(uart_mux_dev_0, *buf++);
	} while (--buf_len);
}

static void test_uart_mux_read(void)
{

}

void test_main(void)
{
	if (IS_ENABLED(CONFIG_USERSPACE)) {
		set_permissions();
	}

	ztest_test_suite(uart_mux_test,
			 ztest_unit_test(test_uart_setup),
			 ztest_unit_test(test_uart_mux_setup),
			 ztest_unit_test(test_uart_mux_write),
			 ztest_unit_test(test_uart_mux_read)
		);
	ztest_run_test_suite(uart_mux_test);
}
