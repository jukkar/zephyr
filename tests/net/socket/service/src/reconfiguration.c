/*
 * Copyright (c) 2026, Ylhyra ehf.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/net/socket.h>
#include <zephyr/net/socket_service.h>
#include <zephyr/sys/fdtable.h>
#include <zephyr/ztest.h>

/* Verify callback reconfiguration does not reuse stale poll state.
 * Keep readiness asserted so stale re-arming causes another observable poll.
 */
#define RECONFIG_TIMEOUT        K_MSEC(500)
#define RECONFIG_CLOSE_FD_COUNT 2

struct reconfig_mock_fd {
	struct k_sem readable;
	struct k_sem prepared;
	struct k_sem closed;
	struct k_sem wrong_events;
	short expected_events;
};

static void reconfig_mock_init(struct reconfig_mock_fd *mock)
{
	k_sem_init(&mock->readable, 0, 1);
	k_sem_init(&mock->prepared, 0, UINT_MAX);
	k_sem_init(&mock->closed, 0, 1);
	k_sem_init(&mock->wrong_events, 0, 1);
	mock->expected_events = -1;
}

static int reconfig_mock_close(void *obj)
{
	struct reconfig_mock_fd *mock = obj;

	k_sem_give(&mock->closed);

	return 0;
}

static int reconfig_mock_ioctl(void *obj, unsigned int request, va_list args)
{
	struct reconfig_mock_fd *mock = obj;
	struct zsock_pollfd *pfd;
	struct k_poll_event **pev;

	switch (request) {
	case ZFD_IOCTL_POLL_PREPARE: {
		struct k_poll_event *pev_end;

		pfd = va_arg(args, struct zsock_pollfd *);
		pev = va_arg(args, struct k_poll_event **);
		pev_end = va_arg(args, struct k_poll_event *);

		if ((mock->expected_events >= 0) && (pfd->events != mock->expected_events)) {
			k_sem_give(&mock->wrong_events);
		}

		if (*pev == pev_end) {
			return -ENOMEM;
		}

		k_poll_event_init(*pev, K_POLL_TYPE_SEM_AVAILABLE, K_POLL_MODE_NOTIFY_ONLY,
				  &mock->readable);
		(*pev)++;
		k_sem_give(&mock->prepared);

		return 0;
	}
	case ZFD_IOCTL_POLL_UPDATE:
		pfd = va_arg(args, struct zsock_pollfd *);
		pev = va_arg(args, struct k_poll_event **);

		if ((*pev)->state == K_POLL_STATE_SEM_AVAILABLE) {
			pfd->revents = pfd->events;
		}

		(*pev)++;

		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static const struct fd_op_vtable reconfig_mock_vtable = {
	.close = reconfig_mock_close,
	.ioctl = reconfig_mock_ioctl,
};

static int reconfig_mock_alloc(struct reconfig_mock_fd *mock)
{
	return zvfs_alloc_fd(mock, &reconfig_mock_vtable);
}

struct reconfig_state {
	struct k_sem callback;
	struct zsock_pollfd replacement;
	int callback_result;
	int callback_count;
};

static void reconfig_state_init(struct reconfig_state *state)
{
	k_sem_init(&state->callback, 0, UINT_MAX);
	state->replacement.fd = -1;
	state->callback_result = 0;
	state->callback_count = 0;
}

static void reconfig_unregister_handler(struct net_socket_service_event *pev)
{
	struct reconfig_state *state = pev->user_data;

	state->callback_result = net_socket_service_unregister(pev->svc);
	k_sem_give(&state->callback);
}

NET_SOCKET_SERVICE_SYNC_DEFINE_STATIC(reconfig_unregister_service, reconfig_unregister_handler, 1);

static void reconfig_close_handler(struct net_socket_service_event *pev)
{
	struct reconfig_state *state = pev->user_data;

	state->callback_count++;
	if (state->callback_count == 1) {
		state->callback_result = net_socket_service_close(pev->svc);
	} else {
		(void)net_socket_service_unregister(pev->svc);
	}

	k_sem_give(&state->callback);
}

NET_SOCKET_SERVICE_SYNC_DEFINE_STATIC(reconfig_close_service, reconfig_close_handler,
				      RECONFIG_CLOSE_FD_COUNT);

static void reconfig_replace_handler(struct net_socket_service_event *pev)
{
	struct reconfig_state *state = pev->user_data;

	state->callback_count++;
	if (state->callback_count == 1) {
		state->callback_result =
			net_socket_service_register(pev->svc, &state->replacement, 1, state);
	} else {
		state->callback_result = net_socket_service_close(pev->svc);
	}

	k_sem_give(&state->callback);
}

NET_SOCKET_SERVICE_SYNC_DEFINE_STATIC(reconfig_service, reconfig_replace_handler, 1);

static void reconfig_witness_handler(struct net_socket_service_event *pev)
{
	ARG_UNUSED(pev);
}

NET_SOCKET_SERVICE_SYNC_DEFINE_STATIC(reconfig_witness_service, reconfig_witness_handler, 1);

ZTEST(net_socket_service, test_close_from_callback)
{
	struct zsock_pollfd pollfd = {.events = ZSOCK_POLLIN};
	static struct reconfig_mock_fd mock;
	static struct reconfig_state state;
	int fd, ret;

	reconfig_mock_init(&mock);
	reconfig_state_init(&state);
	fd = reconfig_mock_alloc(&mock);
	zassert_true(fd >= 0, "Cannot allocate fd (%d)", fd);

	pollfd.fd = fd;
	ret = net_socket_service_register(&reconfig_close_service, &pollfd, 1, &state);
	zassert_equal(ret, 0, "Cannot register service (%d)", ret);
	zassert_ok(k_sem_take(&mock.prepared, RECONFIG_TIMEOUT), "Registered fd was not polled");

	k_sem_give(&mock.readable);
	zassert_ok(k_sem_take(&state.callback, RECONFIG_TIMEOUT), "Timeout while waiting callback");
	zassert_equal(state.callback_result, 0, "Cannot close service (%d)", state.callback_result);

	ret = k_sem_take(&mock.closed, RECONFIG_TIMEOUT);
	if (ret != 0) {
		(void)net_socket_service_unregister(&reconfig_close_service);
		(void)zvfs_close(fd);
	}

	zassert_ok(ret, "Service fd was not closed");
	zassert_equal(state.callback_count, 1, "Callback ran again before close");
}

ZTEST(net_socket_service, test_close_multiple_from_callback)
{
	struct zsock_pollfd pollfd[RECONFIG_CLOSE_FD_COUNT] = {
		{.events = ZSOCK_POLLIN},
		{.events = ZSOCK_POLLIN},
	};
	static struct reconfig_mock_fd mock[RECONFIG_CLOSE_FD_COUNT];
	static struct reconfig_state state;
	int close_ret[RECONFIG_CLOSE_FD_COUNT], ret;

	reconfig_state_init(&state);
	for (int i = 0; i < ARRAY_SIZE(mock); i++) {
		reconfig_mock_init(&mock[i]);
		pollfd[i].fd = reconfig_mock_alloc(&mock[i]);
		zassert_true(pollfd[i].fd >= 0, "Cannot allocate fd %d (%d)", i, pollfd[i].fd);
		k_sem_give(&mock[i].readable);
	}

	ret = net_socket_service_register(&reconfig_close_service, pollfd, ARRAY_SIZE(pollfd),
					  &state);
	zassert_equal(ret, 0, "Cannot register service (%d)", ret);
	for (int i = 0; i < ARRAY_SIZE(mock); i++) {
		zassert_ok(k_sem_take(&mock[i].prepared, RECONFIG_TIMEOUT),
			   "Registered fd %d was not polled", i);
	}

	zassert_ok(k_sem_take(&state.callback, RECONFIG_TIMEOUT), "Timeout while waiting callback");
	zassert_equal(state.callback_result, 0, "Cannot close service (%d)", state.callback_result);

	for (int i = 0; i < ARRAY_SIZE(mock); i++) {
		close_ret[i] = k_sem_take(&mock[i].closed, RECONFIG_TIMEOUT);
	}

	if ((close_ret[0] != 0) || (close_ret[1] != 0)) {
		(void)net_socket_service_unregister(&reconfig_close_service);
		for (int i = 0; i < ARRAY_SIZE(mock); i++) {
			if (close_ret[i] != 0) {
				(void)zvfs_close(pollfd[i].fd);
			}
		}
	}

	for (int i = 0; i < ARRAY_SIZE(mock); i++) {
		zassert_ok(close_ret[i], "Service fd %d was not closed", i);
	}
	zassert_equal(state.callback_count, 1, "Another ready fd invoked the callback");
}

ZTEST(net_socket_service, test_reconfigure_from_callback)
{
	struct zsock_pollfd pollfd = {.events = ZSOCK_POLLIN};
	static struct reconfig_mock_fd mock, replacement;
	static struct reconfig_state state;
	int fd, replacement_fd, ret;

	reconfig_mock_init(&mock);
	reconfig_mock_init(&replacement);
	reconfig_state_init(&state);
	replacement.expected_events = ZSOCK_POLLOUT;

	fd = reconfig_mock_alloc(&mock);
	zassert_true(fd >= 0, "Cannot allocate fd (%d)", fd);
	replacement_fd = reconfig_mock_alloc(&replacement);
	zassert_true(replacement_fd >= 0, "Cannot allocate replacement fd (%d)", replacement_fd);

	pollfd.fd = fd;
	state.replacement.fd = replacement_fd;
	state.replacement.events = ZSOCK_POLLOUT;
	ret = net_socket_service_register(&reconfig_service, &pollfd, 1, &state);
	zassert_equal(ret, 0, "Cannot register service (%d)", ret);
	zassert_ok(k_sem_take(&mock.prepared, RECONFIG_TIMEOUT), "Registered fd was not polled");

	k_sem_give(&replacement.readable);
	k_sem_give(&mock.readable);
	zassert_ok(k_sem_take(&state.callback, RECONFIG_TIMEOUT),
		   "Timeout while waiting reconfigure callback");
	zassert_ok(k_sem_take(&state.callback, RECONFIG_TIMEOUT),
		   "Timeout while waiting replacement callback");
	zassert_equal(state.callback_result, 0, "Cannot update service (%d)",
		      state.callback_result);
	zassert_ok(k_sem_take(&replacement.closed, RECONFIG_TIMEOUT),
		   "Replacement fd was not closed");
	zassert_equal(k_sem_count_get(&replacement.wrong_events), 0,
		      "Replacement fd was polled with stale events");

	ret = zvfs_close(fd);
	zassert_equal(ret, 0, "close failed");
}

ZTEST(net_socket_service, test_reconfigure_events_from_callback)
{
	struct zsock_pollfd pollfd = {.events = ZSOCK_POLLIN};
	static struct reconfig_mock_fd mock;
	static struct reconfig_state state;
	int fd, ret;

	reconfig_mock_init(&mock);
	reconfig_state_init(&state);
	fd = reconfig_mock_alloc(&mock);
	zassert_true(fd >= 0, "Cannot allocate fd (%d)", fd);

	pollfd.fd = fd;
	state.replacement.fd = fd;
	state.replacement.events = ZSOCK_POLLOUT;
	ret = net_socket_service_register(&reconfig_service, &pollfd, 1, &state);
	zassert_equal(ret, 0, "Cannot register service (%d)", ret);
	zassert_ok(k_sem_take(&mock.prepared, RECONFIG_TIMEOUT), "Registered fd was not polled");

	mock.expected_events = ZSOCK_POLLOUT;
	k_sem_give(&mock.readable);
	zassert_ok(k_sem_take(&state.callback, RECONFIG_TIMEOUT),
		   "Timeout while waiting reconfigure callback");
	zassert_ok(k_sem_take(&state.callback, RECONFIG_TIMEOUT),
		   "Timeout while waiting reconfigured callback");
	zassert_equal(state.callback_result, 0, "Cannot update service (%d)",
		      state.callback_result);
	zassert_ok(k_sem_take(&mock.closed, RECONFIG_TIMEOUT), "Reconfigured fd was not closed");
	zassert_equal(k_sem_count_get(&mock.wrong_events), 0,
		      "Reconfigured fd was polled with stale events");
}

ZTEST(net_socket_service, test_unregister_from_callback)
{
	struct zsock_pollfd pollfd = {.events = ZSOCK_POLLIN};
	struct zsock_pollfd witness_pollfd = {.events = ZSOCK_POLLIN};
	static struct reconfig_mock_fd mock, witness;
	static struct reconfig_state state;
	int fd, witness_fd, ret;

	reconfig_mock_init(&mock);
	reconfig_mock_init(&witness);
	reconfig_state_init(&state);
	fd = reconfig_mock_alloc(&mock);
	zassert_true(fd >= 0, "Cannot allocate fd (%d)", fd);
	witness_fd = reconfig_mock_alloc(&witness);
	zassert_true(witness_fd >= 0, "Cannot allocate witness fd (%d)", witness_fd);

	/* The witness confirms that the poll set was rebuilt. */
	witness_pollfd.fd = witness_fd;
	ret = net_socket_service_register(&reconfig_witness_service, &witness_pollfd, 1, NULL);
	zassert_equal(ret, 0, "Cannot register witness service (%d)", ret);
	zassert_ok(k_sem_take(&witness.prepared, RECONFIG_TIMEOUT), "Witness fd was not polled");

	pollfd.fd = fd;
	ret = net_socket_service_register(&reconfig_unregister_service, &pollfd, 1, &state);
	zassert_equal(ret, 0, "Cannot register service (%d)", ret);
	zassert_ok(k_sem_take(&mock.prepared, RECONFIG_TIMEOUT), "Registered fd was not polled");
	zassert_ok(k_sem_take(&witness.prepared, RECONFIG_TIMEOUT), "Witness fd was not repolled");

	k_sem_give(&mock.readable);
	zassert_ok(k_sem_take(&state.callback, RECONFIG_TIMEOUT), "Timeout while waiting callback");
	zassert_equal(state.callback_result, 0, "Cannot unregister service (%d)",
		      state.callback_result);
	zassert_ok(k_sem_take(&witness.prepared, RECONFIG_TIMEOUT),
		   "Service did not rebuild its poll set");
	zassert_equal(k_sem_count_get(&mock.prepared), 0, "Unregistered fd was polled again");

	ret = zvfs_close(fd);
	zassert_equal(ret, 0, "close failed");
	ret = net_socket_service_close(&reconfig_witness_service);
	zassert_equal(ret, 0, "Cannot close witness service (%d)", ret);
	zassert_ok(k_sem_take(&witness.closed, RECONFIG_TIMEOUT), "Witness fd was not closed");
}
