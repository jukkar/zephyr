/*
 * Copyright (c) 2020 Intel Corporation.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <stdlib.h>

#define NUM_THREADS 2

#if !defined(__ZEPHYR__)

#include <pthread.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#define USE_IPV6
#define USE_IPV4

#ifndef POINTER_TO_INT
#define POINTER_TO_INT(x)  ((intptr_t) (x))
#endif

#ifndef INT_TO_POINTER
#define INT_TO_POINTER(x)  ((void *) (intptr_t) (x))
#endif

#else

#include <fcntl.h>
#include <net/socket.h>
#include <kernel.h>

#ifdef CONFIG_NET_IPV6
#define USE_IPV6
#endif

#ifdef CONFIG_NET_IPV4
#define USE_IPV4
#endif

K_KERNEL_STACK_ARRAY_DEFINE(thread_stack, NUM_THREADS, 1024);
#define PRIORITY  k_thread_priority_get(k_current_get())

#endif

/* One IPv4 and IPv6 connection at a time */
#define NUM_FDS NUM_THREADS

#define BIND_PORT 4242

static struct pollfd pollfds[NUM_FDS];
static int pollnum;

static struct thread_args {
	int idx;
	int fd;
#if !defined(__ZEPHYR__)
	pthread_t thread;
#else
	struct k_thread thread;
#endif
	bool pending;
} thread_args[NUM_THREADS];

static const int max_conns = sizeof(thread_args) / sizeof(thread_args[0]);

#define fatal(msg, ...)					   \
	do {						   \
		printf("Error: " msg "\n", ##__VA_ARGS__); \
		exit(1);				   \
	} while (0)


static void setblocking(int fd, bool val)
{
	int fl, res;

	fl = fcntl(fd, F_GETFL, 0);
	if (fl == -1) {
		fatal("fcntl(F_GETFL): %d", errno);
	}

	if (val) {
		fl &= ~O_NONBLOCK;
	} else {
		fl |= O_NONBLOCK;
	}

	res = fcntl(fd, F_SETFL, fl);
	if (fl == -1) {
		fatal("fcntl(F_SETFL): %d", errno);
	}
}

static int pollfds_add(int fd)
{
	int i;

	if (pollnum < NUM_FDS) {
		i = pollnum++;
	} else {
		for (i = 0; i < NUM_FDS; i++) {
			if (pollfds[i].fd < 0) {
				goto found;
			}
		}

		return -1;
	}

found:
	pollfds[i].fd = fd;
	pollfds[i].events = POLLIN;

	return 0;
}

#if !defined(__ZEPHYR__)
static void *handler(void *arg)
#else
static void handler(void *arg)
#endif
{
	struct thread_args *args = arg;
	struct pollfd pollfd[1];
	const char *ptr;
	char buf[128];
	int out_len;
	int ret;
	int fd;

	fd = args->fd;

	setblocking(fd, false);

	pollfd[0].fd = fd;
	pollfd[0].events = POLLIN;

	while (1) {
		ret = poll(pollfd, 1, -1);
		if (ret < 0) {
			printf("poll error: %d\n", errno);
			continue;
		}

		if (!(pollfd[0].revents & POLLIN)) {
			continue;
		}

		ret = recv(pollfd[0].fd, buf, sizeof(buf), 0);
		if (ret <= 0) {
			if (ret < 0) {
				printf("error: recv: %d\n", errno);
			}

		error:
			close(pollfd[0].fd);
			args->fd = -1;

			printf("Connection fd %d closed\n", pollfd[0].fd);
			break;
		}

		for (ptr = buf; ret; ret -= out_len) {
			out_len = send(pollfd[0].fd, ptr, ret, 0);
			if (out_len < 0) {
				printf("error: send: %d\n", errno);
				goto error;
			}

			ptr += out_len;
		}
	}

#if !defined(__ZEPHYR__)
	return NULL;
#endif
}

static int accept_and_process(int sock)
{
	struct sockaddr_storage peer_addr;
	socklen_t peer_addr_len = sizeof(peer_addr);
	struct thread_args *arg = NULL;
	char addr_str[INET6_ADDRSTRLEN];
	static int counter;
	void *addr;
	int peer;
	int ret;
	int i;

	peer = accept(sock, (struct sockaddr *)&peer_addr,
		      &peer_addr_len);
	if (peer < 0) {
		return peer;
	}

	for (i = 0; i < max_conns; i++) {
		if (thread_args[i].fd >= 0) {
			continue;
		}

		thread_args[i].fd = peer;
		arg = &thread_args[i];
		break;
	}

	if (i >= max_conns) {
		static char msg[] = "Too many connections\n";

		ret = send(peer, msg, sizeof(msg) - 1, 0);
		if (ret < 0) {
			printf("error: send: %d\n", errno);
		}

		close(peer);

		if (arg) {
			arg->fd = -1;
		}

		errno = ENFILE;
		return -1;
	}

	if (peer_addr.ss_family == AF_INET) {
		addr = &((struct sockaddr_in *)&peer_addr)->sin_addr;
	} else {
		addr = &((struct sockaddr_in6 *)&peer_addr)->sin6_addr;
	}

	inet_ntop(peer_addr.ss_family, addr, addr_str, sizeof(addr_str));

	printf("Connection #%d from %s fd %d\n", ++counter, addr_str, peer);

#if !defined(__ZEPHYR__)
	ret = pthread_create(&arg->thread, NULL, handler, arg);
	if (ret < 0) {
		close(peer);
		arg->fd = -1;
		return 0;
	}
#else
	k_thread_create(&arg->thread, thread_stack[arg->idx],
			K_THREAD_STACK_SIZEOF(thread_stack[arg->idx]),
			(k_thread_entry_t)handler, arg, NULL, NULL,
			PRIORITY, 0, K_NO_WAIT);
#endif

	return peer;
}

void main(void)
{
	int num_socks = 0;
	int opt = 1;
	int ret, i;

	int serv4;
	struct sockaddr_in bind_addr4 = {
		.sin_family = AF_INET,
		.sin_port = htons(BIND_PORT),
		.sin_addr = {
			.s_addr = htonl(INADDR_ANY),
		},
	};

	int serv6;
	struct sockaddr_in6 bind_addr6 = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(BIND_PORT),
		.sin6_addr = IN6ADDR_ANY_INIT,
	};

#if defined(USE_IPV4)
	serv4 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (serv4 < 0) {
		printf("error: socket: %d\n", errno);
		exit(1);
	}

	ret = bind(serv4, (struct sockaddr *)&bind_addr4, sizeof(bind_addr4));
	if (ret < 0) {
		printf("Cannot bind IPv4, errno: %d\n", errno);
		exit(1);
	}

	num_socks++;
	setblocking(serv4, false);
	listen(serv4, 5);
	pollfds_add(serv4);
#endif

#if defined(USE_IPV6)
	serv6 = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (serv6 < 0) {
		printf("error: socket(AF_INET6): %d\n", errno);
		exit(1);
	}

#if defined(IPV6_V6ONLY)
	/* For Linux, we need to make socket IPv6-only to bind it to the
	 * same port as IPv4 socket above.
	 */
	ret = setsockopt(serv6, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
	if (ret < 0) {
		printf("error: setsockopt: %d\n", errno);
		exit(1);
	}
#endif

	ret = bind(serv6, (struct sockaddr *)&bind_addr6, sizeof(bind_addr6));
	if (ret < 0) {
		printf("Cannot bind IPv6, errno: %d\n", errno);
	}

	num_socks++;
	setblocking(serv6, false);
	listen(serv6, 5);
	pollfds_add(serv6);
#endif

	for (i = 0; i < max_conns; i++) {
		thread_args[i].idx = i;
		thread_args[i].fd = -1;
	}

	printf("Posix TCP echo server waits for connections on port %d\n",
	       BIND_PORT);

	while (1) {
		ret = poll(pollfds, pollnum, -1);
		if (ret < 0) {
			printf("poll error: %d\n", errno);
			continue;
		}

		for (i = 0; i < pollnum; i++) {
			if (!(pollfds[i].revents & POLLIN)) {
				continue;
			}

			if (i < num_socks) {
				int peer;

				peer = accept_and_process(pollfds[i].fd);
				if (peer < 0) {
					printf("error: accept: %d\n", errno);
					continue;
				}
			}
		}
	}
}
