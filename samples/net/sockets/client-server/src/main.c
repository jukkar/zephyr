
#include <kernel.h>

#include <net/socket.h>

#define STACK_SIZE 2024
#define THREAD_PRIORITY K_PRIO_COOP(8)

int client()
{
	struct sockaddr_in addr;
	uint16_t port = 40000;
	char              *dst = "192.0.2.1";
	int               s = -1;
	int                ret = -1;
	char* messg = "Hello from client";
	char buffer[1024] = {0};

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if ((s = zsock_socket(addr.sin_family, SOCK_STREAM, 0)) < 0) {
		printk("socket\n");
		return -1;
	}

	if (zsock_inet_pton(addr.sin_family, dst, &addr.sin_addr) != 1)
		return -1;

	if (zsock_connect(s, (struct sockaddr*)&addr, sizeof(addr)) < 0){
		zsock_close(s);
		return -1;
	}

	if((ret = zsock_send(s , messg , strlen(messg) , 0 )) < 0)
		return -1;

	return 0;
}

int server()
{
	struct sockaddr_in addr;
	uint16_t port = 40000;
	char              *dst = "192.0.2.1";
	int               s, new_socket = -1;
	int                ret = -1;
	int addrlen = sizeof(addr);
	int opt = 1;
	char buffer[1024] = {0};
	char* messg = "Hello from server";

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	if ((s = zsock_socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return -1;
	}

	if (zsock_setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
		return -1;
	}

	if (zsock_bind(s, (struct sockaddr *)&addr, sizeof(addr))<0) {
		printk("bind\n");
		return -1;
	}

	if (zsock_listen(s, 3) < 0) {
		return -1;
	}

	if ((new_socket = zsock_accept(s, (struct sockaddr *)&addr,
				       (socklen_t*)&addrlen))<0) {
		return -1;
	}

	ret = zsock_recv( new_socket , buffer, sizeof(buffer), 0);
	printk("len %d  %s\n",ret, buffer);

	return 0;
}


K_THREAD_DEFINE(client_thread_id, STACK_SIZE,
		client, NULL, NULL, NULL,
		THREAD_PRIORITY, 0, -1);

K_THREAD_DEFINE(server_thread_id, STACK_SIZE,
		server, NULL, NULL, NULL,
		THREAD_PRIORITY, 0, -1);

void main(void)
{
	k_thread_start(server_thread_id);
	k_thread_start(client_thread_id);
}
