/*
 * Copyright (c) 2024 Nordic Semiconductor ASA
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/logging/log.h>
LOG_MODULE_DECLARE(net_shell);

#include <zephyr/posix/unistd.h>
#include <getopt.h>
#include <zephyr/sys/base64.h>

#include <zephyr/net/virtual.h>
#include <zephyr/net/wireguard.h>

#include "net_shell_private.h"
#include "wireguard/wg_internal.h"

#if defined(CONFIG_WIREGUARD)
static void wg_peer_cb(struct wg_peer *peer, void *user_data)
{
	struct net_shell_user_data *data = user_data;
	const struct shell *sh = data->sh;
	int *count = data->user_data;
	/* +7 for []/len */
	char addr[ADDR_LEN + 7];
	char mask[sizeof("/128")];
	char public_key[WG_PUBLIC_KEY_LEN * 2];
	size_t olen;

	if ((*count) == 0) {
		PR("Id   Iface %-24s\t%s\n", "Allowed IPs", "Public key");
	}

	net_addr_ntop(peer->allowed_ips.sa_family,
		      &net_sin(&peer->allowed_ips)->sin_addr,
		      addr, sizeof(addr));

	(void)base64_encode(public_key, sizeof(public_key),
			    &olen, peer->public_key, sizeof(peer->public_key));

	snprintk(mask, sizeof(mask), "/%d", peer->mask_len);
	strcat(addr, mask);

	PR("[%2d] %d     %-24s\t%s\n",
	   peer->id, net_if_get_by_iface(peer->iface), addr, public_key);

	(*count)++;
}
#endif /* CONFIG_WIREGUARD */

static int cmd_net_wg(const struct shell *sh, size_t argc, char *argv[])
{
#if defined(CONFIG_WIREGUARD)
	struct net_shell_user_data user_data;
	int count = 0;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	user_data.sh = sh;
	user_data.user_data = &count;

	wireguard_peer_foreach(wg_peer_cb, &user_data);

	if (count == 0) {
		PR("No connections\n");
	}
#else
	PR_INFO("Set %s to enable %s support.\n", "CONFIG_WIREGUARD",
		"Wireguard VPN");
#endif /* CONFIG_WIREGUARD */

	return 0;
}

static int parse_addr_and_len(const struct shell *sh, char *opt,
			      struct sockaddr *addr, int *len)
{
	char *slash = strstr(opt, "/");

	if (!net_ipaddr_parse(opt, slash == NULL ? strlen(opt) : slash - opt,
			      addr)) {
		return -EINVAL;
	}

	if (slash == NULL) {
		if (addr->sa_family == AF_INET) {
			*len = 32;
		} else {
			*len = 128;
		}
	} else {
		char *endptr;
		int tmp_len;

		tmp_len = strtol(slash + 1, &endptr, 10);
		if (*endptr != '\0') {
			PR_WARNING("Invalid mask len \"%s\"\n", slash + 1);
			return -EINVAL;
		}

		*len = tmp_len;
	}

	return 0;
}

static int parse_peer_add_args_to_params(const struct shell *sh, int argc,
					 char *argv[],
					 struct wireguard_peer_config *peer,
					 char *public_key,
					 size_t public_key_len)
{
	struct getopt_state *state;
	int option_index = 0;
	int opt;

	static const struct option long_options[] = {
		{ "public-key", required_argument, 0, 'k' },
		{ "allowed-ips", required_argument, 0, 'a' },
		{ "preshared-key", optional_argument, 0, 'p' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "k:a:p:h", long_options, &option_index)) != -1) {
		state = getopt_state_get();
		switch (opt) {
		case 'k':
			strncpy(public_key, state->optarg, public_key_len);
			break;
		case 'a': {
			struct sockaddr addr = { 0 };
			int len = 0;

			if (parse_addr_and_len(sh, state->optarg, &addr, &len) < 0) {
				return -ENOEXEC;
			}

			memcpy(&peer->allowed_ips, &addr, sizeof(peer->allowed_ips));
			peer->mask_len = len;
			break;
		}
		case 'h':
		case '?':
		default:
			shell_help(sh);
			return SHELL_CMD_HELP_PRINTED;
		}
	}

	return 0;
}

static int cmd_wg_add(const struct shell *sh, size_t argc, char *argv[])
{
#if defined(CONFIG_WIREGUARD)
	struct wireguard_peer_config peer_config = { 0 };
	struct net_if *peer_iface = NULL;
	char public_key[WG_PUBLIC_KEY_LEN * 2];
	int ret;

	if (argc < 2) {
		PR_ERROR("Invalid number of arguments\n");
		return -EINVAL;
	}

	if (parse_peer_add_args_to_params(sh, argc, argv, &peer_config,
					  public_key, sizeof(public_key)) != 0) {
		return -ENOEXEC;
	}

	peer_config.public_key = public_key;

	ret = wireguard_peer_add(&peer_config, &peer_iface);
	if (ret < 0) {
		PR_WARNING("Cannot %s peer (%d)\n", "add", ret);
	} else if (ret > 0) {
		if (peer_iface != NULL) {
			PR("Added peer id %d using interface %d\n", ret,
			   net_if_get_by_iface(peer_iface));
		} else {
			PR("%s peer id %d\n", "Added", ret);
		}
	}
#else
	PR_INFO("Set %s to enable %s support.\n", "CONFIG_WIREGUARD",
		"Wireguard VPN");
#endif /* CONFIG_WIREGUARD */

	return 0;
}

static int parse_peer_del_args_to_params(const struct shell *sh, int argc,
					 char *argv[], int *id)
{
	struct getopt_state *state;
	int option_index = 0;
	int opt;

	static const struct option long_options[] = {
		{ "id", required_argument, 0, 'i' },
		{ "help", no_argument, 0, 'h' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "i:h", long_options, &option_index)) != -1) {
		state = getopt_state_get();
		switch (opt) {
		case 'i': {
			char *endptr;
			int tmp_id;

			tmp_id = strtol(state->optarg, &endptr, 10);
			if (*endptr != '\0') {
				PR_WARNING("Invalid id \"%s\"\n", state->optarg);
				return -EINVAL;
			}

			*id = tmp_id;
			break;
		}
		case 'h':
		case '?':
		default:
			shell_help(sh);
			return SHELL_CMD_HELP_PRINTED;
		}
	}

	return 0;
}

static int cmd_wg_del(const struct shell *sh, size_t argc, char *argv[])
{
#if defined(CONFIG_WIREGUARD)
	int ret, id = 0;

	if (argc < 2) {
		PR_ERROR("Invalid number of arguments\n");
		return -EINVAL;
	}

	if (parse_peer_del_args_to_params(sh, argc, argv, &id) != 0) {
		return -ENOEXEC;
	}

	ret = wireguard_peer_remove(id);
	if (ret < 0) {
		PR_WARNING("Cannot %s peer (%d)\n", "delete", ret);
	} else {
		PR("%s peer id %d\n", "Deleted", ret);
	}
#else
	PR_INFO("Set %s to enable %s support.\n", "CONFIG_WIREGUARD",
		"Wireguard VPN");
#endif /* CONFIG_WIREGUARD */

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(net_cmd_wg,
	SHELL_CMD_ARG(add, NULL,
		      "Add a peer in order to establish a VPN connection.\n"
		      "[-k, --public-key <key>] : Peer public key in base64 format\n"
		      "[-a, --allowed-ips <ipaddr/mask-len>] : Allowed IPv4/6 addresses\n"
		      "[-p, --preshared-key <key>] : Pre-shared key (optional)\n"
		      "[-t, --private-key-tag <tag>]: Private key tag in the credetial store\n",
		      cmd_wg_add, 1, 8),
	SHELL_CMD_ARG(del, NULL,
		      "Delete a peer. Any existing connection is terminated.\n"
		      "[-i, --id <peer-id>] : Peer id\n",
		      cmd_wg_del, 1, 4),
	SHELL_SUBCMD_SET_END
);

SHELL_SUBCMD_ADD((net), wg, &net_cmd_wg,
		 "Print information about Wireguard VPN connections.",
		 cmd_net_wg, 1, 1);
