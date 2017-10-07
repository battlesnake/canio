#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>

#include <getopt.h>

#include <termios.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>

#include <sys/signalfd.h>

#include "log.h"

#include "args.h"

#include "canio.h"

#include "cansys.h"

#define TIMEOUT 1000

CLI_COMMAND_HANDLER(do_ident)
{
	(void) args;
	struct cansys_client *client = ctx;
	char name[8];
	if (cansys_client_ident(client, name, sizeof(name), 0)) {
		error("%s", strerror(errno));
		return ccr_fail;
	}
	info("Identity: <%s>", name);
	return ccr_success;
}

CLI_COMMAND_HANDLER(do_ping)
{
	struct cansys_client *client = ctx;
	if (cansys_client_ping(client, 0)) {
		error("%s", strerror(errno));
		return ccr_fail;
	}
	return ccr_success;
}

CLI_COMMAND_HANDLER(do_set_heartbeat)
{
	uint64_t value = strtoull(args->args[1], NULL, 10);
	struct cansys_client *client = ctx;
	if (cansys_client_set_heartbeat(client, value, 0)) {
		error("%s", strerror(errno));
		return ccr_fail;
	}
	return ccr_success;
}

CLI_COMMAND_HANDLER(do_reboot)
{
	struct cansys_client *client = ctx;
	if (cansys_client_reboot(client, 0)) {
		error("%s", strerror(errno));
		return ccr_fail;
	}
	return ccr_success;
}

CLI_COMMAND_HANDLER(do_uptime)
{
	struct cansys_client *client = ctx;
	uint64_t value;
	if (cansys_client_uptime(client, &value, 0)) {
		error("%s", strerror(errno));
		return ccr_fail;
	}
	int z = value % 1000; value /= 1000;
	int s = value % 60; value /= 60;
	int m = value % 60; value /= 60;
	int h = value;
	info("Uptime: %02d:%02u:%02u.%03u", h, m, s, z);
	return ccr_success;
}

CLI_COMMAND_HANDLER(do_reg)
{
	struct cansys_client *client = ctx;
	uint16_t reg = strtol(args->args[1], NULL, 0);
	if (args->argc == 3) {
		uint64_t value = strtoll(args->args[2], NULL, 0);
		if (cansys_client_reg_write(client, reg, value, 0)) {
			error("%s", strerror(errno));
			return ccr_fail;
		}
		return ccr_success;
	}
	uint64_t value;
	if (cansys_client_reg_read(client, reg, &value, 0)) {
		error("%s", strerror(errno));
		return ccr_fail;
	}
	info("Register %hu: %ld (%010lx)\n", reg, value, value);
	return ccr_success;
}

struct cli_command cmds[] = {
	{
		.command = "ident",
		.min_args = 1,
		.max_args = 1,
		.handler = do_ident
	},
	{
		.command = "ping",
		.min_args = 1,
		.max_args = 1,
		.handler = do_ping
	},
	{
		.command = "heartbeat",
		.min_args = 2,
		.max_args = 2,
		.handler = do_set_heartbeat
	},
	{
		.command = "reboot",
		.min_args = 1,
		.max_args = 1,
		.handler = do_reboot
	},
	{
		.command = "uptime",
		.min_args = 1,
		.max_args = 1,
		.handler = do_uptime
	},
	{
		.command = "reg",
		.min_args = 2,
		.max_args = 3,
		.handler = do_reg
	},
};

int main(int argc, char *argv[])
{
	int node_id = -1;
	const char *iface = NULL;

	int c;
	while ((c = getopt(argc, argv, "n:i:")) != -1) {
		switch (c) {
		case 'n': node_id = atoi(optarg); break;
		case 'i': iface = optarg; break;
		default: error("Invalid argument: '%c'", c); return 1;
		}
	}
	if (node_id < 0 || !iface || optind != argc) {
		error("Syntax: %s -n <node_id> -i <iface>", argv[0]);
		return 1;
	}

	struct cansys_client client;
	if (cansys_client_init(&client, iface, node_id, TIMEOUT)) {
		callfail("cansys_client_init");
		return 1;
	}
	int fd = client.fd;

	sigset_t ss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGQUIT);

	const int sfd = signalfd(-1, &ss, 0);

	if (sfd < 0) {
		sysfail("signalfd");
		return 1;
	}

	if (sigprocmask(SIG_BLOCK, &ss, NULL) < 0) {
		sysfail("sigprocmask");
		return 1;
	}

	struct arg_builder args;
	args_reset(&args);

	bool end = false;

	if (write(STDOUT_FILENO, "$ ", 2)) { }

	while (true) {
		enum fds {
			fd_stdin,
			fd_can,
			fd_signal
		};
		struct pollfd pfd[] = {
			[fd_stdin] = { .fd = STDIN_FILENO, .events = POLLIN },
			[fd_can] = { .fd = fd, .events = POLLIN },
			[fd_signal] = { .fd = sfd, .events = POLLIN },
		};
		if (poll(pfd, sizeof(pfd) / sizeof(pfd[0]), -1) < 0) {
			sysfail("poll");
			break;
		}
		if (pfd[fd_signal].revents) {
			end = true;
			break;
		}
		if (pfd[fd_stdin].revents) {
			char c;
			if (read(STDIN_FILENO, &c, 1) != 1) {
				sysfail("read");
				break;
			}
			enum args_char_action ret = args_char(&args, c);
			if (ret == aca_error) {
				break;
			}
			if (ret == aca_run) {
				switch (args_execute(&args, &client, cmds, sizeof(cmds) / sizeof(cmds[0]))) {
				case ccr_syntax: error("Syntax error"); break;
				case ccr_fail: error("Command failed"); break;
				case ccr_success: info("Success"); break;
				}
				args_reset(&args);
				if (write(STDOUT_FILENO, "$ ", 2)) { }
				continue;
			}
		}
		if (pfd[fd_can].revents) {
			uint32_t id;
			struct cansys_data msg;
			ssize_t ret;
			if ((ret = canio_read(fd, &id, &msg, sizeof(msg))) < 0) {
				error("canio_read failed: %s", strerror(errno));
				break;
			}
			if (cansys_client_is_heartbeat(&client, &msg, ret)) {
				/* Ignore result in case we have no stdout */
				if (write(STDOUT_FILENO, "\a", 1) < 0) { }
			} else {
				info("Mysterious unexpected packet of length %zu received, perhaps someone else is accessing the server", ret);
			}
		}
	}

	cansys_client_free(&client);

	close(sfd);

	return end ? 0 : 1;
}
