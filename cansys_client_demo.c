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
#include <time.h>

#include <sys/signalfd.h>

#include "log.h"

#include "args.h"

#include "reactor.h"

#include "canio.h"

#include "cansys.h"

#define TIMEOUT 1000

struct program_state
{
	struct reactor reactor;

	struct arg_builder args;
	struct cansys_client can_client;

	int can_fd;
	int signal_fd;
};

static canio_timeout_t get_optional_timeout(const struct arg_builder *args)
{
	if (args->argc == 2) {
		return strtoull(args->args[1], NULL, 10);
	} else {
		return 0;
	}
}

CLI_COMMAND_HANDLER(do_ident)
{
	struct program_state *state = ctx;
	char name[8];
	if (cansys_client_ident(&state->can_client, name, sizeof(name), get_optional_timeout(args))) {
		error("%s", strerror(errno));
		return ccr_fail;
	}
	info("Identity: <%s>", name);
	return ccr_success;
}

CLI_COMMAND_HANDLER(do_ping)
{
	struct program_state *state = ctx;
	struct timespec a, b;
	if (clock_gettime(CLOCK_BOOTTIME, &a)) {
		sysfail("clock_gettime");
		return ccr_fail;
	}
	if (cansys_client_ping(&state->can_client, get_optional_timeout(args))) {
		error("%s", strerror(errno));
		return ccr_fail;
	}
	if (clock_gettime(CLOCK_BOOTTIME, &b)) {
		sysfail("clock_gettime");
		return ccr_fail;
	}
	uint64_t ds = b.tv_sec - a.tv_sec;
	int32_t dns = b.tv_nsec - a.tv_nsec;
	if (dns < 0) {
		ds--;
		dns += 1000000000;
	}
	info("RTT: %lu.%06ds", ds, dns / 1000);
	return ccr_success;
}

CLI_COMMAND_HANDLER(do_set_heartbeat)
{
	uint64_t value = strtoull(args->args[1], NULL, 10);
	struct program_state *state = ctx;
	if (cansys_client_set_heartbeat(&state->can_client, value, 0)) {
		error("%s", strerror(errno));
		return ccr_fail;
	}
	info("Done");
	return ccr_success;
}

CLI_COMMAND_HANDLER(do_reboot)
{
	struct program_state *state = ctx;
	if (cansys_client_reboot(&state->can_client, get_optional_timeout(args))) {
		error("%s", strerror(errno));
		return ccr_fail;
	}
	info("Done");
	return ccr_success;
}

CLI_COMMAND_HANDLER(do_uptime)
{
	struct program_state *state = ctx;
	uint64_t value;
	if (cansys_client_uptime(&state->can_client, &value, get_optional_timeout(args))) {
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
	struct program_state *state = ctx;
	uint16_t reg = strtol(args->args[1], NULL, 0);
	if (args->argc == 3) {
		uint64_t value = strtoll(args->args[2], NULL, 0);
		if (cansys_client_reg_write(&state->can_client, reg, value, 0)) {
			error("%s", strerror(errno));
			return ccr_fail;
		}
		info("Register %hu <- %ld (0x%010lx)\n", reg, value, value);
		return ccr_success;
	}
	uint64_t value;
	if (cansys_client_reg_read(&state->can_client, reg, &value, 0)) {
		error("%s", strerror(errno));
		return ccr_fail;
	}
	info("Register %hu -> %ld (0x%010lx)\n", reg, value, value);
	return ccr_success;
}

CLI_COMMAND_HANDLER(do_exit)
{
	struct program_state *state = ctx;
	reactor_end(&state->reactor, 0);
	return ccr_success;
}

static const struct cli_command cmds[];

CLI_COMMAND_HANDLER(do_help)
{
	const struct cli_command *cmd = cmds;
	size_t ncmd = (size_t) -1;
	if (args->argc == 2) {
		const char *cmd_name = args->args[1];
		cmd = find_command(cmds, -1, cmd_name);
		if (!cmd) {
			error("Command not found: '%s'", cmd_name);
		}
		ncmd = 1;
	}
	info("HELP");
	info("====");
	for (; ncmd && cmd->command; ncmd--, cmd++) {
		info("\x1b[0mCommand: %s", cmd->command);
		info("\x1b[0mSyntax: %s", cmd->syntax);
		info("\x1b[0mDescription: %s", cmd->description);
		info("\x1b[0mArgument count: %zu-%zu", cmd->min_args, cmd->max_args);
		info("");
	}
	return ccr_success;
}

static const struct cli_command cmds[] = {
	{
		.command = "help",
		.syntax = "help [command]",
		.description = "Get help for command-line interface",
		.min_args = 1,
		.max_args = 2,
		.handler = do_help
	},
	{
		.command = "ident",
		.syntax = "ident [timeout]",
		.description = "Get identity of remote node",
		.min_args = 1,
		.max_args = 2,
		.handler = do_ident
	},
	{
		.command = "ping",
		.syntax = "ping [timeout]",
		.description = "Ping remote node",
		.min_args = 1,
		.max_args = 2,
		.handler = do_ping
	},
	{
		.command = "heartbeat",
		.syntax = "heartbeat <interval-ms>",
		.description = "Change heartbeat interval of remote node (0 to disable)",
		.min_args = 2,
		.max_args = 2,
		.handler = do_set_heartbeat
	},
	{
		.command = "reboot",
		.syntax = "reboot [timeout]",
		.description = "Reboot remote node",
		.min_args = 1,
		.max_args = 2,
		.handler = do_reboot
	},
	{
		.command = "uptime",
		.syntax = "uptime [timeout]",
		.description = "Get uptime of remote node",
		.min_args = 1,
		.max_args = 2,
		.handler = do_uptime
	},
	{
		.command = "reg",
		.syntax = "reg <register> [<value>]",
		.description = "Read or write a register on the remote node",
		.min_args = 2,
		.max_args = 3,
		.handler = do_reg
	},
	{
		.command = "exit",
		.syntax = "exit",
		.description = "Exit the client",
		.min_args = 1,
		.max_args = 1,
		.handler = do_exit
	},
	{ }
};

static void args_next_line(struct arg_builder *args)
{
	if (write(STDOUT_FILENO, "$ ", 2)) { }
	args_reset(args);
}

REACTOR_REACTION(on_stdin)
{
	struct program_state *state = ctx;
	char c;
	if (read(STDIN_FILENO, &c, 1) != 1) {
		sysfail("read");
		return -1;
	}
	enum args_char_action ret = args_char(&state->args, c);
	if (ret == aca_error) {
		args_next_line(&state->args);
	} else if (ret == aca_run) {
		if (state->args.argc == 0 && state->args.argl == 0) {
			args_next_line(&state->args);
			return 0;
		}
		switch (args_execute(&state->args, state, cmds, -1)) {
		case ccr_syntax: error("Syntax error"); break;
		case ccr_fail: error("Command failed"); break;
		case ccr_success: /*info("Success");*/ break;
		}
		args_next_line(&state->args);
	}
	return 0;
}

REACTOR_REACTION(on_can)
{
	struct program_state *state = ctx;
	uint32_t id;
	struct cansys_data msg;
	ssize_t ret;
	if ((ret = canio_read(fd, &id, &msg, sizeof(msg))) < 0) {
		error("canio_read failed: %s", strerror(errno));
		return -1;
	}
	if (cansys_client_is_heartbeat(&state->can_client, &msg, ret)) {
		/* Ignore result in case we have no stdout */
		if (write(STDOUT_FILENO, "\a", 1) < 0) { }
	} else {
		info("Mysterious unexpected packet of length %zu received, perhaps someone else is accessing the server", ret);
	}
	return 0;
}

REACTOR_REACTION(on_signal)
{
	reactor_end(reactor, 0);
	return 0;
}

static int run_loop(struct program_state *state)
{
	int ret = 0;

	if (reactor_init(&state->reactor, 3, state)) {
		callfail("reactor_init");
		return -1;
	}

	if (reactor_bind(&state->reactor, state->signal_fd, NULL, on_signal, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_bind(&state->reactor, STDIN_FILENO, NULL, on_stdin, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_bind(&state->reactor, state->can_fd, NULL, on_can, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_loop(&state->reactor, &ret)) {
		callfail("reactor_loop");
		goto fail;
	}

	goto done;
fail:
	ret = -1;

done:
	reactor_free(&state->reactor);
	return ret;
}

int main(int argc, char *argv[])
{
	int ret = -1;

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

	struct program_state state;
	memset(&state, 0, sizeof(state));

	state.can_fd = -1;
	state.signal_fd = -1;

	if (cansys_client_init(&state.can_client, iface, node_id, TIMEOUT)) {
		callfail("cansys_client_init");
		return 1;
	}

	state.can_fd = state.can_client.fd;

	sigset_t ss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGQUIT);

	state.signal_fd = signalfd(-1, &ss, 0);

	if (state.signal_fd < 0) {
		sysfail("signalfd");
		goto done;
	}

	if (sigprocmask(SIG_BLOCK, &ss, NULL) < 0) {
		sysfail("sigprocmask");
		goto done;
	}

	struct arg_builder args;
	args_next_line(&args);

	ret = run_loop(&state);

done:

	cansys_client_free(&state.can_client);

	close(state.signal_fd);

	if (write(STDOUT_FILENO, "\n", 1)) { }

	return ret;
}
