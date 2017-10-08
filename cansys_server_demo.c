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
#include <sys/timerfd.h>

#include "log.h"
#include "terminal.h"
#include "reactor.h"

#include "canio.h"

#include "cansys.h"

#define NREGS 10

struct program_state
{
	struct reactor reactor;

	struct cansys_server server;
	uint32_t can_id;

	struct timespec boottime;
	uint64_t regs[NREGS];

	int can_fd;
	int signal_fd;
	int heartbeat_fd;
};

static int set_heartbeat_interval(const struct program_state *state, uint64_t ms)
{
	struct itimerspec ts;
	ts.it_value.tv_nsec = ms ? 1 : 0;
	ts.it_value.tv_sec = 0;
	uint64_t ns = ms * 1000000;
	ts.it_interval.tv_nsec = ns % 1000000000;
	ts.it_interval.tv_sec = ns / 1000000000;
	if (timerfd_settime(state->heartbeat_fd, 0, &ts, NULL) < 0) {
		sysfail("timerfd_settime");
		return -1;
	}
	return 0;
}

static int do_set_heartbeat_ms(void *arg, uint64_t *ms)
{
	const struct program_state *state = arg;
	if (*ms != 0 && *ms < 100) {
		*ms = 100;
	} else if (*ms > 60000) {
		*ms = 60000;
	}
	if (set_heartbeat_interval(state, *ms)) {
		callfail("set_heartbeat_interval");
		return -1;
	}
	info("Heartbeat interval changed to %lums", ms ? *ms : 0);
	return 0;
}

static int do_reboot(void *arg)
{
	struct program_state *state = arg;
	info("Mock reboot");
	set_heartbeat_interval(arg, 0);
	return clock_gettime(CLOCK_BOOTTIME, &state->boottime);
}

static int do_uptime_ms(void *arg, uint64_t *out)
{
	const struct program_state *state = arg;
	info("Mock uptime");
	struct timespec ts;
	if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) {
		return -1;
	}
	if (ts.tv_nsec < state->boottime.tv_nsec) {
		ts.tv_sec--;
		ts.tv_nsec += 1000000000;
	}
	ts.tv_sec -= state->boottime.tv_sec;
	ts.tv_nsec -= state->boottime.tv_nsec;
	*out = ts.tv_nsec / 1000000 + ts.tv_sec * 1000;
	return 0;
}

static int do_reg_read(void *arg, uint16_t reg, uint64_t *value)
{
	info("Mock reg read %hu", reg);
	const struct program_state *state = arg;
	if (reg >= NREGS) {
		return -ENOENT;
	}
	*value = state->regs[reg];
	return 0;
}

static int do_reg_write(void *arg, uint16_t reg, uint64_t *value)
{
	info("Mock reg write %hu <- %ld (%016lx)", reg, *value, *value);
	struct program_state *state = arg;
	if (reg >= NREGS) {
		return -ENOENT;
	}
	state->regs[reg] = *value;
	return 0;
}

static struct cansys_adapter adapter = {
	.set_heartbeat_ms = do_set_heartbeat_ms,
	.reboot = do_reboot,
	.uptime = do_uptime_ms,
	.reg_read = do_reg_read,
	.reg_write = do_reg_write
};

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
	size_t len = ret;
	if (cansys_server_handle_message(&state->server, &msg, &len)) {
		callfail("cansys_server_handle_message");
	}
	if (canio_write(fd, state->can_id, &msg, len) < 0) {
		error("canio_write failed: %s", strerror(errno));
		return -1;
	}
	return 0;
}

REACTOR_REACTION(on_signal)
{
	info("signal");
	reactor_end(reactor, 0);
	return 0;
}

REACTOR_REACTION(on_heartbeat)
{
	struct program_state *state = ctx;
	uint64_t hits;
	if (read(state->heartbeat_fd, &hits, sizeof(hits)) < 0) {
		sysfail("read");
		return -1;
	}
	struct cansys_data msg;
	size_t len;
	if (cansys_server_make_heartbeat(&state->server, &msg, &len) < 0) {
		callfail("cansys_server_make_heartbeat");
		return -1;
	}
	if (canio_write(state->can_fd, state->can_id, &msg, len) < 0) {
		error("canio_write failed: %s", strerror(errno));
		return -1;
	}
	info("Heartbeat sent");
	return 0;
}

int run_loop(struct program_state *state)
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

	if (reactor_bind(&state->reactor, state->heartbeat_fd, NULL, on_heartbeat, NULL, NULL)) {
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
	const char *ident = argv[optind++];
	if (node_id < 0 || !iface || optind != argc) {
		error("Syntax: %s -n <node_id> -i <iface> <ident>", argv[0]);
		return 1;
	}

	struct program_state state;
	memset(&state, 0, sizeof(state));

	state.can_fd = -1;
	state.signal_fd = -1;
	state.heartbeat_fd = -1;

	state.can_fd = canio_socket(iface, node_id, false);
	if (state.can_fd < 0) {
		callfail("canio_socket");
		return 1;
	}

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

	state.heartbeat_fd = timerfd_create(CLOCK_MONOTONIC, 0);

	if (state.heartbeat_fd < 0) {
		sysfail("timerfd");
		goto done;
	}

	if (clock_gettime(CLOCK_BOOTTIME, &state.boottime) < 0) {
		sysfail("clock_gettime");
		goto done;
	}

	if (cansys_server_init(&state.server, &adapter, ident, &state)) {
		callfail("cansys_server_init");
		goto done;
	}

	if (termios_stdin_no_echo() < 0) {
		callfail("termios_stdin_no_echo");
	}

	state.can_id = CANIO_ID(node_id, CANSYS_CMD_FD);

	ret = run_loop(&state);

done:

	termios_reset();

	cansys_server_free(&state.server);

	close(state.heartbeat_fd);
	close(state.signal_fd);
	close(state.can_fd);

	if (write(STDOUT_FILENO, "\n", 1)) { }

	return ret;
}
