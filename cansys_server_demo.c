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

#include "canio.h"

#include "cansys.h"

static int max3(int a, int b, int c)
{
	return a > b ? a > c ? a : c : b > c ? b : c;
}

#define NREGS 10

struct server_state
{
	struct timespec boottime;
	uint64_t regs[NREGS];
	int tfd;
};

static int do_set_heartbeat_ms(void *arg, uint64_t *ms)
{
	const struct server_state *ss = arg;
	struct itimerspec ts;
	if (*ms > 60000) {
		*ms = 60000;
	}
	ts.it_value.tv_nsec = 1;
	ts.it_value.tv_sec = 0;
	uint64_t ns = *ms * 1000000;
	ts.it_interval.tv_nsec = ns % 1000000000;
	ts.it_interval.tv_sec = ns / 1000000000;
	if (timerfd_settime(ss->tfd, 0, &ts, NULL) < 0) {
		return -1;
	}
	info("Heartbeat interval changed to %lums", *ms);
	return 0;
}

static int do_reboot(void *arg)
{
	struct server_state *ss = arg;
	info("Mock reboot");
	return clock_gettime(CLOCK_BOOTTIME, &ss->boottime);
}

static int do_uptime_ms(void *arg, uint64_t *out)
{
	const struct server_state *ss = arg;
	info("Mock uptime");
	struct timespec ts;
	if (clock_gettime(CLOCK_BOOTTIME, &ts) != 0) {
		return -1;
	}
	if (ts.tv_nsec < ss->boottime.tv_nsec) {
		ts.tv_sec--;
		ts.tv_nsec += 1000000000;
	}
	ts.tv_sec -= ss->boottime.tv_sec;
	ts.tv_nsec -= ss->boottime.tv_nsec;
	*out = ts.tv_nsec / 1000000 + ts.tv_sec * 1000;
	return 0;
}

static int do_reg_read(void *arg, uint16_t reg, uint64_t *value)
{
	info("Mock reg read %hu", reg);
	const struct server_state *ss = arg;
	if (reg >= NREGS) {
		return -ENOENT;
	}
	*value = ss->regs[reg];
	return 0;
}

static int do_reg_write(void *arg, uint16_t reg, uint64_t *value)
{
	info("Mock reg write %hu <- %ld (%016lx)", reg, *value, *value);
	struct server_state *ss = arg;
	if (reg >= NREGS) {
		return -ENOENT;
	}
	ss->regs[reg] = *value;
	return 0;
}

static struct cansys_adapter adapter = {
	.set_heartbeat_ms = do_set_heartbeat_ms,
	.reboot = do_reboot,
	.uptime = do_uptime_ms,
	.reg_read = do_reg_read,
	.reg_write = do_reg_write
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
	const char *ident = argv[optind++];
	if (node_id < 0 || !iface || optind != argc) {
		error("Syntax: %s -n <node_id> -i <iface> <ident>", argv[0]);
		return 1;
	}

	int fd = canio_socket(iface, node_id, false);
	if (fd < 0) {
		callfail("canio_socket");
		return 1;
	}

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

	const int tfd = timerfd_create(CLOCK_MONOTONIC, 0);

	if (tfd < 0) {
		sysfail("timerfd");
		return 1;
	}

	struct server_state state;
	memset(&state, 0, sizeof(state));
	state.tfd = tfd;
	if (clock_gettime(CLOCK_BOOTTIME, &state.boottime) < 0) {
		sysfail("clock_gettime");
		return 1;
	}

	struct cansys_server server;
	if (cansys_server_init(&server, &adapter, ident, &state)) {
		callfail("cansys_server_init");
		return 1;
	}

	if (termios_stdin_no_echo() < 0) {
		callfail("termios_stdin_no_echo");
	}

	bool end = false;

	while (true) {
		enum fds {
			fd_can,
			fd_signal,
			fd_timer
		};
		struct pollfd pfd[] = {
			[fd_can] = { .fd = fd, .events = POLLIN },
			[fd_signal] = { .fd = sfd, .events = POLLIN },
			[fd_timer] = { .fd = tfd, .events = POLLIN },
		};
		if (poll(pfd, sizeof(pfd) / sizeof(pfd[0]), -1) < 0) {
			sysfail("pselect");
			break;
		}
		if (pfd[fd_signal].revents) {
			end = true;
			break;
		}
		if (pfd[fd_timer].revents) {
			uint64_t hits;
			if (read(tfd, &hits, sizeof(hits)) < 0) {
				sysfail("read");
				break;
			}
			struct cansys_data msg;
			size_t len;
			if (cansys_server_make_heartbeat(&server, &msg, &len) < 0) {
				callfail("cansys_server_make_heartbeat");
				break;
			}
			if (canio_write(fd, CANIO_ID(node_id, CANSYS_CMD_FD), &msg, len) < 0) {
				error("canio_write failed: %s", strerror(errno));
				break;
			}
			info("Heartbeat sent");
		}
		if (pfd[fd_can].revents) {
			uint32_t id;
			struct cansys_data msg;
			ssize_t ret;
			if ((ret = canio_read(fd, &id, &msg, sizeof(msg))) < 0) {
				error("canio_read failed: %s", strerror(errno));
				break;
			}
			size_t len = ret;
			if (cansys_server_handle_message(&server, &msg, &len)) {
				callfail("cansys_server_handle_message");
			}
			if (canio_write(fd, CANIO_ID(node_id, CANSYS_CMD_FD), &msg, len) < 0) {
				error("canio_write failed: %s", strerror(errno));
				break;
			}
		}
	}

	termios_reset();

	cansys_server_free(&server);

	close(tfd);
	close(sfd);
	close(fd);

	return end ? 0 : 1;
}
