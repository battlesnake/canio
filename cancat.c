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

#include <sys/signalfd.h>

#include "canio.h"

int set_stdin_char_mode(bool enable, bool signals)
{
	static struct termios old;
	static bool first = true;
	if (first) {
		if (tcgetattr(STDIN_FILENO, &old) < 0) {
			sysfail("tcgetattr");
			return -1;
		}
		first = false;
	}
	struct termios now = old;
	if (enable) {
		now.c_lflag &= ~(ICANON | ECHO | ECHOCTL | ISIG);
		if (signals) {
			now.c_lflag |= ISIG;
		}
		now.c_cc[VMIN] = 1;
		now.c_cc[VTIME] = 2;
	}
	if (tcsetattr(STDIN_FILENO, TCSANOW, &now) < 0) {
		sysfail("tcsetattr");
		return -1;
	}
	return 0;
}

int main(int argc, char *argv[])
{
	bool master = false;
	bool signals = true;
	int node_id = -1;
	const char *iface = NULL;

	int c;
	while ((c = getopt(argc, argv, "mMn:i:")) != -1) {
		switch (c) {
		case 'm': master = true; break;
		case 'M': master = true; signals = false; break;
		case 'n': node_id = atoi(optarg); break;
		case 'i': iface = optarg; break;
		default: error("Invalid argument: '%c'", c); return 1;
		}
	}
	if (node_id < 0 || !iface || optind != argc) {
		error("Syntax: %s [ -m | -M ] -n <node_id> -i <iface>", argv[0]);
		return 1;
	}

	int fd = can_socket(iface, node_id, master);
	if (fd < 0) {
		callfail("can_socket");
		return 1;
	}

	if (!signals) {
		warn("Signal translation disabled - to terminate cancat send SIGTERM from another program, e.g. bash: kill %d", (int) getpid());
	}

	if (set_stdin_char_mode(true, signals) < 0) {
		callfail("set_stdin_char_mode");
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

	bool end = false;

	while (true) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(STDIN_FILENO, &fds);
		FD_SET(fd, &fds);
		FD_SET(sfd, &fds);
		if (pselect((fd > sfd ? fd : sfd) + 1, &fds, NULL, NULL, NULL, NULL) < 0) {
			sysfail("pselect");
			break;
		}
		if (FD_ISSET(sfd, &fds)) {
			end = true;
			break;
		}
		if (FD_ISSET(STDIN_FILENO, &fds)) {
			char c;
			if (read(STDIN_FILENO, &c, sizeof(c)) != sizeof(c)) {
				sysfail("read");
				break;
			}
			if (can_write(fd, master ? CAN_ID_STDIN(node_id) : CAN_ID_STDOUT(node_id), &c, sizeof(c)) < 0) {
				callfail("can_write");
				break;
			}
		}
		if (FD_ISSET(fd, &fds)) {
			char buf[8];
			uint32_t id;
			ssize_t len;
			if ((len = can_read(fd, &id, buf, sizeof(buf))) < 0) {
				callfail("can_read");
				break;
			}
			if (write(STDOUT_FILENO, buf, len) != len) {
				sysfail("write");
				break;
			}
		}
	}

	set_stdin_char_mode(false, true);

	close(fd);

	if (write(STDOUT_FILENO, "\n", 1)) { }

	return end ? 0 : 1;
}
