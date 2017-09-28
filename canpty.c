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

#include <pty.h>
#include <fcntl.h>

#include <sys/signalfd.h>
#include <sys/wait.h>

#include "canio.h"

int max3(int a, int b, int c)
{
	return a > b ? a > c ? a : c : b > c ? b : c;
}

int set_stdin_no_echo(bool enable)
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
		now.c_lflag &= ~(ICANON | ECHO | ECHONL | ECHOCTL);
		now.c_lflag |= ISIG;
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
	int node_id = -1;
	const char *iface = NULL;

	int c;
	while ((c = getopt(argc, argv, "mn:i:")) != -1) {
		switch (c) {
		case 'm': master = true; break;
		case 'n': node_id = atoi(optarg); break;
		case 'i': iface = optarg; break;
		default: error("Invalid argument: '%c'", c); return 1;
		}
	}
	if (node_id < 0 || !iface || optind == argc) {
		error("Syntax: %s [ -m ] -n <node_id> -i <iface> -- ...args", argv[0]);
		return 1;
	}

	int fd = can_socket(iface, node_id, master);
	if (fd < 0) {
		callfail("can_socket");
		return 1;
	}

	sigset_t ss;
	sigemptyset(&ss);
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGCHLD);

	const int sfd = signalfd(-1, &ss, 0);

	if (sfd < 0) {
		sysfail("signalfd");
		return 1;
	}

	if (sigprocmask(SIG_BLOCK, &ss, NULL) < 0) {
		sysfail("sigprocmask");
		return 1;
	}

	int mpty;
	pid_t pid = forkpty(&mpty, NULL, NULL, NULL);
	if (pid < 0) {
		sysfail("forkpty");
		return 1;
	} else if (pid == 0) {
		char **args = argv + optind;
		return execvp(args[0], args);
	}

	info("Launched program with pid=%d", (int) pid);

	set_stdin_no_echo(true);

	bool end = false;
	bool sigchld = false;

	while (true) {
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(mpty, &fds);
		FD_SET(fd, &fds);
		FD_SET(sfd, &fds);
		if (select(max3(mpty, fd, sfd) + 1, &fds, NULL, NULL, NULL) < 0) {
			sysfail("pselect");
			break;
		}
		if (FD_ISSET(sfd, &fds)) {
			struct signalfd_siginfo si;
			if (read(sfd, &si, sizeof(si)) != sizeof(si)) {
				sysfail("read");
				break;
			}
			end = true;
			sigchld = si.ssi_signo == SIGCHLD;
			break;
		}
		if (FD_ISSET(mpty, &fds)) {
			char buf[8];
			ssize_t len;
			if ((len = read(mpty, buf, sizeof(buf))) < 0) {
				sysfail("read");
				break;
			}
			if (len > 0 && can_write(fd, master ? CANIO_STDIN(node_id) : CANIO_STDOUT(node_id), buf, len) < 0) {
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
			if (write(mpty, buf, len) != len) {
				sysfail("write");
				break;
			}
		}
	}

	set_stdin_no_echo(false);

	if (!sigchld) {
		kill(pid, SIGTERM);
		fd_set fds;
		FD_ZERO(&fds);
		FD_SET(sfd, &fds);
		struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
		if (select(sfd + 1, &fds, NULL, NULL, &timeout) <= 0) {
			kill(pid, SIGKILL);
		}
	}
	int ret;
	waitpid(pid, &ret, 0);
	close(mpty);

	close(fd);

	if (WIFEXITED(ret)) {
		info("Child process exited with code %d", WEXITSTATUS(ret));
	} else if (WIFSIGNALED(ret)) {
		info("Child process %s by signal", strsignal(WTERMSIG(ret)));
	}

	return end ? ret : 255;
}
