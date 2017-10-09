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

#include <pty.h>
#include <fcntl.h>

#include <sys/signalfd.h>
#include <sys/wait.h>

#include "log.h"
#include "terminal.h"
#include "reactor.h"

#include "canio.h"

#include "canpty.h"

#define CHILD_KILL_TIMEOUT 1000

struct program_state
{
	struct reactor reactor;

	int node_id;
	bool master;

	int pty_fd;

	int can_stdio_fd;
	int can_ctrl_fd;
	int signal_fd;
	int sigchld_fd;

	pid_t pid;

	bool sigchld;
};

static int set_pty_size(struct program_state *state, int width, int height)
{
	struct winsize pty_size;
	memset(&pty_size, 0, sizeof(pty_size));
	pty_size.ws_col = width;
	pty_size.ws_row = height;
	if (ioctl(state->pty_fd, TIOCSWINSZ, &pty_size) == -1) {
		sysfail("ioctl(TIOCSWINSZ)");
		return -1;
	}
	return 0;
}

REACTOR_REACTION(on_signal)
{
	struct program_state *state = ctx;
	struct signalfd_siginfo si;
	if (read(fd, &si, sizeof(si)) != sizeof(si)) {
		sysfail("read");
		reactor_end(reactor, -1);
		return -1;
	}
	switch (si.ssi_signo) {
	case SIGINT:
		/* Forward SIGINT to child process */
		if (kill(state->pid, SIGINT) == -1) {
			sysfail("kill(SIGINT)");
			return -1;
		}
		return 0;
	case SIGTSTP:
		/* Reset terminal, then stop */
		termios_reset();
		if (kill(state->pid, SIGTSTP) == -1) {
			sysfail("kill(SIGTSTP)");
			return -1;
		}
		if (kill(getpid(), SIGSTOP) == -1) {
			sysfail("kill(SIGSTOP)");
			return -1;
		}
		return 0;
	case SIGCONT:
		/* Resume, set terminal */
		termios_stdin_no_echo();
		if (kill(state->pid, SIGCONT) == -1) {
			sysfail("kill(SIGCONT)");
			return -1;
		}
		if (kill(state->pid, SIGWINCH) == -1) {
			sysfail("kill(SIGWINCH)");
			return -1;
		}
		return 0;
	default:
		/* Other signals (SIGTERM / SIGCHLD) end the message loop */
		reactor_end(reactor, si.ssi_signo);
		return 0;
	}
}

REACTOR_REACTION(on_pty_data)
{
	struct program_state *state = ctx;
	char buf[8];
	ssize_t len;
	if ((len = read(state->pty_fd, buf, sizeof(buf))) < 0) {
		sysfail("read");
		return -1;
	}
	if (len > 0 && canio_write(state->can_stdio_fd, state->master ? CANIO_STDIN(state->node_id) : CANIO_STDOUT(state->node_id), buf, len) < 0) {
		callfail("canio_write");
		return -1;
	}
	return 0;
}

REACTOR_REACTION(on_can_stdio_data)
{
	struct program_state *state = ctx;
	char buf[8];
	uint32_t id;
	ssize_t len;
	if ((len = canio_read(state->can_stdio_fd, &id, buf, sizeof(buf))) < 0) {
		callfail("canio_read");
		return -1;
	}
	if (write(state->pty_fd, buf, len) != len) {
		sysfail("write");
		return -1;
	}
	return 0;
}

REACTOR_REACTION(on_can_ctrl_data)
{
	struct program_state *state = ctx;
	char buf[8];
	uint32_t id;
	ssize_t len;
	if ((len = canio_read(state->can_ctrl_fd, &id, buf, sizeof(buf))) < 0) {
		callfail("canio_read");
		return -1;
	}
	const struct cansh_ctrl *cc = (const void *) buf;

#define GET_CC(var) do { \
		if ((size_t) len != sizeof(var)) { \
			error("Invalid control message received (invalid length, %zu != %zu)", len, sizeof(var)); \
			return -1; \
		} \
		memcpy(&var, cc, sizeof(var)); \
	} while (0)

	switch (cc->cmd) {
	case cc_signal: {
		struct cansh_ctrl_signal data;
		GET_CC(data);
		if (kill(state->pid, data.signal) == -1) {
			sysfail("kill");
			return -1;
		}
		break;
	}
	case cc_exit: {
		break;
	}
	case cc_size: {
		struct cansh_ctrl_size data;
		GET_CC(data);
		if (set_pty_size(state, data.width, data.height)) {
			callfail("set_pty_size");
			return -1;
		}
		break;
	}
	default:
		error("Unknown control message received (command=0x%02hhx, arg=0x%02hhx)", cc->cmd, cc->arg);
		return -1;
	}
#undef GET_CC
	return 0;
}

static int set_cloexec(int fd)
{
	if (fd == -1) {
		return 0;
	}
	if (fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC) == -1) {
		sysfail("fcntl");
		return -1;
	}
	return 0;
}

static int run_loop(struct program_state *state)
{
	int ret = 0;

	if (reactor_init(&state->reactor, 5, state)) {
		callfail("reactor_init");
		return -1;
	}

	if (reactor_bind(&state->reactor, state->sigchld_fd, NULL, on_signal, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_bind(&state->reactor, state->signal_fd, NULL, on_signal, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_bind(&state->reactor, state->can_ctrl_fd, NULL, on_can_ctrl_data, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_bind(&state->reactor, state->can_stdio_fd, NULL, on_can_stdio_data, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_bind(&state->reactor, state->pty_fd, NULL, on_pty_data, NULL, NULL)) {
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

static void show_syntax(const char *argv0)
{
	info("Syntax: %s [-m] -n <node_id> -i <iface> -- <args>...", argv0);
	info("");
	info("      -m        Master mode");
	info("      -n id     Set slave ID to use / to connect to");
	info("      -i iface  Set network interface to use");
	info("    args...     Program to execute");
	info("");
}

int main(int argc, char *argv[])
{
	int ret = 255;
	int child_result = -1;

	struct program_state state;
	memset(&state, 0, sizeof(state));
	state.master = false;
	state.node_id = -1;
	state.pty_fd = -1;
	state.can_stdio_fd = -1;
	state.can_ctrl_fd = -1;
	state.pid = -1;

	const char *iface = NULL;

	int c;
	while ((c = getopt(argc, argv, "hmn:i:")) != -1) {
		switch (c) {
		case 'h': show_syntax(argv[0]); return 0;
		case 'm': state.master = true; break;
		case 'n': state.node_id = atoi(optarg); break;
		case 'i': iface = optarg; break;
		default: error("Invalid argument: '%c'", c); return 1;
		}
	}
	if (state.node_id < 0 || !iface || optind == argc) {
		error("Invalid arguments");
		show_syntax(argv[0]);
		return 1;
	}

	state.can_stdio_fd = canio_socket(iface, state.node_id, state.master ? 1 : 0);
	if (state.can_stdio_fd < 0) {
		callfail("canio_socket");
		goto done;
	}

	if (!state.master) {
		state.can_ctrl_fd = canio_socket(iface, state.node_id, 3);
		if (state.can_ctrl_fd < 0) {
			callfail("canio_socket");
			goto done;
		}
	}

	sigset_t ss;

	/* SIGTERM/SIGINT/SIGQUIT/SIGTSTP/SIGCONT receiver */
	sigemptyset(&ss);
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGQUIT);
	sigaddset(&ss, SIGTSTP);
	sigaddset(&ss, SIGCONT);

	state.signal_fd = signalfd(-1, &ss, 0);
	if (state.signal_fd < 0) {
		sysfail("signalfd");
		goto done;
	}

	/* SIGCHLD receiver */
	sigemptyset(&ss);
	sigaddset(&ss, SIGCHLD);

	state.sigchld_fd = signalfd(-1, &ss, 0);
	if (state.sigchld_fd < 0) {
		sysfail("signalfd");
		goto done;
	}

	/* Set FD_CLOEXEC */
	set_cloexec(state.can_ctrl_fd);
	set_cloexec(state.can_stdio_fd);
	set_cloexec(state.signal_fd);
	set_cloexec(state.sigchld_fd);

	/* Block signals which we want to handle via signalfd */
	sigemptyset(&ss);
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGQUIT);
	sigaddset(&ss, SIGTSTP);
	sigaddset(&ss, SIGCONT);
	sigaddset(&ss, SIGCHLD);

	sigset_t oss;
	if (sigprocmask(SIG_BLOCK, &ss, &oss) < 0) {
		sysfail("sigprocmask");
		goto done;
	}

	/* Child process */
	struct winsize pty_size;
	memset(&pty_size, 0, sizeof(pty_size));
	pty_size.ws_col = 80;
	pty_size.ws_row = 25;
	state.pid = forkpty(&state.pty_fd, NULL, NULL, &pty_size);
	if (state.pid < 0) {
		sysfail("forkpty");
		goto done;
	} else if (state.pid == 0) {
		/* Unblock signals in child process */
		if (sigprocmask(SIG_SETMASK, &oss, NULL) < 0) {
			sysfail("sigprocmask");
			goto done;
		}
		char **args = argv + optind;
		return execvp(args[0], args);
	}

	info("Launched program with pid=%d", (int) state.pid);

	/* Disable echo, since we don't use the terminal at all */
	termios_stdin_no_echo();

	int loop_result = run_loop(&state);

	if (loop_result == -1) {
		callfail("run_loop");
	}

	/* Close pty */
	close(state.pty_fd);
	state.pty_fd = -1;

	if (loop_result != SIGCHLD) {
		/* Terminate, kill after timeout if not dead */
		if (kill(state.pid, SIGTERM) == -1) {
			sysfail("kill");
		}
		struct pollfd pfd = { .fd = state.sigchld_fd, .events = POLLIN };
		if (poll(&pfd, 1, CHILD_KILL_TIMEOUT) <= 0) {
			if (kill(state.pid, SIGKILL) == -1) {
				sysfail("kill");
			}
		}
	}

	/* Reap process and get exit code */
	if (waitpid(state.pid, &child_result, 0) == -1) {
		sysfail("waitpid");
		goto done;
	}

	ret = child_result;

done:
	termios_reset();

	close(state.pty_fd);
	close(state.signal_fd);
	close(state.can_ctrl_fd);
	close(state.can_stdio_fd);

	if (child_result < 0) {
		error("Failed");
		return ret;
	}

	if (WIFEXITED(child_result)) {
		info("Child process exited with code %d", WEXITSTATUS(child_result));
	} else if (WIFSIGNALED(child_result)) {
		info("Child process %s by signal", strsignal(WTERMSIG(child_result)));
	}
	return child_result;
}
