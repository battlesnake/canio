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
#include <fcntl.h>
#include <poll.h>

#include <sys/signalfd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>

#include "log.h"
#include "terminal.h"
#include "reactor.h"

#include "canio.h"

#include "canpty.h"

/* Control characters to map to signals if input is a tty */
#define C_SIGINT ''
#define C_SIGQUIT ''
#define C_SIGTSTP ''

#define BUFSIZE 4096

struct program_state
{
	struct reactor reactor;

	int node_id;
	bool master;
	bool forward_signals;
	bool verbose;
	bool has_sub;

	pid_t pid;
	int stdin_fd;
	int stdout_fd;
	int can_stdio_fd;
	int can_ctrl_notify_fd;
	int signal_fd;
	int sigchld_fd;
	int signal_fwd_fd;
};

/* Send signal to remote program */
static int send_signal(struct program_state *state, int signo)
{
	struct cansh_ctrl_signal data = {
		.cmd = cc_signal,
		.signal = signo
	};
	if (canio_write(state->can_stdio_fd, CANIO_ID(state->node_id, CANSH_FD_CTRL), &data, sizeof(data)) < 0) {
		callfail("canio_write");
		return -1;
	}
	return 0;
}

/* Send window-(re)size to remote program */
static int send_resize(struct program_state *state, int width, int height)
{
	struct cansh_ctrl_size data = {
		.cmd = cc_size,
		.width = width,
		.height = height
	};
	if (width < 0) {
		struct winsize w;
		if (ioctl(state->stdin_fd, TIOCGWINSZ, &w) == -1 &&
			ioctl(state->stdout_fd, TIOCGWINSZ, &w) == -1) {
			errno = ENOTTY;
			return -1;
		}
		data.width = w.ws_col;
		data.height = w.ws_row;
	}
	if (canio_write(state->can_stdio_fd, CANIO_ID(state->node_id, CANSH_FD_CTRL), &data, sizeof(data)) < 0) {
		callfail("canio_write");
		return -1;
	}
	return send_signal(state, SIGWINCH);
}

/* Request PID of remote program */
static int request_pid(struct program_state *state)
{
	struct cansh_ctrl_pid data = {
		.cmd = cc_pid
	};
	if (canio_write(state->can_stdio_fd, CANIO_ID(state->node_id, CANSH_FD_CTRL), &data, sizeof(data)) < 0) {
		callfail("canio_write");
		return -1;
	}
	return 0;
}

/* Calculate length of block, translating signals as needed */
static ssize_t calc_write_length_isig(size_t maxlen, const char *buf, size_t buflen, int *sig)
{
	*sig = 0;
	size_t send = 0;
	size_t skip = 0;
	for (size_t i = 0; i < maxlen && i < buflen; i++) {
		switch (buf[i]) {
		case C_SIGINT: *sig = SIGINT; break;
		case C_SIGQUIT: *sig = SIGQUIT; break;
		case C_SIGTSTP: *sig = SIGTSTP; break;
		default: break;
		}
		skip = i + 1;
		send = i + 1;
		if (*sig) {
			send--;
			break;
		}
	}
	return skip;
}

/* Calculate length of block, verbatim */
static ssize_t calc_write_length_raw(size_t maxlen, size_t buflen)
{
	return buflen > maxlen ? maxlen : buflen;
}

/* Handle certain signals */
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
		/* Pass SIGINT to child */
		if (state->has_sub) {
			if (kill(state->pid, SIGINT) == -1) {
				sysfail("kill");
				return -1;
			}
		}
		return 0;
	case SIGTSTP:
		/* Reset terminal, then stop */
		termios_reset();
		if (state->has_sub) {
			if (kill(state->pid, SIGTSTP) == -1) {
				sysfail("kill");
				return -1;
			}
		}
		if (kill(getpid(), SIGSTOP) == -1) {
			sysfail("kill");
			return -1;
		}
		return 0;
	case SIGCONT:
		/* Resume, set terminal */
		termios_stdin_no_echo();
		if (state->has_sub) {
			if (kill(state->pid, SIGCONT) == -1) {
				sysfail("kill");
				return -1;
			}
		}
		return 0;
	case SIGQUIT:
		/* Fall through, exit event-loop */
	default:
		/* Exit event-loop */
		reactor_end(reactor, si.ssi_signo);
		return 0;
	}
}

/* Handle signals which should be forwarded to the remote program */
REACTOR_REACTION(on_signal_fwd)
{
	struct program_state *state = ctx;
	struct signalfd_siginfo si;
	if (read(fd, &si, sizeof(si)) != sizeof(si)) {
		sysfail("read");
		reactor_end(reactor, -1);
		return -1;
	}
	/* Send window size before signal on WINCH */
	if (si.ssi_signo == SIGWINCH && !state->has_sub) {
		if (send_resize(state, -1, -1)) {
			callfail("send_resize");
		}
	}
	if (send_signal(state, si.ssi_signo)) {
		callfail("send_signal");
	}
	return 0;
}

/* Read data from stdin and dispatch */
REACTOR_REACTION(on_stdin_data)
{
	struct program_state *state = ctx;
	char buf[BUFSIZE];
	size_t len;
	if ((ssize_t) (len = read(state->stdin_fd, buf, sizeof(buf))) < 0) {
		sysfail("read");
		return -1;
	}
	uint32_t can_id = state->master ? CANIO_STDIN(state->node_id) : CANIO_STDOUT(state->node_id);
	const char *p = buf;
	/* Process data block by block */
	while (len) {
		size_t sent;
		int sig = 0;
		if (state->forward_signals) {
			/* Write blocks with signal translation */
			if ((ssize_t) (sent = calc_write_length_isig(CAN_DATA_LEN, p, len, &sig)) < 0) {
				callfail("write_isig");
				return -1;
			}
		} else {
			/* Write blocks raw */
			if ((ssize_t) (sent = calc_write_length_raw(CAN_DATA_LEN, len)) < 0) {
				callfail("write_raw");
				return -1;
			}
		}
		if (canio_write(state->can_stdio_fd, can_id, p, sent) < 0) {
			callfail("canio_write");
			return -1;
		}
		/* SIGQUIT ends event loop, is not forwarded to remote program */
		if (sig == SIGQUIT) {
			reactor_end(reactor, sig);
			return 0;
		}
		/* Send translated signals (except SIGQUIT) */
		if (sig && send_signal(state, sig)) {
			callfail("send_signal");
			return -1;
		}
		/* Update iterator */
		p += sent;
		len -= sent;
	}
	return 0;
}

/* Copy data from CAN socket to stdout */
REACTOR_REACTION(on_can_stdio_data)
{
	struct program_state *state = ctx;
	char buf[BUFSIZE];
	uint32_t id;
	ssize_t len;
	if ((len = canio_read(state->can_stdio_fd, &id, buf, sizeof(buf))) < 0) {
		callfail("canio_read");
		return -1;
	}
	if (write(state->stdout_fd, buf, len) != len) {
		sysfail("write");
		return -1;
	}
	return 0;
}

/* Size-validation macro */
#define GET_CC(var) do { \
		if ((size_t) len != sizeof(var)) { \
			error("Invalid control message received (invalid length, %zu != %zu)", len, sizeof(var)); \
			return -1; \
		} \
		memcpy(&var, cc, sizeof(var)); \
	} while (0)

/* Handle commands from control channel */
REACTOR_REACTION(on_can_ctrl_data)
{
	struct program_state *state = ctx;
	char buf[8];
	uint32_t id;
	ssize_t len;
	if ((len = canio_read(state->can_ctrl_notify_fd, &id, buf, sizeof(buf))) < 0) {
		callfail("canio_read");
		return -1;
	}

	const struct cansh_ctrl *cc = (const void *) buf;
	switch (cc->cmd) {
	case cc_pid: {
		struct cansh_ctrl_pid data;
		GET_CC(data);
		if (state->verbose) {
			info("Pid request received from remote");
		}
		if (state->has_sub) {
			struct cansh_notify_pid res = {
				.cmd = cn_pid,
				.pid = state->pid
			};
			if (canio_write(state->can_stdio_fd, CANIO_ID(state->node_id, CANSH_FD_NOTIF), &res, sizeof(res)) < 0) {
				callfail("canio_write");
				return -1;
			}
		}
		break;
	}
	case cc_signal: {
		struct cansh_ctrl_signal data;
		GET_CC(data);
		if (state->verbose) {
			info("Signal received from remote: %d (%s)", data.signal, strsignal(data.signal));
		}
		if (state->has_sub) {
			if (kill(state->pid, data.signal) == -1) {
				sysfail("kill");
				return -1;
			}
		}
		break;
	}
	case cc_size: {
		struct cansh_ctrl_size data;
		GET_CC(data);
		if (state->verbose) {
			info("Window resize notification from remote: %hux%hu", data.width, data.height);
		}
		break;
	}
	default:
		if (state->verbose) {
			error("Unknown control message received (command=0x%02hhx, arg=0x%02hhx)", cc->cmd, cc->arg);
		}
		break;
	}
	return 0;
}

/* Handle notifications from notification channel */
REACTOR_REACTION(on_can_notify_data)
{
	struct program_state *state = ctx;
	char buf[8];
	uint32_t id;
	ssize_t len;
	if ((len = canio_read(state->can_ctrl_notify_fd, &id, buf, sizeof(buf))) < 0) {
		callfail("canio_read");
		return -1;
	}

	const struct cansh_ctrl *cc = (const void *) buf;
	switch (cc->cmd) {
	case cn_pid: {
		struct cansh_notify_pid data;
		GET_CC(data);
		if (state->verbose) {
			info("Pid response received from remote: pid=%d", (int) data.pid);
		}
		/* Send window size */
		if (state->master && isatty(state->stdin_fd)) {
			send_resize(state, -1, -1);
		}
		break;
	case cn_exit: {
		struct cansh_notify_exit data;
		GET_CC(data);
		if (state->verbose) {
			if (WIFEXITED(data.status)) {
				info("Remote process exited with code %d", WEXITSTATUS(data.status));
			} else if (WIFSIGNALED(data.status)) {
				info("Remote process ended by signal: %d (%s)", WTERMSIG(data.status), strsignal(WTERMSIG(data.status)));
			} else {
				info("Remote process exited, exit status = %d", data.status);
			}
		}
		break;
	}
	}
	default:
		if (state->verbose) {
			error("Unknown notification message received (notification=0x%02hhx, arg=0x%02hhx)", cc->cmd, cc->arg);
		}
		break;
	}
	return 0;
}

#undef GET_CC

/* Set CLOEXEC on descriptor */
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

/* Main event-loop */
static int run_loop(struct program_state *state)
{
	int ret = 0;

	if (reactor_init(&state->reactor, 7, state)) {
		callfail("reactor_init");
		return -1;
	}

	if (reactor_bind(&state->reactor, state->signal_fd, NULL, on_signal, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_bind(&state->reactor, state->sigchld_fd, NULL, on_signal, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_bind(&state->reactor, state->signal_fwd_fd, NULL, on_signal_fwd, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_bind(&state->reactor, state->can_stdio_fd, NULL, on_can_stdio_data, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_bind(&state->reactor, state->can_ctrl_notify_fd, NULL, state->master ? on_can_notify_data : on_can_ctrl_data, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_bind(&state->reactor, state->stdin_fd, NULL, on_stdin_data, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_loop(&state->reactor, &ret) && errno) {
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
	log_plain("Syntax: %s [ -m | -M ] [-v] -n <node_id> -i <iface> [ -- args... ]", argv0);
	log_plain("");
	log_plain("      -m        Master mode");
	log_plain("      -M        Master mode with signal forwarding (SIGQUIT ^\\ to exit)");
	log_plain("      -v        Log control/notification/subprocess messages");
	log_plain("      -n id     Set slave ID to use / to connect to");
	log_plain("      -i iface  Set network interface to use");
	log_plain("    args...     Execute a program and pipe it's STDIO");
	log_plain("");
}

int main(int argc, char *argv[])
{
	int ret = 255;
	int child_result = -1;

	/* Defaults */
	struct program_state state;
	memset(&state, 0, sizeof(state));
	state.pid = -1;
	state.stdin_fd = -1;
	state.stdout_fd = -1;
	state.can_stdio_fd = -1;
	state.can_ctrl_notify_fd = -1;
	state.signal_fd = -1;
	state.verbose = false;
	state.node_id = -1;
	state.master = false;
	state.forward_signals = false;

	int p0[2] = { -1, -1 };
	int p1[2] = { -1, -1 };

	const char *iface = NULL;
	char **sub_argv = NULL;
	int sub_argc = 0;

	/* Process parameters */
	int c;
	while ((c = getopt(argc, argv, "hmMvn:i:")) != -1) {
		switch (c) {
		case 'h': show_syntax(argv[0]); return 0;
		case 'M': state.forward_signals = true; /* fall-thru */
		case 'm': state.master = true; break;
		case 'v': state.verbose = true; break;
		case 'n': state.node_id = atoi(optarg); break;
		case 'i': iface = optarg; break;
		default: error("Invalid argument: '%c'", c); return 1;
		}
	}
	state.has_sub = optind != argc;
	if (state.has_sub) {
		sub_argv = argv + optind;
		sub_argc = argc - optind;
	}
	if (state.node_id < 0 || !iface) {
		error("Invalid arguments");
		show_syntax(argv[0]);
		return 1;
	}

	/* Warn when enabling signal processing for non-TTY input */
	if (state.forward_signals && (!isatty(STDIN_FILENO) || state.has_sub) && state.verbose) {
		warn("Signal forwarding is enabled but input is not a TTY");
	}

	/* Open CAN stdio and notification channels */

	state.can_stdio_fd = canio_socket(iface, state.node_id, state.master ? 1 : 0);
	if (state.can_stdio_fd < 0) {
		callfail("canio_socket");
		return 1;
	}
	set_cloexec(state.can_stdio_fd);

	state.can_ctrl_notify_fd = canio_socket(iface, state.node_id, state.master ? CANSH_FD_NOTIF : CANSH_FD_CTRL);
	if (state.can_stdio_fd < 0) {
		callfail("canio_socket");
		return 1;
	}
	set_cloexec(state.can_ctrl_notify_fd);

	sigset_t ss;

	/* Signal handler for INT/TERM/QUIT/TSTP/CONT */
	sigemptyset(&ss);
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGQUIT);
	sigaddset(&ss, SIGTSTP);
	sigaddset(&ss, SIGCONT);
	sigaddset(&ss, SIGINT);

	state.signal_fd = signalfd(-1, &ss, 0);
	if (state.signal_fd < 0) {
		sysfail("signalfd");
		goto done;
	}
	set_cloexec(state.signal_fd);

	/* Signal forwarder for USR1/USR2/WINCH */
	sigemptyset(&ss);
	sigaddset(&ss, SIGUSR1);
	sigaddset(&ss, SIGUSR2);
	if (state.master) {
		sigaddset(&ss, SIGWINCH);
	}

	state.signal_fwd_fd = signalfd(-1, &ss, 0);
	if (state.signal_fwd_fd < 0) {
		sysfail("signalfd");
		goto done;
	}
	set_cloexec(state.signal_fwd_fd);

	/* SIGCHLD receiver */
	sigemptyset(&ss);
	sigaddset(&ss, SIGCHLD);

	state.sigchld_fd = signalfd(-1, &ss, 0);
	if (state.sigchld_fd < 0) {
		sysfail("signalfd");
		goto done;
	}
	set_cloexec(state.sigchld_fd);

	/* Block signals which we handle via signalfd */
	sigemptyset(&ss);
	sigaddset(&ss, SIGTERM);
	sigaddset(&ss, SIGQUIT);
	sigaddset(&ss, SIGTSTP);
	sigaddset(&ss, SIGCONT);
	sigaddset(&ss, SIGINT);
	sigaddset(&ss, SIGUSR1);
	sigaddset(&ss, SIGUSR2);
	sigaddset(&ss, SIGWINCH);
	sigaddset(&ss, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &ss, NULL) < 0) {
		sysfail("sigprocmask");
		goto done;
	}

	/* Put terminal in character mode */
	if (isatty(STDIN_FILENO) && termios_stdin_char_mode(!state.forward_signals) < 0) {
		callfail("termios_stdin_char_mode");
		goto done;
	}

	/* If subprocess was specified, fork it and set up stdio pipes */
	if (sub_argc) {
		if (pipe(p0) || pipe(p1)) {
			sysfail("pipe");
			goto done;
		}
		state.pid = fork();
		if (state.pid == -1) {
			sysfail("fork");
			goto done;
		} else if (state.pid == 0) {
			/* Set up stdio pipes */
			if (dup2(p0[0], STDIN_FILENO) < 0 || dup2(p1[1], STDOUT_FILENO) < 0) {
				sysfail("dup2");
				goto done;
			}
			close(p0[0]);
			close(p0[1]);
			close(p1[0]);
			close(p1[1]);
			/* Unblock signals */
			sigset_t empty;
			sigemptyset(&empty);
			if (sigprocmask(SIG_SETMASK, &empty, NULL) < 0) {
				sysfail("sigprocmask");
				goto done;
			}
			/* Exec */
			execvp(sub_argv[0], sub_argv);
			sysfail("execv");
			exit(255);
		}
		if (state.verbose) {
			info("Launched program with pid=%d", (int) state.pid);
		}
		state.stdin_fd = p1[0];
		state.stdout_fd = p0[1];
		close(p0[0]);
		close(p1[1]);
	} else {
		/* If not using subprocess, use default stdio */
		state.stdin_fd = STDIN_FILENO;
		state.stdout_fd = STDOUT_FILENO;
	}

	if (state.master) {
		/* If we're a master, request PID */
		request_pid(&state);
		/*
		 * Receiving a PID triggers sending of window size if we're a
		 * master, so the remote will fit in our terminal
		 */
	} else if (state.has_sub) {
		/* Send PID notification */
		struct cansh_notify_pid cmd = {
			.cmd = cn_pid,
			.pid = state.pid,
		};
		if (canio_write(state.can_stdio_fd, CANIO_ID(state.node_id, CANSH_FD_NOTIF), &cmd, sizeof(cmd)) < 0) {
			callfail("canio_write");
		}
	}

	/* Result is negative on error or signal which ended event-loop */
	int loop_result = run_loop(&state);
	if (loop_result < 0) {
		callfail("run_loop");
	}

	ret = 0;

	/* If we don't have a subprocess, skip the clean-up */
	if (!state.has_sub) {
		goto done;
	}

	/* If child's exit didn't end the loop, kill the child */
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

	/* Log exit status */
	if (state.verbose) {
		if (WIFEXITED(child_result)) {
			info("Child process exited with code %d", WEXITSTATUS(child_result));
		} else if (WIFSIGNALED(child_result)) {
			info("Child process %s by signal", strsignal(WTERMSIG(child_result)));
		}
	}

	/* Send exit notification */
	struct cansh_notify_exit res = {
		.cmd = cn_exit,
		.status = child_result
	};
	if (!state.master && canio_write(state.can_stdio_fd, CANIO_ID(state.node_id, CANSH_FD_NOTIF), &res, sizeof(res)) < 0) {
		callfail("canio_write");
	}

done:
	if (isatty(STDIN_FILENO)) {
		termios_reset();
	}

	close(state.signal_fwd_fd);
	close(state.signal_fd);
	close(state.can_ctrl_notify_fd);
	close(state.can_stdio_fd);
	close(state.stdin_fd);
	close(state.stdout_fd);

	return ret;
}
