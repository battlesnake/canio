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
#include <sys/ioctl.h>

#include "log.h"
#include "terminal.h"
#include "reactor.h"

#include "canio.h"

#include "canpty.h"

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
	bool show_control;

	int can_stdio_fd;
	int can_ctrl_fd;
	int signal_fd;
	int signal_fwd_fd;
};

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

static int send_resize(struct program_state *state, int width, int height)
{
	struct cansh_ctrl_size data = {
		.cmd = cc_size,
		.width = width,
		.height = height
	};
	if (width < 0) {
		struct winsize w;
		if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == -1 &&
			ioctl(STDIN_FILENO, TIOCGWINSZ, &w) == -1) {
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

static ssize_t calc_write_length_isig(size_t maxlen, const char *buf, size_t buflen, int *sig)
{
	/* Calculate length of block, translating signals as needed */
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

static ssize_t calc_write_length_raw(size_t maxlen, size_t buflen)
{
	/* Calculate length of block, verbatim */
	return buflen > maxlen ? maxlen : buflen;
}

REACTOR_REACTION(on_signal)
{
	struct signalfd_siginfo si;
	if (read(fd, &si, sizeof(si)) != sizeof(si)) {
		sysfail("read");
		reactor_end(reactor, -1);
		return -1;
	}
	switch (si.ssi_signo) {
	case SIGTSTP:
		/* Reset terminal, then stop */
		termios_reset();
		if (kill(getpid(), SIGSTOP) == -1) {
			sysfail("kill");
			return -1;
		}
		return 0;
	case SIGCONT:
		/* Resume, set terminal */
		termios_stdin_no_echo();
		return 0;
	default:
		reactor_end(reactor, si.ssi_signo);
		return 0;
	}
}

REACTOR_REACTION(on_signal_fwd)
{
	struct program_state *state = ctx;
	struct signalfd_siginfo si;
	if (read(fd, &si, sizeof(si)) != sizeof(si)) {
		sysfail("read");
		reactor_end(reactor, -1);
		return -1;
	}
	if (si.ssi_signo == SIGWINCH) {
		if (send_resize(state, -1, -1)) {
			callfail("send_resize");
		}
	}
	if (send_signal(state, si.ssi_signo)) {
		callfail("send_signal");
	}
	return 0;
}

REACTOR_REACTION(on_stdin_data)
{
	struct program_state *state = ctx;
	char buf[BUFSIZE];
	size_t len;
	if ((ssize_t) (len = read(STDIN_FILENO, buf, sizeof(buf))) < 0) {
		sysfail("read");
		return -1;
	}
	const char *p = buf;
	uint32_t can_id = state->master ? CANIO_STDIN(state->node_id) : CANIO_STDOUT(state->node_id);
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
		if (sig == SIGQUIT) {
			reactor_end(reactor, sig);
			return 0;
		}
		if (sig && send_signal(state, sig)) {
			callfail("send_signal");
			return -1;
		}
		p += sent;
		len -= sent;
	}
	return 0;
}

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
	if (write(STDOUT_FILENO, buf, len) != len) {
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
	if (!state->show_control) {
		return 0;
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
		info("Signal received from remote: %d (%s)", data.signal, strsignal(data.signal));
		break;
	}
	case cc_exit: {
		struct cansh_ctrl_exit data;
		GET_CC(data);
		if (WIFEXITED(data.status)) {
			info("Remote process exited with code %d", WEXITSTATUS(data.status));
		} else if (WIFSIGNALED(data.status)) {
			info("Remote process ended by signal: %d (%s)", WTERMSIG(data.status), strsignal(WTERMSIG(data.status)));
		} else {
			info("Remote process exited, exit status = %d", data.status);
		}
		break;
	}
	case cc_size: {
		struct cansh_ctrl_size data;
		GET_CC(data);
		info("Window resize notification from remote: %hux%hu", data.width, data.height);
		break;
	}
	default:
		error("Unknown control message received (command=0x%02hhx, arg=0x%02hhx)", cc->cmd, cc->arg);
		break;
	}
#undef GET_CC
	return 0;
}

static int run_loop(struct program_state *state)
{
	int ret = 0;

	if (reactor_init(&state->reactor, 6, state)) {
		callfail("reactor_init");
		return -1;
	}

	if (reactor_bind(&state->reactor, state->signal_fd, NULL, on_signal, NULL, NULL)) {
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

	if (reactor_bind(&state->reactor, state->can_ctrl_fd, NULL, on_can_ctrl_data, NULL, NULL)) {
		callfail("reactor_bind");
		goto fail;
	}

	if (reactor_bind(&state->reactor, STDIN_FILENO, NULL, on_stdin_data, NULL, NULL)) {
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
	int ret = 255;

	struct program_state state;
	memset(&state, 0, sizeof(state));
	state.can_stdio_fd = -1;
	state.can_ctrl_fd = -1;
	state.signal_fd = -1;
	state.show_control = true;
	state.node_id = -1;
	state.master = false;
	state.forward_signals = false;

	const char *iface = NULL;

	int c;
	while ((c = getopt(argc, argv, "mMqn:i:")) != -1) {
		switch (c) {
		case 'M': state.forward_signals = true; /* fall-thru */
		case 'm': state.master = true; break;
		case 'q': state.show_control = false; break;
		case 'n': state.node_id = atoi(optarg); break;
		case 'i': iface = optarg; break;
		default: error("Invalid argument: '%c'", c); return 1;
		}
	}
	if (state.node_id < 0 || !iface || optind != argc) {
		error("Syntax: %s [ -m | -M ] [-q] -n <node_id> -i <iface>", argv[0]);
		return 1;
	}

	state.can_stdio_fd = canio_socket(iface, state.node_id, state.master ? 1 : 0);
	if (state.can_stdio_fd < 0) {
		callfail("canio_socket");
		return 1;
	}

	state.can_ctrl_fd = canio_socket(iface, state.node_id, state.master ? CANSH_FD_NOTIF : CANSH_FD_CTRL);
	if (state.can_stdio_fd < 0) {
		callfail("canio_socket");
		return 1;
	}

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
	if (sigprocmask(SIG_BLOCK, &ss, NULL) < 0) {
		sysfail("sigprocmask");
		goto done;
	}

	/* Put terminal in character mode */
	if (termios_stdin_char_mode(!state.forward_signals) < 0) {
		callfail("termios_stdin_char_mode");
		goto done;
	}

	if (state.master) {
		send_resize(&state, -1, -1);
	}

	if (run_loop(&state) < 0) {
		callfail("run_loop");
	}

	ret = 0;

done:
	termios_reset();

	close(state.signal_fwd_fd);
	close(state.signal_fd);
	close(state.can_ctrl_fd);
	close(state.can_stdio_fd);

	return ret;
}
