#include <stdbool.h>
#include <termios.h>
#include <unistd.h>

#include "log.h"

static struct termios original;
static struct termios actual;
static bool changed;

static int term_fd()
{
	static int fd = -2;
	if (fd != -2) {
		return fd;
	}
	if (isatty(STDIN_FILENO)) {
		return (fd = STDIN_FILENO);
	} else if (isatty(STDOUT_FILENO)) {
		return (fd = STDOUT_FILENO);
	} else {
		return (fd = -1);
	}
}

static int term_getattr(struct termios *t)
{
	int fd = term_fd();
	if (fd == -1) {
		errno = ENOTTY;
		return -1;
	}
	if (tcgetattr(fd, t) < 0) {
		sysfail("tcgetattr");
		return -1;
	}
	return 0;
}

static int term_setattr(const struct termios *t)
{
	int fd = term_fd();
	if (fd == -1) {
		errno = ENOTTY;
		return -1;
	}
	if (tcsetattr(fd, TCSANOW, t) < 0) {
		sysfail("tcsetattr");
		return -1;
	}
	return 0;
}

static int changing(struct termios *new)
{
	if (!changed) {
		if (term_getattr(&original) < 0) {
			sysfail("tcgetattr");
			return -1;
		}
		changed = true;
		actual = original;
	}
	if (new) {
		*new = original;
	}
	return 0;
}

static void change(const struct termios *new)
{
	if (changed) {
		actual = *new;
	}
}

int termios_stop()
{
	if (term_getattr(&actual) < 0) {
		return -1;
	}
	if (term_setattr(&original) < 0) {
		return -1;
	}
	return 0;
}

int termios_cont()
{
	if (changed && term_setattr(&actual) < 0) {
		return -1;
	}
	return 0;
}

int termios_reset()
{
	int fd = term_fd();
	if (fd == -1) {
		return ENOTTY;
	}
	if (changed) {
		if (term_setattr(&original) < 0) {
			sysfail("tcsetattr");
			return -1;
		}
	}
	change(&original);
	return 0;
}

int termios_stdin_no_echo()
{
	struct termios t;
	if (changing(&t) < 0) {
		return -1;
	}
	t.c_lflag &= ~(ICANON | ECHO | ECHONL | ECHOCTL);
	t.c_lflag |= ISIG;
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 2;
	if (term_setattr(&t) < 0) {
		return -1;
	}
	change(&t);
	return 0;
}

int termios_stdin_char_mode(bool signals)
{
	struct termios t;
	if (changing(&t) < 0) {
		return -1;
	}
	t.c_lflag &= ~(ICANON | ECHO | ECHOCTL | ISIG);
	if (signals) {
		t.c_lflag |= ISIG;
	}
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 2;
	if (term_setattr(&t) < 0) {
		return -1;
	}
	change(&t);
	return 0;
}

