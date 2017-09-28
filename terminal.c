#include <stdbool.h>
#include <termios.h>
#include <unistd.h>

#include "log.h"

static struct termios original;
static bool changed;

static int changing(struct termios *new)
{
	if (!changed) {
		if (tcgetattr(STDIN_FILENO, &original) < 0) {
			sysfail("tcgetattr");
			return -1;
		}
		changed = true;
	}
	if (new) {
		*new = original;
	}
	return 0;
}

int termios_reset()
{
	if (changed) {
		if (tcsetattr(STDIN_FILENO, TCSANOW, &original) < 0) {
			sysfail("tcsetattr");
			return -1;
		}
	}
	return 0;
}

int termios_stdin_no_echo()
{
	struct termios t;
	if (changing(&t) < 0) {
		callfail("changing");
		return -1;
	}
	t.c_lflag &= ~(ICANON | ECHO | ECHONL | ECHOCTL);
	t.c_lflag |= ISIG;
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 2;
	if (tcsetattr(STDIN_FILENO, TCSANOW, &t) < 0) {
		sysfail("tcsetattr");
		return -1;
	}
	return 0;
}

int termios_stdin_char_mode(bool signals)
{
	static struct termios t;
	if (changing(&t) < 0) {
		callfail("changing");
		return -1;
	}
	t.c_lflag &= ~(ICANON | ECHO | ECHOCTL | ISIG);
	if (signals) {
		t.c_lflag |= ISIG;
	}
	t.c_cc[VMIN] = 1;
	t.c_cc[VTIME] = 2;
	if (tcsetattr(STDIN_FILENO, TCSANOW, &t) < 0) {
		sysfail("tcsetattr");
		return -1;
	}
	return 0;
}

