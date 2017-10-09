#pragma once
#include <stdbool.h>

/*
 * Terminal configuration
 */

/* Reset to initial state */
int termios_reset();

/* Disable echo */
int termios_stdin_no_echo();

/* Put terminal in character mode, optionally with signal translation enabled */
int termios_stdin_char_mode(bool signals);

/* Call before SIGSTOP / after SIGCONT */
int termios_stop();
int termios_cont();
