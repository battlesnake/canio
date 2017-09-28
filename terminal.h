#pragma once
#include <stdbool.h>

int termios_reset();
int termios_stdin_no_echo();
int termios_stdin_char_mode(bool signals);
