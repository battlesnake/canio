#pragma once
#include <stdint.h>

#define CANSH_FD_CTRL 3
#define CANSH_FD_NOTIF 4

struct __attribute__((__packed__)) cansh_ctrl
{
	union {
		char raw[8];
		struct {
			uint8_t cmd;
			int16_t arg;
			uint16_t param1;
			uint16_t param2;
		};
	};
};

struct __attribute__((__packed__)) cansh_ctrl_signal
{
	uint8_t cmd;
	uint8_t signal;
};

struct __attribute__((__packed__)) cansh_ctrl_exit
{
	uint8_t cmd;
	uint16_t status;
};

struct __attribute__((__packed__)) cansh_ctrl_size
{
	uint8_t cmd;
	uint16_t width;
	uint16_t height;
};

enum cansh_ctrl_cmd
{
	/* Send signal */
	cc_signal = 1,
	/* Receive exit code */
	cc_exit = 2,
	/* Window resize (WINCH + size) */
	cc_size = 3,
};
