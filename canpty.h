#pragma once
#include <stdint.h>

/* Descriptors for control and for notification channels */
#define CANSH_FD_CTRL 3
#define CANSH_FD_NOTIF 4

/* Time (ms) between sending child-process TERM and KILL signals */
#define CHILD_KILL_TIMEOUT 1000

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

struct __attribute__((__packed__)) cansh_ctrl_pid
{
	uint8_t cmd;
};

struct __attribute__((__packed__)) cansh_notify_pid
{
	uint8_t cmd;
	uint32_t pid;
};

struct __attribute__((__packed__)) cansh_ctrl_signal
{
	uint8_t cmd;
	uint8_t signal;
};

struct __attribute__((__packed__)) cansh_notify_exit
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
	/* Request pid */
	cc_pid = 0,
	/* Send signal */
	cc_signal = 1,
	/* Window resize (WINCH + size) */
	cc_size = 2,
};

enum cansh_notify_cmd
{
	/* pid */
	cn_pid = 0,
	/* Receive exit code */
	cn_exit = 1,
};
