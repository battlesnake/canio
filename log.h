#pragma once
#include <stdio.h>
#include <errno.h>
#include <string.h>

/* Logging macros */
#define log_plain(fmt, ...) fprintf(stderr, fmt "\n", ##__VA_ARGS__)
#define log(fmt, ...) log_plain("%-8.8s:%4d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#define error(fmt, ...) log("\x1b[1;31m [fail] " fmt "\x1b[0m", ##__VA_ARGS__)
#define warn(fmt, ...) log("\x1b[1;33m [warn] " fmt "\x1b[0m", ##__VA_ARGS__)
#define info(fmt, ...) log("\x1b[1;36m [info] " fmt "\x1b[0m", ##__VA_ARGS__)
#define sysfail(name) error("'%s' system call failed with code %d: %s", name, errno, strerror(errno))
#define callfail(name) error("'%s' call failed: %s", name, strerror(errno))

