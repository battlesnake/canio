#pragma once
#include <stdio.h>
#include <errno.h>
#include <string.h>

/* Logging macros */
#define log(fmt, ...) fprintf(stderr, "%-8.8s:%4d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define error(fmt, ...) log("\x1b[1;31m [fail] " fmt "\x1b[0m", ##__VA_ARGS__)
#define warn(fmt, ...) log("\x1b[1;33m [warn] " fmt "\x1b[0m", ##__VA_ARGS__)
#define info(fmt, ...) log("\x1b[1;36m [info] " fmt "\x1b[0m", ##__VA_ARGS__)
#define sysfail(name) error("'%s' system call failed with code %d: %s", name, errno, strerror(errno))
#define callfail(name) error("'%s' call failed", name)

