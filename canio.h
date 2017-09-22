#pragma once
#include <stdio.h>
#include <stdint.h>
#include <errno.h>

#define CAN_ID_FD_MASK 0x00000F00U
#define CAN_ID_STDIN_FD 0x00000000U
#define CAN_ID_STDOUT_FD 0x00000100U

#define CAN_ID_NODE_MASK 0x000000FFU
#define CAN_ID_STDOUT(node) (0x00000100U | ((node) & CAN_ID_NODE_MASK))
#define CAN_ID_STDIN(node) (0x00000000U | ((node) & CAN_ID_NODE_MASK))
#define CAN_DATA_LEN 8

#define log(fmt, ...) fprintf(stderr, "%-8.8s:%4d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define error(fmt, ...) log("\x1b[1;31m [fail] " fmt "\x1b[0m", ##__VA_ARGS__)
#define warn(fmt, ...) log("\x1b[1;33m [warn] " fmt "\x1b[0m", ##__VA_ARGS__)
#define info(fmt, ...) log("\x1b[1;36m [info] " fmt "\x1b[0m", ##__VA_ARGS__)
#define sysfail(name) error("'%s' system call failed with code %d: %s", name, errno, strerror(errno))
#define callfail(name) error("'%s' call failed", name)

int can_socket(const char *iface, int node_id, bool master);
ssize_t can_write(int fd, uint32_t id, const char *buf, size_t length);
ssize_t can_read(int fd, uint32_t *id, char *buf, size_t bufsize);
