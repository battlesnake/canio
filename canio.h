#pragma once
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <linux/can.h>

#define CANIO_NODE_ALL 0xFFU
#define CANIO_STREAM_ALL 0xFU

/* Make ID */
#define CANIO_ID(node, stream) ((canid_t) (((node) & CANIO_NODE_ALL) | ((stream) & CANIO_STREAM_ALL) << 8))
/* Deconstruct ID */
#define CANIO_NODE(id) ((id) & 0xFFU)
#define CANIO_STREAM(id) ((id) >> 8 & 0xFU)

/* Masks */
#define CANIO_NODE_MASK CANIO_ID(CANIO_NODE_ALL, 0)
#define CANIO_STREAM_MASK CANIO_ID(0, CANIO_STREAM_ALL)
#define CANIO_NODE_STREAM_MASK CANIO_ID(CANIO_NODE_ALL, CANIO_STREAM_ALL)

/* Node/stream CAN ID generators */
#define CANIO_STDOUT(node) CANIO_ID(node, 1)
#define CANIO_STDIN(node) CANIO_ID(node, 0)
#define CANIO_ALL(node) CANIO_ID(node, CANIO_STREAM_ALL)

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
