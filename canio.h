#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "canio_defs.h"

/* Change this and the open/close/packets in canio.c for CAN FD */
#define CAN_DATA_LEN 8

/* CAN wrappers */
int canio_socket(const char *iface, int node_id, bool master);
ssize_t canio_write(int fd, uint32_t id, const char *buf, size_t length);
ssize_t canio_read(int fd, uint32_t *id, char *buf, size_t bufsize);
#define canio_close(fd) close(fd)
