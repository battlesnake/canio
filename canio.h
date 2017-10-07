#pragma once
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include "canio_defs.h"

/* Change this and the open/close/packets in canio.c for CAN FD */
#define CAN_DATA_LEN 8

typedef int32_t canio_timeout_t;

/* CAN wrappers */
int canio_socket(const char *iface, int node_id, int node_fd);

ssize_t canio_write(int fd, uint32_t id, const void *buf, size_t length);
ssize_t canio_write_for(int fd, uint32_t id, const void *buf, size_t length, canio_timeout_t timeout);

ssize_t canio_read(int fd, uint32_t *id, void *buf, size_t bufsize);
ssize_t canio_read_for(int fd, uint32_t *id, void *buf, size_t bufsize, canio_timeout_t timeout);

int canio_close(int fd);
