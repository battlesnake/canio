#if defined __linux__

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <unistd.h>
#include <poll.h>

#include <net/if.h>
#include <sys/ioctl.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#include "log.h"

#include "canio.h"

int canio_socket(const char *iface, int node_id, int node_fd)
{
	if (node_fd < -1 || node_fd > 255 || node_id < 0 || node_id > 255) {
		return -EINVAL;
	}
	int fd = socket(PF_CAN, SOCK_RAW, CAN_RAW);
	if (fd < 0) {
		sysfail("socket");
		return -1;
	}
	struct sockaddr_can addr;
	memset(&addr, 0, sizeof(addr));
	addr.can_family = AF_CAN;
	if (strcmp(iface, "*") == 0) {
		addr.can_ifindex = 0;
	} else {
		addr.can_ifindex = if_nametoindex(iface);
	}
	struct can_filter cf;
	memset(&cf, 0, sizeof(cf));
	bool wildcard = node_fd == -1;
	cf.can_id = wildcard ? CANIO_ALL(node_id) : CANIO_ID(node_id, node_fd);
	cf.can_mask = wildcard ? CANIO_NODE_MASK : CANIO_NODE_STREAM_MASK;
	if (setsockopt(fd, SOL_CAN_RAW, CAN_RAW_FILTER, &cf, sizeof(cf)) < -1) {
		sysfail("setsockopt:CAN_RAW_FILTER");
		close(fd);
		return -1;
	}
	if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		sysfail("bind");
		close(fd);
		return -1;
	}
	return fd;
}

ssize_t canio_write(int fd, uint32_t id, const void *buf, size_t length)
{
	return canio_write_for(fd, id, buf, length, -1);
}

ssize_t canio_write_for(int fd, uint32_t id, const void *buf, size_t length, canio_timeout_t timeout)
{
	int ret;
	struct pollfd pfd = { .fd = fd, .events = POLLOUT };
	ret = poll(&pfd, 1, timeout);
	if (ret == 0) {
		errno = ETIMEDOUT;
		return -1;
	}
	if (ret < 0) {
		sysfail("poll");
		return -1;
	}
	ret = 0;
	if (length > CAN_MTU) {
		errno = EOVERFLOW;
		return -1;
	}
	struct can_frame fr;
	memset(&fr, 0, sizeof(fr));
	fr.can_id = id;
	memcpy(fr.data, buf, length);
	fr.can_dlc = length;
	ret = write(fd, &fr, sizeof(fr));
	if (ret < 0) {
		sysfail("write");
		return -1;
	}
	return ret;
}

ssize_t canio_read(int fd, uint32_t *id, void *buf, size_t bufsize)
{
	return canio_read_for(fd, id, buf, bufsize, -1);
}

ssize_t canio_read_for(int fd, uint32_t *id, void *buf, size_t bufsize, canio_timeout_t timeout)
{
	int ret;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	ret = poll(&pfd, 1, timeout);
	if (ret == 0) {
		errno = ETIMEDOUT;
		return -1;
	}
	if (ret < 0) {
		sysfail("poll");
		return -1;
	}
	ret = 0;
	struct can_frame fr;
	ret = read(fd, &fr, sizeof(fr));
	if (ret < 0) {
		sysfail("read");
		return -1;
	}
	if (ret != sizeof(fr)) {
		errno = EINVAL;
		sysfail("read");
		return -1;
	}
	if (fr.can_dlc > bufsize) {
		errno = EMSGSIZE;
		error("CAN payload is larger than receive buffer");
		return -1;
	}
	if (id) {
		*id = fr.can_id;
	}
	memcpy(buf, fr.data, fr.can_dlc);
	return fr.can_dlc;
}

int canio_close(int fd)
{
	return close(fd);
}

#endif
