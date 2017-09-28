#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <unistd.h>

#include <net/if.h>
#include <sys/ioctl.h>

#include <linux/can.h>
#include <linux/can/raw.h>

#include "canio.h"

int can_socket(const char *iface, int node_id, bool master)
{
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
	cf.can_id = master ? CANIO_ALL(node_id) : CANIO_STDIN(node_id);
	cf.can_mask = master ? CANIO_NODE_MASK : CANIO_NODE_STREAM_MASK;
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

ssize_t can_write(int fd, uint32_t id, const char *buf, size_t length)
{
	if (length > CAN_MTU) {
		return -1;
	}
	struct can_frame fr;
	fr.can_id = id;
	memcpy(fr.data, buf, length);
	fr.can_dlc = length;
	int ret = write(fd, &fr, sizeof(fr));
	if (ret == -1) {
		sysfail("write");
		return -1;
	}
	return ret;
}

ssize_t can_read(int fd, uint32_t *id, char *buf, size_t bufsize)
{
	struct can_frame fr;
	int ret = read(fd, &fr, sizeof(fr));
	if (ret != sizeof(fr)) {
		sysfail("read");
		return -1;
	}
	if (fr.can_dlc > bufsize) {
		error("CAN payload is larger than receive buffer");
		return -1;
	}
	if (id) {
		*id = fr.can_id;
	}
	memcpy(buf, fr.data, fr.can_dlc);
	return fr.can_dlc;
}
