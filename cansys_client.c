#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <errno.h>
#include <endian.h>

#include "log.h"

#include "canio.h"
#include "cansys.h"

#include "cansys_common.h"

int cansys_client_init(struct cansys_client *inst, const char *iface, int node_id, canio_deadline_t default_deadline)
{
	cansys_log("%s", __func__);
	inst->fd = canio_socket(iface, node_id, CANSYS_CMD_FD);
	if (inst->fd < 0) {
		errno = EIO;
		return -1;
	}
	inst->node_id = node_id;
	inst->deadline = default_deadline;
	return 0;
}

void cansys_client_free(struct cansys_client *inst)
{
	cansys_log("%s", __func__);
	canio_close(inst->fd);
}

static int cansys_client_transaction(struct cansys_client *inst, struct cansys_data *data, size_t *datalen, canio_deadline_t deadline)
{
	cansys_log("%s", __func__);
	if (!deadline) {
		deadline = inst->deadline;
	}
	cansys_printx("tx", data, *datalen + 1);
	if (canio_write_for(inst->fd, inst->node_id, data, *datalen + 1, deadline) < 0) {
		cansys_log("canio_write_for failed: %s", strerror(errno));
		return -1;
	}
	struct cansys_data res;
	uint32_t node_id;
	ssize_t len;
	do {
		if ((len = canio_read_for(inst->fd, &node_id, &res, sizeof(res), deadline)) < 0) {
			cansys_log("canio_read_for failed: %s", strerror(errno));
			return -1;
		}
		if (len == 0) {
			continue;
		}
	} while (!(
			len >= 0 &&
			CANSYS_CTRL_CMD(res.ctrl) == CANSYS_CTRL_CMD(data->ctrl) &&
			CANSYS_CTRL_IS_RES(res.ctrl)));
	cansys_printx("rx", &res, len);
	if (CANSYS_CTRL_IS_ERROR(res.ctrl)) {
		errno = get_raw64(res.data, len - 1);
		cansys_log("Transaction failed");
		return -1;
	}
	*data = res;
	*datalen = len - 1;
	return 0;
}

int cansys_client_ident(struct cansys_client *inst, char *buf, size_t buflen, canio_deadline_t deadline)
{
	cansys_log("%s", __func__);
	struct cansys_data msg;
	msg.ctrl = CANSYS_MAKE_CTRL(cansys_cmd_ident, false, false);
	memset(msg.data, 0, sizeof(msg.data));
	size_t datalen = 0;
	int ret = cansys_client_transaction(inst, &msg, &datalen, deadline);
	if (ret) {
		return ret;
	}
	memset(buf, 0, buflen);
	snprintf(buf, buflen, "%.*s", (int) datalen, msg.data);
	return 0;
}

int cansys_client_ping(struct cansys_client *inst, canio_deadline_t deadline)
{
	cansys_log("%s", __func__);
	struct cansys_data msg;
	msg.ctrl = CANSYS_MAKE_CTRL(cansys_cmd_ping, false, false);
	memset(msg.data, 0, sizeof(msg.data));
	size_t datalen = 0;
	return cansys_client_transaction(inst, &msg, &datalen, deadline);
}

int cansys_client_set_heartbeat(struct cansys_client *inst, uint64_t ms, canio_deadline_t deadline)
{
	cansys_log("%s", __func__);
	struct cansys_data msg;
	msg.ctrl = CANSYS_MAKE_CTRL(cansys_cmd_set_heartbeat_ms, false, false);
	ssize_t datalen = set_val64(&msg, ms);
	if (datalen < 0) {
		return -1;
	}
	return cansys_client_transaction(inst, &msg, (size_t *) &datalen, deadline);
}

int cansys_client_reboot(struct cansys_client *inst, canio_deadline_t deadline)
{
	cansys_log("%s", __func__);
	struct cansys_data msg;
	msg.ctrl = CANSYS_MAKE_CTRL(cansys_cmd_reboot, false, false);
	memset(msg.data, 0, sizeof(msg.data));
	size_t datalen = 0;
	return cansys_client_transaction(inst, &msg, &datalen, deadline);
}

int cansys_client_uptime(struct cansys_client *inst, uint64_t *ms, canio_deadline_t deadline)
{
	cansys_log("%s", __func__);
	struct cansys_data msg;
	msg.ctrl = CANSYS_MAKE_CTRL(cansys_cmd_uptime_ms, false, false);
	memset(msg.data, 0, sizeof(msg.data));
	size_t datalen = 0;
	if (cansys_client_transaction(inst, &msg, &datalen, deadline)) {
		return -1;
	}
	*ms = get_raw64(msg.data, datalen);
	return 0;
}

static int cansys_client_reg(struct cansys_client *inst, uint16_t reg, uint64_t *in, uint64_t *out, canio_deadline_t deadline)
{
	cansys_log("%s", __func__);
	struct cansys_data msg;
	struct cansys_reg_data *rd = (void *) msg.data;
	msg.ctrl = CANSYS_MAKE_CTRL(cansys_cmd_reg, false, false);
	rd->reg = htole16(CANSYS_REG_READ(reg));
	size_t datalen = sizeof(rd->reg);
	if (in) {
		datalen += set_raw64(rd->raw, sizeof(rd->raw), *in);
	}
	int ret = cansys_client_transaction(inst, &msg, &datalen, deadline);
	if (ret) {
		return -1;
	}
	if (datalen < sizeof(rd->reg)) {
		errno = EIO;
		return -1;
	}
	if (out) {
		*out = get_raw64(rd->raw, datalen - sizeof(rd->reg));
	}
	return 0;
}

int cansys_client_reg_read(struct cansys_client *inst, uint16_t reg, uint64_t *val, canio_deadline_t deadline)
{
	cansys_log("%s", __func__);
	return cansys_client_reg(inst, CANSYS_REG_READ(reg), NULL, val, deadline);
}

int cansys_client_reg_write(struct cansys_client *inst, uint16_t reg, uint64_t val, canio_deadline_t deadline)
{
	cansys_log("%s", __func__);
	return cansys_client_reg(inst, CANSYS_REG_WRITE(reg), &val, NULL, deadline);
}

int cansys_client_is_heartbeat(struct cansys_client *inst, const struct cansys_data *msg, size_t msglen)
{
	cansys_log("%s", __func__);
	(void) inst;
	return msg->ctrl == CANSYS_CTRL_HEARTBEAT && msglen == 1;
}
