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

static ssize_t do_ident(const struct cansys_server *inst, struct cansys_data *buf, size_t datalen)
{
	cansys_log("%s", __func__);
	if (datalen > 0) {
		return -EINVAL;
	}
	strncpy(buf->data, inst->ident, sizeof(buf->data));
	return strnlen(inst->ident, sizeof(inst->ident));
}

static ssize_t do_pong(const struct cansys_server *inst, struct cansys_data *buf, size_t datalen)
{
	cansys_log("%s: %zu bytes", __func__, datalen);
	(void) inst;
	(void) buf;
	return datalen;
}

static ssize_t do_set_heartbeat_ms(const struct cansys_server *inst, struct cansys_data *buf, size_t datalen)
{
	uint64_t val = get_val64(buf, datalen);
	cansys_log("%s: %lums", __func__, val);
	if (!inst->ad || !inst->ad->set_heartbeat_ms) {
		return -ENOTSUP;
	}
	int ret = inst->ad->set_heartbeat_ms(inst->arg, &val);
	if (ret < 0) {
		return ret;
	}
	return set_val64(buf, val);
}

static ssize_t do_reboot(const struct cansys_server *inst, struct cansys_data *buf, size_t datalen)
{
	cansys_log("%s", __func__);
	(void) buf;
	(void) datalen;
	if (!inst->ad || !inst->ad->reboot) {
		return -ENOTSUP;
	}
	return inst->ad->reboot(inst->arg);
}

static ssize_t do_uptime_ms(const struct cansys_server *inst, struct cansys_data *buf, size_t datalen)
{
	cansys_log("%s", __func__);
	(void) buf;
	(void) datalen;
	if (!inst->ad || !inst->ad->uptime) {
		return -ENOTSUP;
	}
	uint64_t val = (uint64_t) -1;
	int ret = inst->ad->uptime(inst->arg, &val);
	if (ret < 0) {
		return ret;
	}
	return set_val64(buf, val);
}

static ssize_t do_reg_read(const struct cansys_server *inst, uint16_t reg, uint64_t *value)
{
	cansys_log("%s", __func__);
	if (!inst->ad || !inst->ad->reg_read) {
		return -ENOTSUP;
	}
	return inst->ad->reg_read(inst->arg, reg, value);
}

static ssize_t do_reg_write(const struct cansys_server *inst, uint16_t reg, uint64_t value)
{
	cansys_log("%s", __func__);
	if (!inst->ad || !inst->ad->reg_write) {
		return -ENOTSUP;
	}
	return inst->ad->reg_write(inst->arg, reg, &value);
}

static ssize_t do_reg(const struct cansys_server *inst, struct cansys_data *buf, size_t datalen)
{
	struct cansys_reg_data *rd = (void *) &buf->data;
	if (datalen < sizeof(rd->reg)) {
		return -EINVAL;
	}
	uint16_t reg = le16toh(rd->reg);
	uint16_t regidx = CANSYS_REG_IDX(reg);
	uint64_t val = get_raw64(rd->raw, datalen - sizeof(rd->reg));
	int ret;
	if (CANSYS_REG_IS_READ(reg)) {
		ret = do_reg_read(inst, regidx, &val);
		cansys_log("%s: [%hu] -> %lu", __func__, regidx, val);
		if (ret < 0) {
			return ret;
		}
		return sizeof(rd->reg) + set_raw64(rd->raw, sizeof(rd->raw), val);
	} else if (CANSYS_REG_IS_WRITE(reg)) {
		cansys_log("%s: [%hu] <- %lu", __func__, regidx, val);
		ret = do_reg_write(inst, regidx, val);
		if (ret < 0) {
			return ret;
		}
		return sizeof(rd->reg);
	} else {
		return -EINVAL;
	}
}

static ssize_t handle_cmd(const struct cansys_server *inst, struct cansys_data *buf, size_t datalen)
{
	cansys_log("%s", __func__);
	switch (CANSYS_CTRL_CMD(buf->ctrl)) {
	case cansys_cmd_ident: return do_ident(inst, buf, datalen);
	case cansys_cmd_ping: return do_pong(inst, buf, datalen);
	case cansys_cmd_set_heartbeat_ms: return do_set_heartbeat_ms(inst, buf, datalen);
	case cansys_cmd_reboot: return do_reboot(inst, buf, datalen);
	case cansys_cmd_uptime_ms: return do_uptime_ms(inst, buf, datalen);
	case cansys_cmd_reg: return do_reg(inst, buf, datalen);
	}
	return -EINVAL;
}

int cansys_server_init(struct cansys_server *inst, const struct cansys_adapter *ad, const char *ident, void *arg)
{
	cansys_log("%s", __func__);
	inst->ad = ad;
	strncpy(inst->ident, ident, sizeof(inst->ident));
	inst->arg = arg;
	return 0;
}

void cansys_server_free(struct cansys_server *inst)
{
	cansys_log("%s", __func__);
	(void) inst;
}

int cansys_server_handle_message(struct cansys_server *inst, struct cansys_data *msg, size_t *msglen)
{
	cansys_log("%s", __func__);
	cansys_printx("rx", msg, *msglen);
	if (msglen == 0) {
		warn("Received zero-length packet in CANSYS server");
		return -EAGAIN;
	}
	if (CANSYS_CTRL_IS_RES(msg->ctrl)) {
		/* Response flag set: not a request */
		return -EAGAIN;
	}
	cansys_log("Received command, ctrl=0x%02hhx", msg->ctrl);
	const ssize_t ret = handle_cmd(inst, msg, *msglen - 1);
	const bool err = ret < 0;
	const ssize_t len = err ? set_val64(msg, -ret) : ret;
	if (err || len < 0) {
		cansys_log("Failed to handle command: %s", strerror(-ret));
	}
	if (len < 0) {
		return -1;
	}
	msg->ctrl = CANSYS_MAKE_CTRL(CANSYS_CTRL_CMD(msg->ctrl), true, err);
	*msglen = len + 1;
	cansys_printx("tx", msg, *msglen);
	cansys_log("Command executed");
	return 0;
}

int cansys_server_make_heartbeat(struct cansys_server *inst, struct cansys_data *msg, size_t *msglen)
{
	cansys_log("%s", __func__);
	(void) inst;
	msg->ctrl = CANSYS_CTRL_HEARTBEAT;
	*msglen = 1;
	return 0;
}
