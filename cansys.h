#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include "canio.h"

//#define cansys_log(fmt, ...) log("<cansys> " fmt, ##__VA_ARGS__)
#define cansys_log(fmt, ...)

struct __attribute__((__packed__)) cansys_data
{
	uint8_t ctrl;
	char data[7];
};

#define CANSYS_CTRL_FLAG_RES 0x08
#define CANSYS_CTRL_FLAG_ERROR 0x0c
#define CANSYS_MAKE_CTRL(cmd, is_res, error) ( \
		((cmd) << 4 & 0xf0) | \
		((is_res) ? CANSYS_CTRL_FLAG_RES : 0) | \
		((error) ? CANSYS_CTRL_FLAG_ERROR : 0) )
#define CANSYS_CTRL_CMD(ctrl) (((ctrl) & 0xf0) >> 4)
#define CANSYS_CTRL_IS_RES(ctrl) ((ctrl) & CANSYS_CTRL_FLAG_RES ? 1 : 0)
#define CANSYS_CTRL_IS_ERROR(ctrl) (((ctrl) & CANSYS_CTRL_FLAG_ERROR) == CANSYS_CTRL_FLAG_ERROR ? 1 : 0)

#define CANSYS_CTRL_HEARTBEAT CANSYS_MAKE_CTRL(cansys_cmd_set_heartbeat_ms, true, false)

#define CANSYS_CMD_FD 0x7f

enum cansys_cmd
{
	cansys_cmd_ident = 0x0,
	cansys_cmd_ping = 0x1,
	cansys_cmd_set_heartbeat_ms = 0x2,
	cansys_cmd_reboot = 0x3,
	cansys_cmd_uptime_ms = 0x4,
	cansys_cmd_reg = 0x5,
};

struct __attribute__((__packed__)) cansys_reg_data
{
	uint16_t reg;
	union {
		char raw[5];
		uint64_t val;
	};
};

#define CANSYS_REG_READ(reg) (reg)
#define CANSYS_REG_WRITE(reg) (0x8000 | (reg))

#define CANSYS_REG_IS_READ(regraw) (((regraw) & 0x8000) == 0)
#define CANSYS_REG_IS_WRITE(regraw) (((regraw) & 0x8000) == 0x8000)
#define CANSYS_REG_IDX(regraw) ((regraw) & ~0x8000)

/* Server */

typedef int cansys_set_heartbeat_ms(void *arg, uint64_t *ms);
typedef int cansys_reboot(void *arg);
typedef int cansys_uptime_ms(void *arg, uint64_t *out);
typedef int cansys_reg_read(void *arg, uint16_t reg, uint64_t *value);
typedef int cansys_reg_write(void *arg, uint16_t reg, uint64_t *value);

struct cansys_adapter
{
	cansys_set_heartbeat_ms *set_heartbeat_ms;
	cansys_reboot *reboot;
	cansys_uptime_ms *uptime;
	cansys_reg_read *reg_read;
	cansys_reg_write *reg_write;
};

struct cansys_server
{
	const struct cansys_adapter *ad;
	char ident[7];
	void *arg;
};

int cansys_server_init(struct cansys_server *inst, const struct cansys_adapter *ad, const char *ident, void *arg);
void cansys_server_free(struct cansys_server *inst);

int cansys_server_handle_message(struct cansys_server *inst, struct cansys_data *msg, size_t *msglen);
int cansys_server_make_heartbeat(struct cansys_server *inst, struct cansys_data *msg, size_t *msglen);

/* Client */

typedef uint32_t canio_deadline_t;

struct cansys_client
{
	int fd;
	int node_id;
	canio_deadline_t deadline;
};

int cansys_client_init(struct cansys_client *inst, const char *iface, int node_id, canio_deadline_t default_deadline);
void cansys_client_free(struct cansys_client *inst);

int cansys_client_ident(struct cansys_client *inst, char *buf, size_t buflen, canio_deadline_t deadline);

int cansys_client_ping(struct cansys_client *inst, canio_deadline_t deadline);

int cansys_client_reboot(struct cansys_client *inst, canio_deadline_t deadline);
int cansys_client_uptime(struct cansys_client *inst, uint64_t *ms, canio_deadline_t deadline);

int cansys_client_reg_read(struct cansys_client *inst, uint16_t reg, uint64_t *val, canio_deadline_t deadline);
int cansys_client_reg_write(struct cansys_client *inst, uint16_t reg, uint64_t val, canio_deadline_t deadline);

int cansys_client_set_heartbeat(struct cansys_client *inst, uint64_t ms, canio_deadline_t deadline);

int cansys_client_is_heartbeat(struct cansys_client *inst, const struct cansys_data *msg, size_t msglen);
