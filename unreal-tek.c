/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "poemgr.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define ARRAY_SIZE(arr)			sizeof(arr)/sizeof((arr)[0])
#define URTL_PORT_STATE_DISABLED	0
#define URTL_PORT_STATE_DELIVERING	2
#define URTL_PWR_MGMNT_DYNAMIC		2

#define RESPONSE_TIMEOUT_MS		100

struct unreal_poe {
	unsigned int configuration_is_unsaved : 1;
	unsigned int remote_enable_gpio : 1;
	unsigned int output_pairing_enabled : 1;
	unsigned int num_ports_detected;
	unsigned int mcu_fw_version;
	const char *mcu_name;

	int fd;
	int sequnce_num;
};

struct unreal_cmd {
	size_t len;
	uint8_t raw[12];
};

static uint16_t read16_be(uint8_t *raw)
{
	return (uint16_t)raw[0] << 8 | raw[1];
}

static const char *mcu_name_from_type(unsigned int type)
{
	static const char *names[] = {
		[0] = "ST Micro ST32F100",
		[1] = "Nuvoton M05xx LAN",
		[2] = "ST Micro STF030C8",
		[3] = "Nuvoton M058SAN",
		[4] = "Nuvoton NUC122"
	};

	if (type >= ARRAY_SIZE(names))
		return "unknown";

	return names[type];
}

static int urtl_to_poemgr_fault(uint8_t fault)
{
	static const int faults[] = {
		[0] = POEMGR_FAULT_TYPE_UNKNOWN,	/* Over-voltage */
		[1] = POEMGR_FAULT_TYPE_OPEN_CIRCUIT,
		[2] = POEMGR_FAULT_TYPE_SHORT_CIRCUIT,
		[3] = POEMGR_FAULT_TYPE_OVER_CURRENT,
		[4] = POEMGR_FAULT_TYPE_POWER_MANAGEMENT,
		[5] = POEMGR_FAULT_TYPE_OVER_TEMPERATURE,
	};

	if (fault >= ARRAY_SIZE(faults))
		return POEMGR_FAULT_TYPE_UNKNOWN;

	return faults[fault];
}

static uint8_t calc_packet_checksum(const struct unreal_cmd *cmd)
{
	unsigned int i, csum = 0;

	for (i = 0; i < sizeof(cmd->raw) - 1; i++)
		csum += cmd->raw[i];

	return csum;
}

static unsigned int elapsed_ms_since(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start->tv_sec) * 1000
	     + (now.tv_nsec - start->tv_nsec) / 1000000;
}

static int read_n_bytes(int fd, uint8_t *buf, size_t len)
{
	struct timespec start;
	int ret, num_read = 0;

	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		ret = read(fd, buf + num_read, len - num_read);
		if (ret < 0)
			return -1;

		if (elapsed_ms_since(&start) > RESPONSE_TIMEOUT_MS) {
			errno = ETIMEDOUT;
			return -1;
		}

		num_read += ret;
	} while (num_read < len);

	return num_read;
}

static int transcieve_command(struct unreal_poe *ctrl, struct unreal_cmd *cmd)
{
	uint8_t request_id = cmd->raw[0];
	ssize_t ret;

	if (cmd->len >= sizeof(cmd->raw))
	    return -EINVAL;

	memset(cmd->raw + cmd->len, 0xff, sizeof(cmd->raw) - cmd->len);
	cmd->raw[1] = ++ctrl->sequnce_num;
	cmd->raw[11] = calc_packet_checksum(cmd);

	ret = write(ctrl->fd, cmd->raw, sizeof(cmd->raw));
	if (ret < 0) {
		perror("Write packet");
		return -errno;
	}

	ret = read_n_bytes(ctrl->fd, cmd->raw, sizeof(cmd->raw));
	if (ret < 0) {
		perror("Read packet");
		return -errno;
	}

	if (cmd->raw[11] != calc_packet_checksum(cmd)) {
		fprintf(stderr, "Bad checksum\n");
		return -EBADE;
	}

	if (cmd->raw[0] != request_id) {
		fprintf(stderr, "Unknown reply (id=%02x)\n", cmd->raw[0]);
		return -EBADE;
	}

	return ret;
}

/*
 * Transcieve simple requests, where returned data is an error code.
 *
 * This works for both global requests, and port requests
 *     * 3-byte requests return [error]
 *     * 4-byte requests return [port][error]
 * For more complex commands, use transcieve_command().
 */
static int transcieve_request(struct unreal_poe *ctrl, struct unreal_cmd *cmd)
{
	int ret, mcu_response;

	ret = transcieve_command(ctrl, cmd);
	if (ret < 0)
		return ret;

	mcu_response = cmd->raw[cmd->len - 1];
	return (mcu_response == 0) ? 0 : -EPROTO;
}

static int enable_port(struct unreal_poe *poe, unsigned int port)
{
	struct unreal_cmd enable_port = {
		.raw = { 0x00, 0x00, port, 0x01 },
		.len = 4,
	};

	return transcieve_request(poe, &enable_port);
}

static int set_global_port_enable(struct unreal_poe *poe, bool enable)
{
	struct unreal_cmd global_port_enable = {
		.raw = { 0x06, 0x00, enable },
		.len = 3,
	};

	return transcieve_request(poe, &global_port_enable);
}

static int port_enable_classification(struct unreal_poe *poe, uint8_t port, bool enable)
{
	struct unreal_cmd class_en = {
		.raw = { 0x11, 0x00, port, enable },
		.len = 4,
	};

	return transcieve_request(poe, &class_en);
}

static int set_port_limit_type(struct unreal_poe *poe, uint8_t port, uint8_t type)
{
	struct unreal_cmd limit_type = {
		.raw = { 0x15, 0x00, port, type },
		.len = 4,
	};

	return transcieve_request(poe, &limit_type);
}

static int set_power_management_mode(struct unreal_poe *poe, unsigned int mode)
{
	struct unreal_cmd power_mgmnt_mode = {
		.raw = { 0x17, 0x00, mode },
		.len = 3,
	};

	return transcieve_request(poe, &power_mgmnt_mode);
}

static int set_port_priority(struct unreal_poe *poe, uint8_t port, uint8_t priority)
{
	struct unreal_cmd port_priority = {
		.raw = { 0x1a, 0x00, port, priority },
		.len = 4,
	};

	return transcieve_request(poe, &port_priority);
}

static int unreal_sys_info(struct unreal_poe *poe)
{
	unsigned int system_status, version_major, version_minor;
	int ret;

	struct unreal_cmd system_info = {
		.raw = { 0x20 },
		.len = 1,
	};

	ret = transcieve_command(poe, &system_info);
	if (ret < 0)
		return ret;

	poe->num_ports_detected = system_info.raw[3];
	version_major = system_info.raw[7];
	poe->mcu_name = mcu_name_from_type(system_info.raw[8]);
	system_status = system_info.raw[9];
	version_minor = system_info.raw[10];

	poe->mcu_fw_version = (version_major << 8) | version_minor;
	poe->configuration_is_unsaved = !!(system_status & (1 << 0));
	poe->remote_enable_gpio = !!(system_status & (1 << 1));
	poe->output_pairing_enabled = !!(system_status & (1 << 2));
	return 0;
}

static int unreal_init(struct poemgr_ctx *ctx)
{
	struct unreal_poe *poe;
	int ret;

	struct termios thermo = {
		.c_oflag = 0,
		.c_iflag = 0,
		.c_cflag = B19200 | CS8 | CREAD | CLOCAL,
		.c_lflag = 0,
	};

	poe = malloc(sizeof(*poe));
	if (!poe)
	    return -ENOMEM;

	memset(poe, 0, sizeof(*poe));
	ctx->priv = poe;
	poe->fd = open("/dev/ttyS1", O_RDWR);
	if (poe->fd < 0) {
		perror("Can't get serial port");
		return -errno;
	}

	ret = tcsetattr(poe->fd, TCSANOW, &thermo);
	if (ret) {
		perror("Can't configure serial port");
		return -errno;
	}
	tcflush(poe->fd, TCIOFLUSH);

	ret = unreal_sys_info(poe);
	if (ret < 0)
		return ret;

	return 0;
}

static int unreal_ready(struct poemgr_ctx *ctx)
{
	fprintf(stderr, "junk %s\n", __func__);
	return 1;
}

static int unreal_enable(struct poemgr_ctx *ctx)
{
	return set_global_port_enable(ctx->priv, true);
}

static int unreal_disable(struct poemgr_ctx *ctx)
{
	return set_global_port_enable(ctx->priv, false);
}

static int unreal_configure_ports(struct poemgr_ctx *ctx)
{
	struct poemgr_port_settings *port_setting;
	struct unreal_poe *poe = ctx->priv;
	size_t port;

	for (port = 0; port < ctx->profile->num_ports; port++) {
		port_setting = &ctx->ports[port].settings;
		if (port_setting->disabled)
			continue;

		set_port_priority(poe, port, 0);
		set_port_limit_type(poe, port, 1);
		port_enable_classification(poe, port, true);
		enable_port(poe, port);
		/* TODO: Get port budget from config, apply it */
	}

	return 0;
}

static int unreal_apply_config(struct poemgr_ctx *ctx)
{
	struct unreal_poe *poe = ctx->priv;

	set_power_management_mode(poe, URTL_PWR_MGMNT_DYNAMIC);
	unreal_configure_ports(ctx);
	return 0;
}

static int unreal_update_port_status(struct poemgr_ctx *ctx, int port)
{
	struct poemgr_port_status *port_status = &ctx->ports[port].status;
	struct unreal_poe *poe = ctx->priv;
	int ret, state, fault_type;
	float power_budget;

	struct unreal_cmd port_stat = {
		.raw = { 0x21, 0x00, port },
		.len = 3,
	};

	struct unreal_cmd port_config = {
		.raw = { 0x26, 0x00, port },
		.len = 3,
	};

	struct unreal_cmd port_measure = {
		.raw = { 0x30, 0x00, port },
		.len = 3,
	};

	ret = transcieve_command(poe, &port_stat);
	if (ret < 0)
		return ret;

	ret = transcieve_command(poe, &port_config);
	if (ret < 0)
		return ret;

	ret = transcieve_command(poe, &port_measure);
	if (ret < 0)
		return ret;

	state = port_stat.raw[3];
	port_status->enabled = (state != URTL_PORT_STATE_DISABLED);
	port_status->active = (state == URTL_PORT_STATE_DELIVERING);
	fault_type = port_stat.raw[4];
	port_status->poe_class  = port_stat.raw[5];

	if (state == URTL_PORT_STATE_DELIVERING || state == 6)
		port_status->faults = 0;
	else
		port_status->faults = urtl_to_poemgr_fault(fault_type);

	power_budget = port_config.raw[5] * 0.2;
	port_status->power_limit = power_budget;
	port_status->power = read16_be(port_measure.raw + 9) * 0.1;
	port_status->last_update = time(NULL);

	return 0;
}

static int unreal_update_output_status(struct poemgr_ctx *ctx)
{
	struct unreal_poe *poe = ctx->priv;
	float budget;
	int ret;

	struct unreal_cmd power_stats = {
		.raw = { 0x23 },
		.len = 1,
	};

	ret = transcieve_command(poe, &power_stats);
	if (ret < 0)
		return ret;

	budget = read16_be(power_stats.raw + 4) * 0.1;
	ctx->output_status.power_budget = budget;
	ctx->output_status.last_update = time(NULL);

	return 0;
}


const struct poemgr_profile poemgr_profile_unreal = {
	.name = "unreal-tek",
	.num_ports = 8,
	.ready = unreal_ready,
	.enable = unreal_enable,
	.disable = unreal_disable,
	.init = unreal_init,
	.apply_config = unreal_apply_config,
	.update_port_status = unreal_update_port_status,
	.update_output_status = unreal_update_output_status,
	.num_pse_chips = 0,
};
