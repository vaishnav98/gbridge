/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.

 * Author: Alexandre Bailon <abailon@baylibre.com>
 * Copyright (c) 2016 Alexandre Bailon
 */

#include <debug.h>
#include <gbridge.h>
#include <controller.h>
#include <controllers/uart.h>

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>

struct controller uart_controller;

struct uart_controller {
	int fd;
};

static speed_t to_speed_t( int baudrate ) {

#define _case(x) case x: return B ## x

	switch(baudrate) {
	_case(0);
	_case(50);
	_case(75);
	_case(110);
	_case(134);
	_case(150);
	_case(200);
	_case(300);
	_case(600);
	_case(1200);
	_case(1800);
	_case(2400);
	_case(4800);
	_case(9600);
	_case(19200);
	_case(38400);
	_case(57600);
	_case(115200);
	_case(230400);
	_case(460800);
	_case(500000);
	_case(576000);
	_case(921600);
	_case(1000000);
	_case(1152000);
	_case(1500000);
	_case(2000000);
	_case(2500000);
	_case(3000000);
	_case(3500000);
	_case(4000000);
	default:
		pr_err("%d is not a recognized baud rate\n", baudrate);
		return -1;
	}

#undef _case
}

int register_uart_controller(const char *file_name, int baudrate)
{
	int ret;
	struct termios tio;
	struct controller *ctrl;
	struct uart_controller *uart_ctrl;

	speed_t speed = to_speed_t(baudrate);
	if ((speed_t)-1 == speed) {
		return -EINVAL;
	}

	uart_ctrl = malloc(sizeof(*uart_ctrl));
	if (!uart_ctrl)
		return -ENOMEM;

	uart_ctrl->fd = open(file_name, O_RDWR | O_NOCTTY);
	if (uart_ctrl->fd < 0) {
		free(uart_ctrl);
		return uart_ctrl->fd;
	}

	cfmakeraw(&tio);
	cfsetspeed(&tio, speed);
	tio.c_cc[VMIN] = 1; // 1 character minimum
	tio.c_cc[VTIME] = 1; // 100ms timeout

	ret = tcsetattr(uart_ctrl->fd, TCSANOW, &tio);
	if (ret < 0) {
		close(uart_ctrl->fd);
		free(uart_ctrl);
	}

	tcflush(uart_ctrl->fd, TCIFLUSH);
	ctrl = malloc(sizeof(*ctrl));
	if (!ctrl) {
		close(uart_ctrl->fd);
		free(uart_ctrl);
		return -ENOMEM;
	}

	memcpy(ctrl, &uart_controller, sizeof(*ctrl));
	ctrl->priv = uart_ctrl;
	register_controller(ctrl);

	return 0;
}

static int uart_init(struct controller * ctrl)
{
	return 0;
}

static void uart_exit(struct controller * ctrl)
{
	struct uart_controller *uart_ctrl = ctrl->priv;

	close(uart_ctrl->fd);
	free(uart_ctrl);
}

static int uart_hotplug(struct controller *ctrl)
{
	int ret;
	struct interface *intf;

	/* FIXME: use real IDs */
	intf = interface_create(ctrl, 1, 1, 0x1234, NULL);
	if (!intf)
		return -ENOMEM;

	ret = interface_hotplug(intf);
	if (ret < 0) {
		interface_destroy(intf);
		return ret;
	}

	return 0;
}

static int uart_write(struct connection * conn, void *data, size_t len)
{
	int r;
	size_t remaining;
	size_t offset;
	size_t written;

	struct uart_controller *ctrl = conn->intf2->ctrl->priv;

	cport_pack(data, conn->cport2_id);

	for(remaining = len, offset = 0, written = 0; remaining; remaining -= written, offset += written, written = 0) {
		r = write(ctrl->fd, &((uint8_t *)data)[offset], remaining);
		if (-1 == r) {
			r = -errno;
			pr_err("%s(): write failed: %s\n", __func__, strerror(errno));
			goto out;
		}
		written = r;
	}

	r = len;

out:
	return r;
}

static int _uart_read(struct uart_controller *ctrl,
		      void *data, size_t len)
{
	int ret;
	size_t remaining;
	size_t offset;
	size_t recvd;

	if (0 == len) {
		return 0;
	}

	for(remaining = len, offset = 0, recvd = 0; remaining; remaining -= recvd, offset += recvd, recvd = 0) {
		ret = read(ctrl->fd, &((uint8_t *)data)[offset], remaining);
		if (-1 == ret) {
			if (EAGAIN == errno) {
				continue;
			}
			ret = -errno;
			pr_err("%s(): read: %s\n", __func__, strerror(errno));
			return ret;
		}
		recvd = ret;
	}

	return 0;
}

static int uart_read(struct interface * intf,
		     uint16_t * cport_id, void *data, size_t len)
{
	int ret;
	uint8_t *p_data = data;
	struct uart_controller *ctrl = intf->ctrl->priv;
	size_t msg_size;
	size_t payload_size;

	ret = _uart_read(ctrl, p_data, sizeof(struct gb_operation_msg_hdr));
	if (ret) {
		pr_err("Failed to get header\n");
		return ret;
	}

	msg_size = gb_operation_msg_size(data);
	payload_size = msg_size - sizeof(struct gb_operation_msg_hdr);
	p_data += sizeof(struct gb_operation_msg_hdr);

	ret = _uart_read(ctrl, p_data, payload_size);
	if (ret < 0) {
		pr_err("Failed to get payload\n");
		return ret;
	}

	*cport_id = cport_unpack(data);

	return msg_size;
}

struct controller uart_controller = {
	.name = "uart",
	.init = uart_init,
	.exit = uart_exit,
	.write = uart_write,
	.intf_read = uart_read,
	.event_loop = uart_hotplug,
};
