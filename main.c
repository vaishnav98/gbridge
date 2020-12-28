/*
 * GBridge (Greybus Bridge)
 * Copyright (c) 2016 Alexandre Bailon
 *
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
 */

#include <errno.h>
#include <signal.h>
#include <unistd.h>

#include <debug.h>
#include <controller.h>

#include "gbridge.h"
#include "controllers/uart.h"
#include "controllers/tls.h"

int run;

static void help(void)
{
	printf("gbridge: Greybus bridge application\n"
		"\t-h: Print the help\n"
#ifdef HAVE_UART
		"uart options:\n"
		"\t-p uart_device: set the uart device\n"
		"\t-b baudrate: set the uart baudrate\n"
#endif
#ifdef HAVE_TLS
		"tls options:\n"
		"\t-a ca_cert: set the CA certificate\n"
		"\t-c client_cert: set the client certificate\n"
		"\t-k client_key: set the client key\n"
#endif
		);
}

static void signal_handler(int sig)
{
	run = 0;
}

int main(int argc, char *argv[])
{
	int c;
	int ret;

	int baudrate = 115200;
	const char *uart = NULL;

#ifdef HAVE_TLS
	const char *ca_cert = NULL;
	const char *client_cert = NULL;
	const char *client_key = NULL;
#endif

	signal(SIGINT, signal_handler);
	signal(SIGHUP, signal_handler);
	signal(SIGTERM, signal_handler);

	register_controllers();

	while ((c = getopt(argc, argv, "p:b:m:a:c:k:")) != -1) {
		switch(c) {
		case 'p':
			uart = optarg;
			break;
		case 'b':
			if (sscanf(optarg, "%u", &baudrate) != 1) {
				help();
				return -EINVAL;
			}
			break;
		case 'm':
#ifdef GBSIM
			ret = register_gbsim_controller(optarg);
			if (ret)
				return ret;
			break;
#else
			pr_err("You must build gbridge with gbsim enabled\n");
			return -EINVAL;
#endif
#ifdef HAVE_TLS
		case 'a':
			ca_cert = optarg;
			break;
		case 'c':
			client_cert = optarg;
			break;
		case 'k':
			client_key = optarg;
			break;
#else
			pr_err("You must build gbridge with tls enabled\n");
			return -EINVAL;
#endif
		default:
			help();
			return -EINVAL;
		}
	}

	ret = greybus_init();
	if (ret) {
		pr_err("Failed to init Greybus\n");
		return ret;
	}

	if (uart) {
		ret = register_uart_controller(uart, baudrate);
		if (ret)
			return ret;
	}

#ifdef HAVE_TLS
	ret = gbridge_tls_init(ca_cert, client_cert, client_key);
	if (ret) {
		pr_err("gbridge_tls_init() failed (%d)\n", ret);
		return ret;
	}
#endif

	run = 1;
	controllers_init();
	while(run)
		sleep(1);
	controllers_exit();

	return 0;
}
