/*
 * Copyright (C) 2014 jibi <jibi@paranoici.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdio.h>
#include <getopt.h>

#include <eth/log.h>
#include <eth/exotcp.h>
#include <eth/exotcp/eth.h>
#include <eth/netmap.h>

static
void
usage(void)
{
	printf("usage: eth [options]\n");
	printf("options are:\n");
	printf("  --dev [device]:    the device name\n");
	printf("  --mac [mac addr]: the device mac address\n");
	printf("  --ip [ip addr]:   the device ip address\n");
	printf("  --port [port]:    the bind port\n");
}

static
void
signal_handler(int signo)
{
	exit(0);
}

int
main(int argc, char *argv[])
{
	char *dev, *mac, *ip;
	uint16_t port;

	dev  = NULL;
	mac  = NULL;
	ip   = NULL;
	port = 0;

	while (1) {
		int option_index = 0;
		int c;

		static struct option long_options[] = {
			{"dev",  required_argument, 0, 'd'},
			{"mac",  required_argument, 0, 'm'},
			{"ip",   required_argument, 0, 'i'},
			{"port", required_argument, 0, 'p'},
			{0, 0, 0, 0}
		};

		c = getopt_long (argc, argv, "d:m:i:p:", long_options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
			case 'd':
				dev  = optarg;
				break;
			case 'm':
				mac = optarg;
				break;
			case 'i':
				ip  = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case '?':
				usage();
				break;
			default:
				abort ();
		}
	}

	if (!dev) {
		fatal_tragedy(1, "you need to specify a device");
	}

	if (!mac) {
		fatal_tragedy(1, "you need to specify the device's mac address");
	}

	if (!ip) {
		fatal_tragedy(1, "you need to specify the device's ip address");
	}

	if (!port) {
		fatal_tragedy(1, "you need to specify the listening port");
	}

	signal(SIGINT, signal_handler);
	signal(SIGQUIT, signal_handler);

	log_info("Hi, this is Eth version %s", ETH_VERSION);

	init_netmap(dev);
	init_exotcp(mac, ip, port);

	nm_loop();

	return 0;
}

