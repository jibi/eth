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

#include <eth/log.h>
#include <eth/exotcp.h>
#include <eth/exotcp/eth.h>
#include <eth/netmap.h>

int
main(int argc, char *argv[]) {
	char *ifname, *macaddr, *ipaddr;
	uint16_t port;

	if (argc < 5) {
		fatal_tragedy(1, "Usage: %s ifname macaddr ipaddr port", argv[0]);
	}

	log_info("Hi, this is ETH!");

	/*
	 * TODO: improve args handling
	 */

	ifname  = argv[1];
	macaddr = argv[2];
	ipaddr  = argv[3];
	port    = atoi(argv[4]);

	init_netmap(ifname);
	init_exotcp(macaddr, ipaddr, port);

	netmap_recv_loop(process_eth);

	return 0;
}

