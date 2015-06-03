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

#define _GNU_SOURCE
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include <eth/exotcp.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/arp.h>
#include <eth/exotcp/icmp.h>
#include <eth/exotcp/tcp.h>

struct ether_addr mac_addr;
struct in_addr    ipv4_addr;
struct in6_addr   ipv6_addr;
uint16_t          listening_port;
bool              ipv4_listen;
bool              ipv6_listen;

packet_t          *cur_pkt;
socket_t          *cur_sock;

void
init_exotcp(char *mac, char *ipv4, char *ipv6, uint16_t port)
{
	ipv4_listen = false;
	ipv6_listen = false;

	ether_aton_r(mac, &mac_addr);

	if (ipv4) {
		inet_aton(ipv4, &ipv4_addr);
		ipv4_listen = true;
	}

	if (ipv6) {
		inet_pton(AF_INET6, ipv6, &ipv6_addr);
		ipv6_listen = true;
	}

	listening_port = port;

	init_arp();
	init_icmp();
	init_tcp();
}


