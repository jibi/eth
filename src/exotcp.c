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
#include <eth/exotcp/tcp.h>

struct ether_addr mac_addr;
struct in_addr    ip_addr;
uint16_t          listening_port;
packet_t          *cur_pkt;
socket_t          *cur_sock;

void
init_exotcp(char *mac, char *ip, uint16_t port) {
	ether_aton_r(mac, &mac_addr);
	inet_aton(ip, &ip_addr);
	listening_port = port;

	init_arp();
	init_tcp();
}

int
is_this_card_mac(struct ether_addr *addr) {
	return ! memcmp(&mac_addr, addr, sizeof(struct ether_addr));
}

int
is_this_card_ip(struct in_addr *addr) {
	return ! memcmp(&ip_addr, addr, sizeof(struct in_addr));
}

