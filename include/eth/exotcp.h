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

#ifndef _ETH_EXOTCP_H
#define _ETH_EXOTCP_H

#include <stdint.h>
#include <stddef.h>

#include <arpa/inet.h>
#include <net/ethernet.h>

#define HTONS(x) ((((x) & 0xff00) >> 8) | (((x) & 0x00ff) << 8))
#define HTONL(x) ((((x) & 0xff000000) >> 24) | (((x) & 0xff0000) >> 8) | (((x) & 0xff00) << 8) | (((x) & 0xff) << 24))

extern struct ether_addr mac_addr;
extern struct in_addr    ip_addr;
extern uint16_t          listening_port;

void init_exotcp(char *mac, char *ip, uint16_t port);

int is_this_card_mac(struct ether_addr *addr);
int is_this_card_ip(struct in_addr *addr);

struct eth_hdr_s;
struct ip_hdr_s;
struct arp_hdr_s;
struct tcp_hdr_s;

typedef struct packet_s {
	struct eth_hdr_s *eth_hdr;

	union {
		struct ip_hdr_s  *ip_hdr;
		struct arp_hdr_s *arp_hdr;
	};

	struct tcp_hdr_s *tcp_hdr;

	char *buf;
	size_t len;
} packet_t;

#endif
