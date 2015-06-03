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

#include <string.h>
#include <stdint.h>
#include <stddef.h>

#include <arpa/inet.h>
#include <net/ethernet.h>

#define HTONS(x) ((((x) & 0xff00) >> 8) | (((x) & 0x00ff) << 8))
#define HTONL(x) ((((x) & 0xff000000) >> 24) | (((x) & 0xff0000) >> 8) | (((x) & 0xff00) << 8) | (((x) & 0xff) << 24))

struct eth_hdr_s;
struct ipv4_hdr_s;
struct arp_hdr_s;
struct tcp_hdr_s;

typedef struct packet_s {
	struct eth_hdr_s *eth_hdr;

	union {
		struct ipv4_hdr_s *ip_hdr;
		struct arp_hdr_s  *arp_hdr;
	};

	union {
		struct tcp_hdr_s *tcp_hdr;
		struct icmp_echo_req_hdr_s *icmp_echo_req_hdr;
	};

	char *buf;
	size_t len;
} packet_t;

typedef struct socket_s {
	uint8_t  src_mac[6];
	uint32_t src_ip;
	uint16_t src_port;
} socket_t;

extern struct ether_addr mac_addr;
extern struct in_addr    ip_addr;
extern uint16_t          listening_port;
extern packet_t          *cur_pkt;
extern socket_t          *cur_sock;

void init_exotcp(char *mac, char *ip, uint16_t port);

#define set_cur_pkt(x)  cur_pkt = x;
#define set_cur_sock(x) cur_sock = x;

static inline
int
is_this_card_mac(struct ether_addr *addr)
{
	return ! memcmp(&mac_addr, addr, sizeof(struct ether_addr));
}

static inline
int
is_this_card_ip(struct in_addr *addr)
{
	return ! memcmp(&ip_addr, addr, sizeof(struct in_addr));
}

#endif
