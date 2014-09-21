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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include <eth.h>
#include <eth/exotcp.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/arp.h>
#include <eth/exotcp/ip.h>
#include <eth/exotcp/tcp.h>

unsigned char broadcast_addr[] = "\xff\xff\xff\xff\xff\xff";

void
init_eth_packet(eth_hdr_t *eth_hdr) {
	memcpy(eth_hdr->mac_src, &mac_addr, sizeof(struct ether_addr));
	eth_hdr->mac_type = ETH_TYPE_IPV4;
}

void
setup_eth_hdr(eth_hdr_t *eth_hdr, tcp_conn_t *conn) {
	memcpy(eth_hdr->mac_dst, conn->src_mac, sizeof(struct ether_addr));
}

void
process_eth(char *packet_buf, size_t len) {
	eth_hdr_t *eth_hdr = (eth_hdr_t *) packet_buf;
	packet_t *p;

	dump_eth_hdr(eth_hdr);

	if (unlikely(!(is_this_card_mac((struct ether_addr *) eth_hdr->mac_dst) ||
		is_broadcast_addr((struct ether_addr *) eth_hdr->mac_dst)))) {
		printf("this is not the packet you are looking for\n");
		return;
	}

	p= malloc(sizeof(packet_t));
	p->buf     = packet_buf;
	p->eth_hdr = (eth_hdr_t *) packet_buf;
	p->len     = len;

	if (eth_hdr->mac_type == ETH_TYPE_IPV4) {
		process_ip(p);
	} else if (eth_hdr->mac_type == ETH_TYPE_ARP) {
		process_arp(p);
	}
}

void
dump_eth_hdr(eth_hdr_t __attribute__ ((unused)) *hdr) {
#if defined DEBUG && defined DUMP_PACKET
	char *mac_dst = format_eth_addr(hdr->mac_dst);
	char *mac_src = format_eth_addr(hdr->mac_src);

	printf("[eth hdr]\n");
	printf("\tmac dst: %s\n", mac_dst);
	printf("\tmac src: %s\n", mac_src);
	printf("\tether type: 0x%04x\n", ntohs(hdr->mac_type));

	free(mac_dst);
	free(mac_src);
#endif
}

char *
format_eth_addr(unsigned char *a) {
	char *ptr;
	asprintf(&ptr, "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5]);

	return ptr;
}

int
is_broadcast_addr(struct ether_addr *a) {
	return ! memcmp(a, broadcast_addr, sizeof(struct ether_addr));
}

