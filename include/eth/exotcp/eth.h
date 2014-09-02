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

#ifndef _ETH_EXOTCP_ETH_H
#define _ETH_EXOTCP_ETH_H


#include <stddef.h>

#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <net/ethernet.h>

#include <eth/exotcp.h>

typedef struct eth_hdr_s {
	uint8_t  mac_dst[6];
	uint8_t  mac_src[6];
	uint16_t mac_type;
} __attribute__ ((packed)) eth_hdr_t;

#define ETH_TYPE_IPV4 HTONS(0x0800)
#define ETH_TYPE_ARP  HTONS(0x0806)

#define ETH_MTU (1500 - sizeof(eth_hdr_t))

void process_eth(char *packet_buf, size_t len);
void dump_eth_hdr(eth_hdr_t *hdr);
char *format_eth_addr(unsigned char *a);
int is_broadcast_addr(struct ether_addr *a);

#endif

