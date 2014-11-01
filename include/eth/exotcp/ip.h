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

#ifndef _ETH_EXOTCP_IP_H
#define _ETH_EXOTCP_IP_H

#include <stdint.h>

#include <eth/exotcp.h>
#include <eth/exotcp/tcp.h>

typedef struct ip_hdr_s {
	uint32_t hdr_len:4;
	uint32_t version:4;
	uint8_t  tos;
	uint16_t total_len;
	uint16_t id;
	uint16_t frag_offset;
	uint8_t  ttl;
	uint8_t  proto;
	uint16_t checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
} __attribute__ ((packed)) ip_hdr_t;

#define IP_PROTO_ICMP 0x1
#define IP_PROTO_TCP  0x6

#define ip_data_len(ip_hdr) (ntohs(ip_hdr->total_len) - sizeof(ip_hdr_t))

void init_ip_packet(ip_hdr_t *ip_hdr, uint16_t data_len, uint8_t proto);
void setup_ip_hdr(ip_hdr_t *ip_hdr, uint16_t payload_len);
void process_ip(void);

#endif

