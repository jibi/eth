/*
 * Copyright (C) 2015 jibi <jibi@paranoici.org>
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

typedef struct ipv6_hdr_s {
	uint32_t version:4;
	uint32_t useless:28; /* TODO: traffic class + flow label */
	uint16_t payload_len;
	uint8_t  next_hdr;
	uint8_t  hop_limit;
	uint16_t src_addr[8];
	uint16_t dst_addr[8];
} __attribute__ ((packed)) ipv6_hdr_t;

void init_ipv6_packet(ipv6_hdr_t *ip_hdr, uint16_t data_len, uint8_t proto);
void setup_ipv6_hdr(ipv6_hdr_t *ip_hdr, uint16_t payload_len);
void process_ipv6(void);

#endif

