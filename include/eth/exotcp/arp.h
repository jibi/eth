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

#ifndef _ETH_EXOTCP_ARP_H
#define _ETH_EXOTCP_ARP_H

#include <stdint.h>

#include <eth/exotcp.h>

typedef struct arp_hdr_s {
	uint16_t hw_type;
	uint16_t proto_type;
	uint8_t  hw_addr_len;
	uint8_t  proto_addr_len;
	uint16_t opcode;
	uint8_t  sender_hw_addr[6];
	uint8_t  sender_proto_addr[4];
	uint8_t  target_hw_addr[6];
	uint8_t  target_proto_addr[4];
} __attribute__ ((packed)) arp_hdr_t;

#define ARP_HW_TYPE_ETHERNET HTONS(0x1)
#define ARP_PROTO_TYPE_IP    HTONS(0x0800)

#define ARP_OPCODE_REQUEST   HTONS(0x1)
#define ARP_OPCODE_REPLY     HTONS(0x2)

void init_arp();
void process_arp();

#endif

