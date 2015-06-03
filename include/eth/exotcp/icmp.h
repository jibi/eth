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

#ifndef _ETH_EXOTCP_ICMP_H
#define _ETH_EXOTCP_ICMP_H

#include <stdint.h>

#include <eth/exotcp.h>
#include <eth/exotcp/ipv4.h>

typedef struct icmp_echo_req_hdr_s {
	uint8_t  type;
	uint8_t  code;
	uint16_t checksum;

	uint16_t id;
	uint16_t seq;
} __attribute__ ((packed)) icmp_echo_req_hdr_t;

#define icmp_echo_req_data(x)     (((uint8_t *) x->icmp_echo_req_hdr) + sizeof(icmp_echo_req_hdr_t))
#define icmp_echo_req_data_len(x) (ipv4_data_len(x->ip_hdr) - sizeof(icmp_echo_req_hdr_t))

typedef struct icmp_echo_rpl_hdr_s {
	uint8_t  type;
	uint8_t  code;
	uint16_t checksum;

	uint16_t id;
	uint16_t seq;
} __attribute__ ((packed)) icmp_echo_rpl_hdr_t;

#define ICMP_TYPE_ECHO_RPL 0
#define ICMP_TYPE_ECHO_REQ 8

void init_icmp(void);
void process_icmp(void);

#endif

