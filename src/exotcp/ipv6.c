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

#include <string.h>
#include <eth/log.h>

#include <eth.h>
#include <eth/exotcp.h>
#include <eth/exotcp/checksum.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/ipv6.h>

void
init_ipv6_packet(ipv6_hdr_t *ip_hdr, uint16_t data_len, uint8_t proto)
{
	ip_hdr->version     = 6;
	ip_hdr->useless     = 0;
	ip_hdr->payload_len = 0;
	ip_hdr->next_hdr    = proto;
	ip_hdr->hop_limit   = 64;

}

void
setup_ipv6_hdr(ipv6_hdr_t *ip_hdr, uint16_t new_data_len)
{

}

void
process_ipv6(void)
{

}

