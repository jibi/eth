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

#include <eth/netmap.h>

#include <eth/exotcp.h>
#include <eth/exotcp/checksum.h>

#include <eth/exotcp/eth.h>
#include <eth/exotcp/ip.h>
#include <eth/exotcp/icmp.h>

struct {
	eth_hdr_t           eth;
	ip_hdr_t            ip;
	icmp_echo_rpl_hdr_t icmp;
} preinit_icmp_packet;

static
uint16_t
icmp_echo_rpl_checksum(icmp_echo_rpl_hdr_t *icmp_echo_req_hdr, void *data, uint32_t data_len)
{
	uint32_t sum = 0;

	icmp_echo_req_hdr->checksum = 0;

	sum = partial_checksum(sum, (const uint8_t *) icmp_echo_req_hdr, sizeof(icmp_echo_rpl_hdr_t));
	sum = finalize_checksum(sum, data, data_len);

	return sum;
}

static
void
init_preinit_icmp_packet()
{
	init_eth_packet(&preinit_icmp_packet.eth, ETH_TYPE_IPV4);
	init_ip_packet(&preinit_icmp_packet.ip, 0, IP_PROTO_ICMP);

	preinit_icmp_packet.icmp.type = ICMP_TYPE_ECHO_RPL;
	preinit_icmp_packet.icmp.code = 0;
}

void
init_icmp()
{
	init_preinit_icmp_packet();
}

static
void
process_icmp_echo_request()
{
	uint8_t  *data;
	uint16_t data_len;

	data     = icmp_echo_req_data(cur_pkt);
	data_len = icmp_echo_req_data_len(cur_pkt);

	setup_eth_hdr(&preinit_icmp_packet.eth);
	setup_ip_hdr(&preinit_icmp_packet.ip, sizeof(icmp_echo_rpl_hdr_t) + data_len);

	preinit_icmp_packet.icmp.id       = cur_pkt->icmp_echo_req_hdr->id;
	preinit_icmp_packet.icmp.seq      = cur_pkt->icmp_echo_req_hdr->seq;
	preinit_icmp_packet.icmp.checksum = icmp_echo_rpl_checksum(&preinit_icmp_packet.icmp, data, data_len);

	nm_send_packet_with_data(&preinit_icmp_packet, sizeof(preinit_icmp_packet), data, data_len);
}

void
process_icmp()
{
	cur_pkt->icmp_echo_req_hdr = (icmp_echo_req_hdr_t *) (cur_pkt->buf + sizeof(eth_hdr_t) + sizeof(ip_hdr_t));

	if (cur_pkt->icmp_echo_req_hdr->type == ICMP_TYPE_ECHO_REQ) {
		process_icmp_echo_request();
	}
}

