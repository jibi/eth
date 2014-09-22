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

#include <string.h>
#include <eth/log.h>

#include <eth.h>
#include <eth/exotcp.h>
#include <eth/exotcp/checksum.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/ip.h>
#include <eth/exotcp/tcp.h>

void
init_ip_packet(ip_hdr_t *ip_hdr, uint16_t opt_len) {
	ip_hdr->version          = 4;
	ip_hdr->hdr_len          = 5;
	ip_hdr->tos              = 0;
	ip_hdr->total_len        = HTONS(sizeof(ip_hdr_t) + sizeof(tcp_hdr_t) + opt_len);
	ip_hdr->id               = 0;
	ip_hdr->frag_offset      = HTONS(0x4000); /* dont fragment */
	ip_hdr->ttl              = 64;
	ip_hdr->proto            = IP_PROTO_TCP;

	memcpy(&ip_hdr->src_addr, &ip_addr, sizeof(struct in_addr));
}

void
setup_ip_hdr(ip_hdr_t *ip_hdr, tcp_conn_t *conn, uint16_t payload_len) {
	memcpy(&ip_hdr->dst_addr, &conn->key->src_addr, sizeof(struct in_addr));

	if (payload_len) {
		ip_hdr->total_len = HTONS(sizeof(ip_hdr_t) + sizeof(tcp_hdr_t) + sizeof(tcp_data_opts_t) + payload_len);
	}

	ip_checksum(ip_hdr);
}

void
process_ip(packet_t *packet) {
	packet->ip_hdr = (ip_hdr_t *) (packet->buf + sizeof(eth_hdr_t));

	if (unlikely(! is_this_card_ip((struct in_addr *) &packet->ip_hdr->dst_addr))) {
		log_debug1("this is not the packet you are looking for\n");
		return;
	}

	if (packet->ip_hdr->proto == IP_PROTO_TCP) {
		process_tcp(packet);
	}
}

void
ip_checksum(ip_hdr_t *ip_hdr) {
	ip_hdr->check = 0;
	ip_hdr->check = checksum((uint8_t *) ip_hdr, sizeof(ip_hdr_t));
}

