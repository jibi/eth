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
#include <eth/exotcp/icmp.h>

static inline void ipv4_checksum(ipv4_hdr_t *ip_hdr);

void
init_ipv4_packet(ipv4_hdr_t *ip_hdr, uint16_t data_len, uint8_t proto)
{
	ip_hdr->version     = 4;
	ip_hdr->hdr_len     = 5;
	ip_hdr->tos         = 0;
	/*
	 * data_len is the ip payload length.
	 * For example, given a TCP ack packet it should be sizeof(tcp_hdr_t) + sizeof(tcp_ack_opts_t),
	 */
	ip_hdr->total_len   = HTONS(sizeof(ipv4_hdr_t) + data_len);
	ip_hdr->id          = 0;
	ip_hdr->frag_offset = HTONS(0x4000); /* dont fragment */
	ip_hdr->ttl         = 64;
	ip_hdr->proto       = proto;

	memcpy(&ip_hdr->src_addr, &ip_addr, sizeof(struct in_addr));
}

void
setup_ipv4_hdr(ipv4_hdr_t *ip_hdr, uint16_t new_data_len)
{
	ip_hdr->dst_addr = cur_sock->src_ip;

	if (new_data_len) {
		ip_hdr->total_len = HTONS(sizeof(ipv4_hdr_t) + new_data_len);
	}

	ipv4_checksum(ip_hdr);
}

void
process_ipv4(void)
{
	cur_pkt->ip_hdr  = (ipv4_hdr_t *) (cur_pkt->buf + sizeof(eth_hdr_t));
	cur_sock->src_ip = cur_pkt->ip_hdr->src_addr;

	if (unlikely(cur_pkt->ip_hdr->version != 4)) {
		log_debug1("this is not the packet you are looking for");
		return;
	}

	if (unlikely(! is_this_card_ip((struct in_addr *) &cur_pkt->ip_hdr->dst_addr))) {
		log_debug1("this is not the packet you are looking for");
		return;
	}

	switch(cur_pkt->ip_hdr->proto) {
		case IP_PROTO_TCP:
			process_tcp();  break;
		case IP_PROTO_ICMP:
			process_icmp(); break;
	}
}

static inline
void
ipv4_checksum(ipv4_hdr_t *ip_hdr)
{
	ip_hdr->checksum = 0;
	ip_hdr->checksum = checksum((uint8_t *) ip_hdr, sizeof(ipv4_hdr_t));
}

