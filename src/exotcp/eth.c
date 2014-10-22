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
#include <eth/log.h>

#include <eth/exotcp.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/arp.h>
#include <eth/exotcp/ip.h>
#include <eth/exotcp/tcp.h>

void
init_eth_packet(eth_hdr_t *eth_hdr, uint16_t eth_type)
{
	memcpy(eth_hdr->src_addr, &mac_addr, sizeof(struct ether_addr));
	eth_hdr->mac_type = eth_type;
}

void
setup_eth_hdr(eth_hdr_t *eth_hdr)
{
	memcpy(eth_hdr->dst_addr, cur_sock->src_mac, sizeof(struct ether_addr));
}

void
process_eth()
{
	cur_pkt->eth_hdr  = (eth_hdr_t *) cur_pkt->buf;
	memcpy(cur_sock->src_mac,cur_pkt->eth_hdr->src_addr, sizeof(struct ether_addr));

	if (unlikely(!(is_this_card_mac((struct ether_addr *) cur_pkt->eth_hdr->dst_addr) ||
		is_broadcast_addr((struct ether_addr *) cur_pkt->eth_hdr->dst_addr)))) {
		log_debug1("this is not the packet you are looking for\n");
		return;
	}

	if (likely(cur_pkt->eth_hdr->mac_type == ETH_TYPE_IPV4)) {
		process_ip();
	} else if (cur_pkt->eth_hdr->mac_type == ETH_TYPE_ARP) {
		process_arp();
	}
}

