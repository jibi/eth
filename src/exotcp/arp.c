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

#include <glib.h>

#include <eth/netmap.h>

#include <eth/exotcp.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/arp.h>

/* this is a "prebuild" arp reply packet, so when we need to respond we just
 * need to set target mac and ip address:
 *
 * assumption:
 * - we are in an ethernet network
 * - we use ipv4 addresses
 */

struct {
	eth_hdr_t eth;
	arp_hdr_t arp;
} prebuild_arp_packet;

static void
init_prebuild_arp_packet() {

	init_eth_packet(&prebuild_arp_packet.eth, ETH_TYPE_ARP);

	prebuild_arp_packet.arp.hw_type        = ARP_HW_TYPE_ETHERNET;
	prebuild_arp_packet.arp.proto_type     = ARP_PROTO_TYPE_IP;
	prebuild_arp_packet.arp.hw_addr_len    = sizeof(struct ether_addr);
	prebuild_arp_packet.arp.proto_addr_len = sizeof(struct in_addr);
	prebuild_arp_packet.arp.opcode         = ARP_OPCODE_REPLY;

	memcpy(prebuild_arp_packet.arp.sender_hw_addr, &mac_addr, sizeof(struct ether_addr));
	memcpy(prebuild_arp_packet.arp.sender_proto_addr, &ip_addr, sizeof(struct in_addr));
}

void
init_arp() {

	init_prebuild_arp_packet();
}

static void
process_arp_request() {

	setup_eth_hdr(&prebuild_arp_packet.eth);

	memcpy(prebuild_arp_packet.arp.target_hw_addr, cur_pkt->arp_hdr->sender_hw_addr, sizeof(struct ether_addr));
	memcpy(prebuild_arp_packet.arp.target_proto_addr, cur_pkt->arp_hdr->sender_proto_addr, sizeof(struct in_addr));

	nm_send_packet(&prebuild_arp_packet, sizeof(prebuild_arp_packet));
}

void
process_arp() {

	cur_pkt->arp_hdr = (arp_hdr_t *) (cur_pkt->buf + sizeof(eth_hdr_t));

	if (likely(cur_pkt->arp_hdr->opcode == ARP_OPCODE_REQUEST)) {
		process_arp_request();
	}
}

