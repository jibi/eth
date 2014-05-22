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
#include <eth/exotcp/card.h>
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
	memcpy(prebuild_arp_packet.eth.mac_src, &mac_addr, sizeof(struct ether_addr));
	prebuild_arp_packet.eth.mac_type       = ETH_TYPE_ARP;

	prebuild_arp_packet.arp.hw_type        = HTONS(ARP_HW_TYPE_ETHERNET);
	prebuild_arp_packet.arp.proto_type     = ARP_PROTO_TYPE_IP;
	prebuild_arp_packet.arp.hw_addr_len    = sizeof(struct ether_addr);
	prebuild_arp_packet.arp.proto_addr_len = sizeof(struct in_addr);
	prebuild_arp_packet.arp.opcode         = HTONS(ARP_OPCODE_REPLY);

	memcpy(prebuild_arp_packet.arp.sender_hw_addr, &mac_addr, sizeof(struct ether_addr));
	memcpy(prebuild_arp_packet.arp.sender_proto_addr, &ip_addr, sizeof(struct in_addr));
}

void
init_arp() {
	init_prebuild_arp_packet();
}

void
process_arp(char *packet_buf) {
	arp_hdr_t *arp_hdr = (arp_hdr_t *) (packet_buf + sizeof(eth_hdr_t));

	if (arp_hdr->opcode != HTONS(ARP_OPCODE_REQUEST)) {
		return;
	}

	dump_arp_hdr(arp_hdr);

	memcpy(prebuild_arp_packet.eth.mac_dst, arp_hdr->sender_hw_addr, sizeof(struct ether_addr));
	memcpy(prebuild_arp_packet.arp.target_hw_addr, arp_hdr->sender_hw_addr, sizeof(struct ether_addr));
	memcpy(prebuild_arp_packet.arp.target_proto_addr, arp_hdr->sender_proto_addr, sizeof(struct in_addr));

	nm_inject(netmap, &prebuild_arp_packet, sizeof(eth_hdr_t) + sizeof(arp_hdr_t));

	ioctl(NETMAP_FD(netmap), NIOCTXSYNC);
}

void
dump_arp_hdr(arp_hdr_t __attribute__ ((unused)) *hdr) {
#ifdef DEBUG
	printf("[arp hdr]\n");

	printf("\thw type: 0x%04x\n", ntohs(hdr->hw_type));
	printf("\tproto type: 0x%04x\n", ntohs(hdr->proto_type));

	printf("\thw addr len: %d\n", hdr->hw_addr_len);
	printf("\tproto addr len: %d\n\n", hdr->proto_addr_len);
#endif
}


