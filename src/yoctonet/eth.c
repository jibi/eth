#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include <eth.h>
#include <eth/yoctonet.h>
#include <eth/yoctonet/card.h>
#include <eth/yoctonet/eth.h>
#include <eth/yoctonet/arp.h>
#include <eth/yoctonet/ip.h>

unsigned char broadcast_addr[] = "\xff\xff\xff\xff\xff\xff";

void
process_eth(char *packet_buf) {
	eth_hdr_t *eth_hdr = (eth_hdr_t *) packet_buf;

	dump_eth_hdr(eth_hdr);

	if (unlikely(!(is_this_card_mac((struct ether_addr *) eth_hdr->mac_dst) ||
		is_broadcast_addr((struct ether_addr *) eth_hdr->mac_dst)))) {
		printf("this is not the packet you are looking for\n");
		return;
	}


	if (eth_hdr->mac_type == ETH_TYPE_IPV4) {
		process_ip(packet_buf);
	} else if (eth_hdr->mac_type == ETH_TYPE_ARP) {
		process_arp(packet_buf);
	}
}

void
dump_eth_hdr(eth_hdr_t __attribute__ ((unused)) *hdr) {
#ifdef DEBUG
	char *mac_dst = format_eth_addr(hdr->mac_dst);
	char *mac_src = format_eth_addr(hdr->mac_src);

	printf("[eth hdr]\n");
	printf("\tmac dst: %s\n", mac_dst);
	printf("\tmac src: %s\n", mac_src);
	printf("\tether type: 0x%04x\n", ntohs(hdr->mac_type));

	free(mac_dst);
	free(mac_src);
#endif
}

char *
format_eth_addr(unsigned char *a) {
	char *ptr;
	asprintf(&ptr, "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3], a[4], a[5]);

	return ptr;
}

int
is_broadcast_addr(struct ether_addr *a) {
	return ! memcmp(a, broadcast_addr, sizeof(struct ether_addr));
}

