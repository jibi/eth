#include <string.h>
#include <eth/log.h>

#include <eth.h>
#include <eth/exotcp.h>
#include <eth/exotcp/checksum.h>
#include <eth/exotcp/card.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/ip.h>
#include <eth/exotcp/tcp.h>

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
init_ip_packet(ip_hdr_t *ip_hdr) {
	ip_hdr->version          = 4;
	ip_hdr->hdr_len          = 5;
	ip_hdr->tos              = 0;
	ip_hdr->total_len        = HTONS(sizeof(ip_hdr_t) + sizeof(tcp_hdr_t) + sizeof(tcp_syn_ack_opts_t));
	ip_hdr->id               = 0;
	ip_hdr->frag_offset      = HTONS(0x4000); /* dont fragment */
	ip_hdr->ttl              = 64;
	ip_hdr->proto            = IP_PROTO_TCP;

	memcpy(&ip_hdr->src_addr, &ip_addr, sizeof(struct in_addr));
}
