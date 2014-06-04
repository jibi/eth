#include <eth/log.h>

#include <eth.h>
#include <eth/exotcp.h>
#include <eth/exotcp/card.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/ip.h>
#include <eth/exotcp/tcp.h>

void
process_ip(packet_t *packet) {
	packet->ip_hdr = (ip_hdr_t *) (packet + sizeof(eth_hdr_t));

	if (unlikely(! is_this_card_ip((struct in_addr *) &packet->ip_hdr->dst_addr))) {
		log_debug1("this is not the packet you are looking for\n");
		return;
	}

	if (packet->ip_hdr->proto == IP_PROTO_TCP) {
		process_tcp(packet);
	}
}

void
ip_checksum(packet_t *p) {
	uint32_t len = p->ip_hdr->hdr_len * 4;
	uint8_t *buf = (uint8_t *) p->ip_hdr;
	uint32_t tmp = 0;
	uint32_t sum = 0;
	uint32_t i   = 0;

	for( i = 0; i < len; i += 2u) {
		tmp  = buf[i];
		sum += (tmp << 8lu);

		if (len > (i + 1u)) {
			sum += buf[i + 1];
		}
	}

	while (sum >> 16) {
		sum = (sum & 0x0000FFFF) + (sum >> 16);
	}

	p->ip_hdr->check = (uint16_t) ~sum;
}

