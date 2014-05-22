#include <eth/log.h>

#include <eth.h>
#include <eth/exotcp.h>
#include <eth/exotcp/card.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/ip.h>
#include <eth/exotcp/tcp.h>

void
process_ip(char *packet_buf) {
	ip_hdr_t *ip_hdr = (ip_hdr_t *) (packet_buf + sizeof(eth_hdr_t));

	if (unlikely(! is_this_card_ip((struct in_addr *) &ip_hdr->dst_addr))) {
		log_debug1("this is not the packet you are looking for\n");
		return;
	}

	if (ip_hdr->proto == IP_PROTO_TCP) {
		process_tcp(packet_buf);
	}
}


