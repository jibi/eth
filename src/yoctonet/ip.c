#include <eth/log.h>

#include <eth.h>
#include <eth/yoctonet.h>
#include <eth/yoctonet/card.h>
#include <eth/yoctonet/eth.h>
#include <eth/yoctonet/ip.h>
#include <eth/yoctonet/tcp.h>

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


