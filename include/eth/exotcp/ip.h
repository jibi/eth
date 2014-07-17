#include <stdint.h>

#include <eth/exotcp.h>

typedef struct ip_hdr_s {
	uint32_t hdr_len:4;
	uint32_t version:4;
	uint8_t  tos;
	uint16_t total_len;
	uint16_t id;
	uint16_t frag_offset;
	uint8_t  ttl;
	uint8_t  proto;
	uint16_t check;
	uint32_t src_addr;
	uint32_t dst_addr;
} __attribute__ ((packed)) ip_hdr_t;

#define IP_PROTO_TCP 0x6

void process_ip(packet_t *p);
void init_ip_packet(ip_hdr_t *ip_hdr, uint16_t opt_len, uint16_t payload_len);

