#include <stdint.h>

typedef struct arp_hdr_s {
	uint16_t hw_type;
	uint16_t proto_type;
	uint8_t  hw_addr_len;
	uint8_t  proto_addr_len;
	uint16_t opcode;
	uint8_t  sender_hw_addr[6];
	uint8_t  sender_proto_addr[4];
	uint8_t  target_hw_addr[6];
	uint8_t  target_proto_addr[4];
} __attribute__ ((packed)) arp_hdr_t;

#define ARP_HW_TYPE_ETHERNET 0x1
#define ARP_PROTO_TYPE_IP    0x8

#define ARP_OPCODE_REQUEST   0x1
#define ARP_OPCODE_REPLY     0x2


void init_arp();
void process_arp(char *packet_buf);
void dump_arp_hdr(arp_hdr_t *hdr);


