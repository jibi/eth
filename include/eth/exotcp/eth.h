#include <stddef.h>

#include <netinet/ether.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <net/ethernet.h>

#include <eth/exotcp.h>

typedef struct eth_hdr_s {
	uint8_t  mac_dst[6];
	uint8_t  mac_src[6];
	uint16_t mac_type;
} __attribute__ ((packed)) eth_hdr_t;

#define ETH_TYPE_IPV4 HTONS(0x0800)
#define ETH_TYPE_ARP  HTONS(0x0806)

void process_eth(char *packet_buf, size_t len);
void dump_eth_hdr(eth_hdr_t *hdr);
char *format_eth_addr(unsigned char *a);
int is_broadcast_addr(struct ether_addr *a);

