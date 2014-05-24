#ifndef _EXOTCP_H
#define _EXOTCP_H

#define HTONS(x) (((x & 0xff00) >> 8) | ((x & 0x00ff) << 8))
#define HTONL(x) (((x & 0xff000000) >> 24) | ((x & 0xff0000) >> 8) | ((x & 0xff00) << 8) | ((x & 0xff) << 24))

void init_exotcp();

struct eth_hdr_s;
struct ip_hdr_s;
struct arp_hdr_s;
struct tcp_hdr_s;

typedef struct packet_s {
	struct eth_hdr_s *eth_hdr;

	union {
	struct ip_hdr_s  *ip_hdr;
	struct arp_hdr_s *arp_hdr;
	};

	struct tcp_hdr_s *tcp_hdr;
} packet_t;

#endif
