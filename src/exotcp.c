#define _GNU_SOURCE
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include <eth/exotcp.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/arp.h>
#include <eth/exotcp/tcp.h>

struct ether_addr mac_addr;
struct in_addr    ip_addr;
uint16_t          listening_port;

void
init_exotcp(char *mac, char *ip, uint16_t port) {
	ether_aton_r(mac, &mac_addr);
	inet_aton(ip, &ip_addr);
	listening_port = port;

	init_arp();
	init_tcp();
}

int
is_this_card_mac(struct ether_addr *addr) {
	return ! memcmp(&mac_addr, addr, sizeof(struct ether_addr));
}

int
is_this_card_ip(struct in_addr *addr) {
	return ! memcmp(&ip_addr, addr, sizeof(struct in_addr));
}

