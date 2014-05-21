#define _GNU_SOURCE
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

#include <eth.h>
#include <eth/yoctonet.h>
#include <eth/yoctonet/card.h>

struct ether_addr mac_addr;
struct in_addr    ip_addr;

void
init_card(const char *ascii_mac_addr, const char *ascii_ip_addr) {
	ether_aton_r(ascii_mac_addr, &mac_addr);
	inet_aton(ascii_ip_addr, &ip_addr);
}

void
init_card_defaults() {
	init_card(DEFAULT_MAC, DEFAULT_IP);
}

int
is_this_card_mac(struct ether_addr *addr) {
	return ! memcmp(&mac_addr, addr, sizeof(struct ether_addr));
}

int
is_this_card_ip(struct in_addr *addr) {
	return ! memcmp(&ip_addr, addr, sizeof(struct in_addr));
}

