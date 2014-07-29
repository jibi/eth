#include <stdio.h>

#include <eth/log.h>
#include <eth/exotcp.h>
#include <eth/exotcp/eth.h>
#include <eth/netmap.h>

int
main(int argc, char *argv[]) {
	char *ifname, *macaddr, *ipaddr;
	uint16_t port;

	if (argc < 5) {
		fatal_tragedy(1, "Usage: %s ifname macaddr ipaddr port", argv[0]);
	}

	log_info("Hi, this is ETH!");

	/*
	 * TODO: improve args handling
	 */

	ifname  = argv[1];
	macaddr = argv[2];
	ipaddr  = argv[3];
	port    = atoi(argv[4]);

	init_netmap(ifname);
	init_exotcp(macaddr, ipaddr, port);

	netmap_recv_loop(process_eth);

	return 0;
}

