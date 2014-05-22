#include <stdio.h>

#include <eth/log.h>
#include <eth/exotcp.h>
#include <eth/exotcp/eth.h>
#include <eth/netmap.h>

int
main(int argc, char *argv[]) {
	log_info("Hi, this is ETH!");

	init_netmap("ens4");
	init_exotcp();

	netmap_recv_loop(process_eth);

	return 0;
}

