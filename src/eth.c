#include <stdio.h>

#include <eth/log.h>
#include <eth/yoctonet.h>
#include <eth/yoctonet/eth.h>
#include <eth/netmap.h>

int
main(int argc, char *argv[]) {
	log_info("Hi, this is ETH!");

	init_netmap("ens4");
	init_yoctonet();

	netmap_recv_loop(process_eth);

	return 0;
}

