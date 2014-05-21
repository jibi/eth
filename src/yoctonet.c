#include <eth/yoctonet.h>
#include <eth/yoctonet/card.h>
#include <eth/yoctonet/eth.h>
#include <eth/yoctonet/arp.h>

void
init_yoctonet() {
	init_card_defaults();
	init_arp();
}
