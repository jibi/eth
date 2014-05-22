#include <eth/exotcp.h>
#include <eth/exotcp/card.h>
#include <eth/exotcp/eth.h>
#include <eth/exotcp/arp.h>

void
init_exotcp() {
	init_card_defaults();
	init_arp();
}
