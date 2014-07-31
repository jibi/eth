#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

typedef struct netmap_tx_ring_desc_s {
	char *buf;
	int  i;
	uint16_t  *len;
} netmap_tx_ring_desc_t;

extern struct nm_desc *netmap;

void init_netmap(char *ifname);
void netmap_recv_loop(void (*process_packet)(char *, size_t len));
netmap_tx_ring_desc_t *netmap_get_tx_ring_buffer();

