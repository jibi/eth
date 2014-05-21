#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

extern struct nm_desc *netmap;

void init_netmap(char *ifname);
void netmap_recv_loop(void (*process_packet)(char *));

