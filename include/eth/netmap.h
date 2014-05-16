#include <net/netmap.h>

struct netmap_if *open_netmap_if(const char *ifname, int *ret_fd);
void receiver(int fd, struct netmap_if *nifp);

