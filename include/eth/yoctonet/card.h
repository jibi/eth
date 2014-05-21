#include <arpa/inet.h>
#include <net/ethernet.h>

#define DEFAULT_MAC "52:54:00:12:34:57"
#define DEFAULT_IP  "192.168.12.2"

struct ether_addr mac_addr;
struct in_addr    ip_addr;

void init_card(const char *ascii_mac_addr, const char *ascii_ip_addr);
void init_card_defaults();

int is_this_card_mac(struct ether_addr *addr);
int is_this_card_ip(struct in_addr *addr);

