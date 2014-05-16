#ifndef INCLUDE_PICO_PCAP
#define INCLUDE_PICO_PCAP
#include "pico_config.h"
#include "pico_device.h"

void pico_netmap_destroy(struct pico_device *dev);
struct pico_device *pico_netmap_create(char *interface, char *name, uint8_t *mac);

#endif


