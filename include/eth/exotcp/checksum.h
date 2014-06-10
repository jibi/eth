#include <stdlib.h>
#include <stdint.h>

uint16_t checksum(const char *buf, unsigned size);

/* partial and finalize checksum are used to calc tcp checksum (otherwise we
 * would need to build a copy of the packet to pass a continous buffer preceeded
 * with the tcp pseudo header */

uint32_t partial_checksum(uint32_t sum, const char *buf, unsigned size);
uint16_t finalize_checksum(uint32_t sum, const char *buf, unsigned size);

