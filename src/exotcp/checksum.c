#include <stdlib.h>
#include <stdint.h>

#include <eth/exotcp/checksum.h>

uint16_t
checksum(const uint8_t *buf, uint32_t size) {
	return finalize_checksum(0, buf, size);
}

uint32_t
partial_checksum(uint32_t sum, const uint8_t *buf, uint32_t size) {
	int i;

	for (i = 0; i < size - 1; i += 2) {
		uint16_t word16 = *(unsigned short *) &buf[i];
		sum += word16;
	}

	if (size & 1) {
		uint16_t word16 = (uint8_t) buf[i];
		sum += word16;
	}

	return sum;

}

uint16_t
finalize_checksum(uint32_t sum, const uint8_t *buf, uint32_t size) {
	sum = partial_checksum(sum, buf, size);

	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}

	return ~sum;
}

