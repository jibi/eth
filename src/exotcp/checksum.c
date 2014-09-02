/*
 * Copyright (C) 2014 jibi <jibi@paranoici.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

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

