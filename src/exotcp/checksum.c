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

#include <eth.h>
#include <eth/exotcp/checksum.h>

uint16_t
checksum(const uint8_t *buf, uint32_t size)
{
	return finalize_checksum(0, buf, size);
}

/*
 * based on this: http://locklessinc.com/articles/tcp_checksum/
 */
uint64_t
partial_checksum(uint64_t sum, const uint8_t *buf, uint32_t size)
{
	const uint64_t *b = (uint64_t *) buf;

	uint64_t s64;
	uint32_t s32;
	uint16_t s16;
	uint8_t  s8;

	while (size >= sizeof(uint64_t)) {
		s64 = *b++;

		sum += s64;
		if (sum < s64) {
			sum++;
		}

		size -= 8;
	}

	buf = (const uint8_t *) b;
	if (size & 4) {
		s32 = *(unsigned *)buf;

		sum += s32;
		if (sum < s32) {
			sum++;
		}

		buf += 4;
	}

	if (size & 2) {
		s16 = *(uint16_t *) buf;

		sum += s16;
		if (sum < s16) {
			sum++;
		}

		buf += 2;
	}

	if (size & 1) {
		s8 = *(uint8_t *) buf;

		sum += s8;
		if (sum < s8) {
			sum++;
		}
	}

	return sum;
}

uint16_t
finalize_checksum(uint64_t sum, const uint8_t *buf, uint32_t size)
{
	uint32_t t1, t2;
	uint16_t t3, t4;

	sum = partial_checksum(sum, buf, size);

	t1 = sum;
	t2 = sum >> 32;
	t1 += t2;
	if (t1 < t2) {
		t1++;
	}

	t3 = t1;
	t4 = t1 >> 16;
	t3 += t4;
	if (t3 < t4) {
		t3++;
	}

	return ~t3;
}

