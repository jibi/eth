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

#ifndef _ETH_EXOTCP_CHECKSUM_H
#define _ETH_EXOTCP_CHECKSUM_H

#include <stdlib.h>
#include <stdint.h>

uint16_t checksum(const uint8_t *buf, uint32_t size);

/* partial and finalize checksum are used to calc tcp checksum (otherwise we
 * would need to build a copy of the packet to pass a continous buffer preceeded
 * with the tcp pseudo header */

uint64_t partial_checksum(uint64_t sum, const uint8_t *buf, uint32_t size);
uint16_t finalize_checksum(uint64_t sum, const uint8_t *buf, uint32_t size);

#endif

