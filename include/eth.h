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

#ifndef _ETH_H
#define _ETH_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

#include <sys/time.h>

#define ETH_VERSION "0.1"

#ifndef likely
#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#define MAX(a,b) __extension__({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a > _b ? _a : _b;  \
}

#define MIN(a,b) __extension__({ \
	typeof(a) _a = (a); \
	typeof(b) _b = (b); \
	_a < _b ? _a : _b;  \
})

#define ARRAY_SIZE(arr) \
		(sizeof(arr) / sizeof((arr)[0]))

static inline
uint64_t
cur_us_ts(void)
{
	struct timeval tv;

	gettimeofday(&tv, NULL);
	return 1000000 * (uint64_t) tv.tv_sec + tv.tv_usec;
}

static inline
uint32_t
cur_ms_ts(void)
{
	struct timeval tv;

	gettimeofday(&tv, 0);
	return tv.tv_sec * 1000 + tv.tv_usec / 1000;
}
#endif

