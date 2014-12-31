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

#ifndef _ETH_DATASTRUCT_JUDY
#define _ETH_DATASTRUCT_JUDY

#include <stdio.h>
#include <stdint.h>

#include <Judy.h>

static inline
uint64_t
judy_count(uint64_t *judy_array)
{
	return JudyLCount(judy_array, 0, -1, PJE0);
}

static inline
void **
judy_get_first(void *judy_array)
{
	uint64_t index = 0;

	return JudyLFirst(judy_array, &index, PJE0);
}

static inline
void **
judy_get(void *judy_array, uint64_t key)
{
	return JudyLGet(judy_array, key, PJE0);
}

static inline
void
judy_ins(void **judy_array, uint64_t key, void *value)
{
	void **pvalue;

	pvalue = JudyLIns(judy_array, key, PJE0);

	if (! *pvalue) {
		*pvalue = value;
	}
}

static inline
void
judy_del(void **judy_array, uint64_t key)
{
	JudyLDel(judy_array, key, PJE0);
}

#define judy_for_each(judy_array, index, value) \
	for (index = 0, value = JudyLFirst(judy_array, &index, PJE0); \
	value; \
	value = JudyLNext(judy_array, &index, PJE0))

#define judy_for_each_reverse_from(judy_array, index, value) \
	for (value = JudyLFirst(judy_array, &index, PJE0); \
	value; \
	value = JudyLPrev(judy_array, &index, PJE0))

#endif

