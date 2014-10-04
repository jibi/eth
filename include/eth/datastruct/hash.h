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

#ifndef _ETH_EXOTCP_HASH_H
#define _ETH_EXOTCP_HASH_H

#include <stdint.h>
#include <eth.h>

typedef bool(key_cmp_func_t)(void *, void*);
typedef uint32_t(hash_func_t)(void *);

typedef struct hash_item {
	struct hash_item *prev;
	struct hash_item *next;

	void *key;
	void *val;
} hash_item;

typedef struct hash_table_s {
	uint32_t m; /* linked list max length */
	uint32_t n; /* linked list cur length */

	hash_item **A;
	hash_func_t    *hash_func;
	key_cmp_func_t *key_comp_func;
} hash_table_t;

hash_table_t *hash_table_init(hash_func_t *hash_func, key_cmp_func_t *cmp);
void hash_table_insert(hash_table_t *h, void *key, void *val);
void hash_table_remove(hash_table_t *h, void *key);
void *hash_table_lookup(hash_table_t *h, void *key);
void hash_table_resize(hash_table_t *h);

uint32_t murmur_hash(const void *key, int len, uint32_t seed);

#endif

