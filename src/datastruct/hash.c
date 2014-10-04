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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <eth.h>

#include <eth/datastruct/list.h>
#include <eth/datastruct/hash.h>

#include <eth/exotcp/tcp.h>

uint32_t calc_hash(hash_table_t *h, void *key);

static const
unsigned int primes[] = {
	8         + 3,  16        + 3,  32        + 5,  64         + 3,
	128       + 3,  256       + 27, 512       + 9,  1024       + 9,
	2048      + 5,  4096      + 3,  8192      + 27, 16384      + 43,
	32768     + 3,  65536     + 45, 131072    + 29, 262144     + 3,
	524288    + 21, 1048576   + 7,  2097152   + 17, 4194304    + 15,
	8388608   + 9,  16777216  + 43, 33554432  + 35, 67108864   + 15,
	134217728 + 29, 268435456 + 3,  536870912 + 11, 1073741824 + 85,
	0
};

static uint32_t
hash_table_next_size(hash_table_t *h) {

	int i;

	for (i = 0; i < sizeof(primes)/sizeof(uint32_t); i++) {
		if (primes[i] > h->m) {
			return primes[i];
		}
	}

	return 0;
}

hash_table_t *
hash_table_init(hash_func_t *hash_func, key_cmp_func_t *cmp) {

	hash_table_t *h;
	
	h       = malloc(sizeof(hash_table_t));
	h->m    = primes[0];
	h->n    = 0;
	h->bins = malloc(sizeof(hash_item_t *) * h->m);

	h->hash_func     = hash_func;
	h->key_comp_func = cmp;

	bzero(h->bins, h->m * sizeof(hash_item_t *));

	return h;
}

hash_item_t *
_hash_table_lookup(hash_table_t *h, void *key) {

	uint32_t hashed_key;
	list_head_t *bin;
	hash_item_t   *item;
	bool found;

	hashed_key = calc_hash(h, key);
	bin        = h->bins[hashed_key];
	found      = false;

	if (!bin) {
		return NULL;
	}

	list_for_each_entry(item, bin, list_head) {
		if (h->key_comp_func(item->key, key)) {
			found = true;
			break;
		}
	}

	return (found ? item : NULL);
}

void
hash_table_resize(hash_table_t *h) {

	int         i;
	uint32_t    old_size;
	list_head_t **old_bins;

	old_bins = h->bins;
	old_size = h->m;

	h->m    = hash_table_next_size(h);
	h->n    = 0;
	h->bins = malloc(h->m * sizeof(hash_item_t *));

	for (i = 0; i < old_size; i++) {
		list_head_t *bin;
		hash_item_t *item;

		bin = old_bins[i];

		list_for_each_entry(item, bin, list_head) {
			hash_table_insert(h, item->key, item->val);
			free(item);
		}

		free(bin);
	}

	free(old_bins);
}

void
hash_table_insert(hash_table_t *h, void *key, void *val) {

	uint32_t   hashed_key;
	bool       found;
	hash_item_t *item;
	list_head_t *bin;

	found      = false;

	hashed_key = calc_hash(h, key);
	bin        = h->bins[hashed_key];

	if (! bin) {
		h->bins[hashed_key] = list_new();

		item = malloc(sizeof(hash_item_t));
		item->key = key;
		item->val = val;

		list_add(&item->list_head, h->bins[hashed_key]);
	} else {
		list_for_each_entry(item, bin, list_head) {
			if (h->key_comp_func(item->key, key)) {
				found = true;
				break;
			}
		}

		if (found) {
			item->val = val;
		} else {
			item      = malloc(sizeof(hash_item_t));
			item->key = key;
			item->val = val;

			list_add(&item->list_head, bin);
		}
	}

	h->n++;

	if (h->n/h->m >= 2) {
		hash_table_resize(h);
	}
}

void
hash_table_remove(hash_table_t *h, void *key) {

	hash_item_t *item;
	item = _hash_table_lookup(h, key);

	if (item) {
		list_del(&item->list_head);
		free(item);

		h->n--;
	}
}

void *
hash_table_lookup(hash_table_t *h, void *key) {

	hash_item_t *i = _hash_table_lookup(h, key);

	if (i) {
		return i->val;
	} else {
		return NULL;
	}
}

uint32_t
calc_hash(hash_table_t *h, void *key) {

	return h->hash_func(key) % h->m;
}

uint32_t
murmur_hash(const void *key, int len, uint32_t seed) {

	const uint32_t m          = 0x5bd1e995;
	const int r               = 24;
	uint32_t h                = seed ^ len;
	const unsigned char *data = (const unsigned char *)key;

	while (len >= 4) {
		uint32_t k = *(uint32_t*)data;

		k *= m;
		k ^= k >> r;
		k *= m;

		h *= m;
		h ^= k;

		data += 4;
		len -= 4;
	}

	switch(len) {
		case 3: h ^= data[2] << 16;
		case 2: h ^= data[1] << 8;
		case 1: h ^= data[0];
			h *= m;
	};

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
}

