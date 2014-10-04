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

#include <eth/datastruct/list.h>
#include <eth/datastruct/hash.h>

#include <eth/exotcp/tcp.h>

uint32_t calc_hash(hash_table_t *h, void *key);

hash_table_t *
hash_table_init(hash_func_t *hash_func, key_cmp_func_t *cmp) {
	hash_table_t *h;
	
	h                = malloc(sizeof(hash_table_t));
	h->m             = 2;
	h->n             = 0;
	h->A             = malloc(sizeof(hash_item *) * h->m);

	h->hash_func      = hash_func;
	h->key_comp_func = cmp;

	memset(h->A, '\x00', h->m *sizeof(hash_item *));

	return h;
}

hash_item *
_hash_table_lookup(hash_table_t *h, void *key) {
	uint32_t hashed_key = calc_hash (h, key);

	hash_item *ptr = h->A[hashed_key];
	int found = 0;

	while (ptr) {
		if (h->key_comp_func(ptr->key, key)) {
			found = 1;
			break;
		}

		ptr = ptr->next;
	}

	return (found ? ptr : NULL);
}

void
hash_table_resize(hash_table_t *h) {
	int i;
	hash_item *ptr;
	hash_item *tmp;
	hash_item **old;

	h->n  = 0;
	h->m *= 2;

	old = h->A;
	h->A = malloc(h->m * sizeof(hash_item *));

	for(i = 0; i < h->m/2; i++) {
		ptr = old[i];

		while(ptr) {
			hash_table_insert(h, ptr->key, ptr->val);

			tmp = ptr;
			ptr = ptr->next;
			free(tmp->val);
			free(tmp->key);
			free(tmp);
		}
	}

	free(old);
}

void
hash_table_insert(hash_table_t *h, void *key, void *val) {
	uint32_t hashed_key = calc_hash(h, key);

	hash_item **ptr = &(h->A[hashed_key]);
	hash_item *prev = NULL;
	int found = 0;

	while (*ptr) {
		if (h->key_comp_func((*ptr)->key, key)) {
			found = 1;

			break;
		}

		prev = *ptr;
		ptr = &((*ptr)->next);
	}

	if(!found) {
		*ptr = malloc (sizeof (hash_item));
		(*ptr)->prev = prev;
		(*ptr)->next = NULL;
	}

	(*ptr)->key = key;
	(*ptr)->val = val;

	h->n++;
	if(h->n/h->m == 2) hash_table_resize(h);
}

void
hash_table_remove(hash_table_t *h, void *key) {
	hash_item *ptr;
	hash_item *tmp;

	ptr = _hash_table_lookup(h, key);

	if (ptr) {
		tmp = ptr;

		if(ptr->prev) {
			ptr->prev->next = ptr->next;
		} else {
			uint32_t hashed_key = calc_hash(h, key);
			h->A[hashed_key] = ptr->next;
		}
		
		if(ptr->next) {
			ptr->next->prev = ptr->prev;
		}

		free (tmp);
	}
}

void *
hash_table_lookup(hash_table_t *h, void *key) {
	hash_item *i = _hash_table_lookup(h, key);

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

