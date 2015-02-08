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

#ifndef _ETH_MEM_POOL_H
#define _ETH_MEM_POOL_H

#include <stdio.h>
#include <stdlib.h>
#include <eth/datastruct/list.h>

/*
 * TODO: perform boundaries checks
 */

typedef struct mem_pool_item_s {
	list_head_t head;
	void *data;
} mem_pool_item_t;


typedef struct mem_pool_s {
	list_head_t     free_list;
	list_head_t     used_list;
	mem_pool_item_t *mem_pool_items;

	void            *mem_pool;
	uint32_t        *obj_size;
	uint32_t        *obj_count;

} mem_pool_t;

static inline
mem_pool_t *
mem_pool_new(uint32_t obj_size, uint32_t obj_count)
{
	mem_pool_t *mem_pool;
	uint32_t   i;

	mem_pool                 = malloc(sizeof(mem_pool_t));
	mem_pool->mem_pool       = malloc(obj_count * obj_size);
	mem_pool->mem_pool_items = malloc(obj_count * sizeof(mem_pool_item_t));

	list_init(&mem_pool->free_list);
	list_init(&mem_pool->used_list);

	for (i = 0; i < obj_count; i++) {
		mem_pool->mem_pool_items[i].data = ((uint8_t *) mem_pool->mem_pool) + i * obj_size;
		list_add(&mem_pool->mem_pool_items[i].head, &mem_pool->free_list);
	}


	return mem_pool;
}

static inline
void *
mem_pool_malloc(mem_pool_t *mem_pool)
{
	mem_pool_item_t *mem_pool_item = list_first_entry(&mem_pool->free_list, mem_pool_item_t, head);
	list_del(&mem_pool_item->head);
	list_add(&mem_pool_item->head, &mem_pool->used_list);

	return mem_pool_item->data;
}

static inline
void
mem_pool_free(mem_pool_t *mem_pool, void *data)
{
	mem_pool_item_t *mem_pool_item = list_first_entry(&mem_pool->used_list, mem_pool_item_t, head);
	list_del(&mem_pool_item->head);
	list_add(&mem_pool_item->head, &mem_pool->free_list);

	mem_pool_item->data = data;
}

#define define_mem_pool(name, type, count)		  \
							  \
mem_pool_t *type##_pool;				  \
							  \
static inline						  \
void							  \
init_##name##_pool()					  \
{							  \
	type##_pool = mem_pool_new(sizeof(type), count);  \
}							  \
							  \
static inline						  \
type *							  \
alloc_##name()						  \
{							  \
	return mem_pool_malloc(type##_pool);		  \
}							  \
							  \
static inline						  \
void							  \
free_##name(type *what)				  \
{							  \
	mem_pool_free(type##_pool, what);		  \
}

#endif
