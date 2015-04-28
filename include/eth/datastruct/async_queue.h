/*
 * Copyright (C) 2015 jibi <jibi@paranoici.org>
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

#ifndef _ETH_DATASTRUCT_ASYNC_QUEUE
#define _ETH_DATASTRUCT_ASYNC_QUEUE


#include <stdint.h>
#include <pthread.h>

typedef struct async_queue_s {
	void **items;

	uint32_t begin;
	uint32_t end;

	uint32_t count;
	uint32_t size;

	pthread_mutex_t rw_lock;
	pthread_cond_t  full_cond;
} async_queue_t;

async_queue_t *async_queue_new();
void async_queue_push(async_queue_t *q, void *item);
void *async_queue_pop(async_queue_t *q);

#endif
