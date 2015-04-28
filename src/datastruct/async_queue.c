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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <pthread.h>

#include <eth/datastruct/async_queue.h>

#define ASYNC_QUEUE_INIT_SIZE 2048

static inline void async_queue_grow(async_queue_t *q);

async_queue_t *
async_queue_new()
{
	async_queue_t *q = malloc(sizeof(async_queue_t));

	q->size  = ASYNC_QUEUE_INIT_SIZE;
	q->items = malloc(q->size * sizeof(void *));

	q->count = 0;
	q->begin = 0;
	q->end   = 0;

	pthread_mutex_init(&q->rw_lock, NULL);
	pthread_cond_init(&q->full_cond, NULL);

	return q;
}

void
async_queue_push(async_queue_t *q, void *item)
{
	bool empty;
	pthread_mutex_lock(&q->rw_lock);

	empty = q->count == 0;

	if (q->count == q->size) {
		async_queue_grow(q);
	}

	q->items[q->end] = item;
	q->end = (q->end + 1) % q->size;
	q->count++;

	pthread_mutex_unlock(&q->rw_lock);

	if (empty) {
		pthread_cond_broadcast(&q->full_cond);
	}
}

void *
async_queue_pop(async_queue_t *q)
{
	void *item;

	pthread_mutex_lock(&q->rw_lock);

	while (q->count == 0) {
		pthread_cond_wait(&q->full_cond, &q->rw_lock);
	}

	item = q->items[q->begin];
	q->begin = (q->begin + 1) % q->size;
	q->count--;

	pthread_mutex_unlock(&q->rw_lock);

	return item;
}

static inline
void
async_queue_grow(async_queue_t *q)
{
	uint32_t new_size = q->size * 2;
	void **new_items  = malloc(new_size * sizeof(void **));

	memcpy(new_items, q->items, q->size);
	free(q->items);

	q->items = new_items;
	q->size  = new_size;
}
