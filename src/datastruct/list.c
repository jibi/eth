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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <eth.h>
#include <eth/log.h>

#include <eth/datastruct/list.h>

#define MAX_LIST_LENGTH_BITS 20

void
init_list(list_head_t *l)
{
	l->prev = l;
	l->next = l;
}

list_head_t *
list_new(void)
{
	list_head_t *l = malloc(sizeof(list_head_t));
	init_list(l);

	return l;
}

static
list_head_t *
merge(void *priv, list_sort_cmp_func_t *cmp, list_head_t *a, list_head_t *b)
{
	list_head_t head, *tail = &head;

	while (a && b) {
		if ((*cmp)(priv, a, b) <= 0) {
			tail->next = a;
			a = a->next;
		} else {
			tail->next = b;
			b = b->next;
		}

		tail = tail->next;
	}

	tail->next = a ? a : b;

	return head.next;
}

static
void
merge_and_restore_back_links(void *priv, list_sort_cmp_func_t *cmp, list_head_t *head, list_head_t *a, list_head_t *b)
{
	list_head_t *tail = head;
	uint8_t count = 0;

	while (a && b) {
		if ((*cmp)(priv, a, b) <= 0) {
			tail->next = a;
			a->prev = tail;
			a = a->next;
		} else {
			tail->next = b;
			b->prev = tail;
			b = b->next;
		}
		tail = tail->next;
	}

	tail->next = a ? a : b;

	do {
		if (unlikely(!(++count))) {
			(*cmp)(priv, tail->next, tail->next);
		}

		tail->next->prev = tail;
		tail = tail->next;
	} while (tail->next);

	tail->next = head;
	head->prev = tail;
}

void
list_sort(void *priv, list_head_t *head, list_sort_cmp_func_t *cmp)
{
	list_head_t *part[MAX_LIST_LENGTH_BITS+1];
	list_head_t *list;

	int lev;
	int max_lev = 0;

	if (list_empty(head)) {
		return;
	}

	memset(part, 0, sizeof(part));

	head->prev->next = NULL;
	list = head->next;

	while (list) {
		list_head_t *cur = list;
		list = list->next;
		cur->next = NULL;

		for (lev = 0; part[lev]; lev++) {
			cur = merge(priv, cmp, part[lev], cur);
			part[lev] = NULL;
		}
		if (lev > max_lev) {
			if (unlikely(lev >= ARRAY_SIZE(part)-1)) {
				log_debug1("list too long for efficiency");
				lev--;
			}
			max_lev = lev;
		}
		part[lev] = cur;
	}

	for (lev = 0; lev < max_lev; lev++) {
		if (part[lev]) {
			list = merge(priv, cmp, part[lev], list);
		}
	}

	merge_and_restore_back_links(priv, cmp, head, part[max_lev], list);
}

