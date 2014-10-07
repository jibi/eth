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
#include <eth/datastruct/list.h>

void
init_list(list_head_t *l)
{
	l->prev = l;
	l->next = l;
}

list_head_t *
list_new()
{
	list_head_t *l = malloc(sizeof(list_head_t));
	init_list(l);

	return l;
}

static inline
void
__list_add(list_head_t *entry, list_head_t *prev, list_head_t *next)
{
	next->prev  = entry;
	entry->next = next;
	entry->prev = prev;
	prev->next  = entry;
}

inline
void
list_add(list_head_t *entry, list_head_t *head)
{
	__list_add(entry, head, head->next);
}

inline
void
list_add_tail(list_head_t *entry, list_head_t *head)
{
	__list_add(entry, head->prev, head);
}

inline
void
list_del(list_head_t *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;
}

