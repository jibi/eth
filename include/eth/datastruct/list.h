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

/* based on the Linux kernel list.h */

#ifndef _ETH_DATASTRUCT_LIST
#define _ETH_DATASTRUCT_LIST

#include <eth.h>
#include <stddef.h>

typedef struct list_head_s {
	struct list_head_s *prev;
	struct list_head_s *next;
} list_head_t;

typedef int(list_sort_cmp_func_t)(void *, list_head_t *, list_head_t *);

void list_init(list_head_t *l);
list_head_t *list_new(void);
void list_sort(void *priv, list_head_t *head, list_sort_cmp_func_t *cmp);

static inline
void
__list_add(list_head_t *entry, list_head_t *prev, list_head_t *next)
{
	next->prev  = entry;
	entry->next = next;
	entry->prev = prev;
	prev->next  = entry;
}

static inline
void
list_add(list_head_t *entry, list_head_t *head)
{
	__list_add(entry, head, head->next);
}

static inline
void
list_add_tail(list_head_t *entry, list_head_t *head)
{
	__list_add(entry, head->prev, head);
}

/*
 * after deleting we set next and prev to NULL, so we can tell if an entry is
 * attached to a list
 */
static inline
void
list_del(list_head_t *entry)
{
	entry->next->prev = entry->prev;
	entry->prev->next = entry->next;

	entry->next       = NULL;
	entry->prev       = NULL;
}

static inline
bool
list_head_attached(list_head_t *entry)
{
	return entry->next && entry->prev;
}

static inline
int
list_empty(const list_head_t *head)
{
	return head->next == head;
}

#define list_entry(ptr, type, member) \
	__extension__({ const typeof( ((type *)0)->member ) *__mptr = (ptr); (type *)( (char *)__mptr - offsetof(type,member) );})
#define list_first_entry(ptr, type, member) \
	list_entry((ptr)->next, type, member)
#define list_next_entry(pos, member) \
	list_entry((pos)->member.next, typeof(*(pos)), member)

#define list_for_each_entry(pos, head, member) \
	for (pos = list_first_entry(head, typeof(*pos), member); \
	&pos->member != (head); \
	pos = list_next_entry(pos, member))

#define list_for_each_entry_continue(pos, head, member) \
	for (pos = list_next_entry(pos, member); \
	&pos->member != (head); \
	pos = list_next_entry(pos, member))

#define list_for_each_entry_from(pos, head, member) \
	for (; &pos->member != (head); \
	pos = list_next_entry(pos, member))

#define list_for_each_entry_safe(pos, n, head, member)                                                  \
	for (pos = list_first_entry(head, typeof(*pos), member), n = list_next_entry(pos, member); \
	&pos->member != (head);                                                                    \
	pos = n, n = list_next_entry(n, member))

#define list_for_each_entry_safe_continue(pos, n, head, member)                         \
	for (pos = list_next_entry(pos, member), n = list_next_entry(pos, member); \
	&pos->member != (head);                                                    \
	pos = n, n = list_next_entry(n, member))

#define list_for_each_entry_safe_from(pos, n, head, member) \
	for (n = list_next_entry(pos, member);         \
	&pos->member != (head);                        \
	pos = n, n = list_next_entry(n, member))

#endif

