/*
 * Copyright (C) 1999 Andrea Arcangeli <andrea@suse.de>
 * Copyright (C) 2002 David Woodhouse <dwmw2@infradead.org>
 * Copyright (C) 2012 Michel Lespinasse <walken@google.com>
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

#ifndef _ETH_DATASTRUCT_RBTREE_H
#define _ETH_DATASTRUCT_RBTREE_H

#include <stdio.h>
#include <stddef.h>
#include <stdbool.h>

#include <eth/datastruct/list.h> /* for container of */

typedef struct rb_node_s {
	unsigned long  __rb_parent_color;
	struct rb_node_s *rb_right;
	struct rb_node_s *rb_left;
} __attribute__((aligned(sizeof(long)))) rb_node_t;

typedef struct rb_root_s {
	rb_node_t *rb_node;
} rb_root_t;

#define rb_parent(r) ((rb_node_t *)((r)->__rb_parent_color & ~3))

#define RB_ROOT	(rb_root_t) { NULL, }
#define	rb_entry(ptr, type, member) container_of(ptr, type, member)

#define RB_EMPTY_ROOT(root)  ((root)->rb_node == NULL)

#define RB_EMPTY_NODE(node)  \
	((node)->__rb_parent_color == (unsigned long)(node))
#define RB_CLEAR_NODE(node)  \
	((node)->__rb_parent_color = (unsigned long)(node))

extern void rb_insert_color(rb_node_t *, rb_root_t *);
extern void rb_erase(rb_node_t *, rb_root_t *);

extern rb_node_t *rb_next(const rb_node_t *);
extern rb_node_t *rb_prev(const rb_node_t *);
extern rb_node_t *rb_first(const rb_root_t *);
extern rb_node_t *rb_last(const rb_root_t *);

extern rb_node_t *rb_first_postorder(const rb_root_t *);
extern rb_node_t *rb_next_postorder(const rb_node_t *);

extern void rb_replace_node(rb_node_t *victim, rb_node_t *new,
			    rb_root_t *root);

static inline
void
rb_link_node(rb_node_t * node, rb_node_t * parent,
	rb_node_t ** rb_link)
{
	node->__rb_parent_color = (unsigned long)parent;
	node->rb_left = node->rb_right = NULL;

	*rb_link = node;
}

#define rb_entry_safe(ptr, type, member) \
	({ typeof(ptr) ____ptr = (ptr); \
	   ____ptr ? rb_entry(____ptr, type, member) : NULL; \
	})

#define rbtree_postorder_for_each_entry_safe(pos, n, root, field) \
	for (pos = rb_entry_safe(rb_first_postorder(root), typeof(*pos), field); \
	     pos && ({ n = rb_entry_safe(rb_next_postorder(&pos->field), \
			typeof(*pos), field); 1; }); \
	     pos = n)

#define rbtree_for_each_node_safe(node, n, root) \
	for (node = rb_first(root), node && (n = rb_next(node)); \
			 node; \
			 node = n, node && (n = rb_next(node)))

struct rb_augment_callbacks {
	void (*propagate)(rb_node_t *node, rb_node_t *stop);
	void (*copy)(rb_node_t *old, rb_node_t *new);
	void (*rotate)(rb_node_t *old, rb_node_t *new);
};

extern void __rb_insert_augmented(rb_node_t *node, rb_root_t *root,
	void (*augment_rotate)(rb_node_t *old, rb_node_t *new));

static inline
void
rb_insert_augmented(rb_node_t *node, rb_root_t *root,
	const struct rb_augment_callbacks *augment)
{
	__rb_insert_augmented(node, root, augment->rotate);
}

#define RB_DECLARE_CALLBACKS(rbstatic, rbname, rbstruct, rbfield,	\
			     rbtype, rbaugmented, rbcompute)		\
static inline void							\
rbname ## _propagate(rb_node_t *rb, rb_node_t *stop)			\
{									\
	while (rb != stop) {						\
		rbstruct *node = rb_entry(rb, rbstruct, rbfield);	\
		rbtype augmented = rbcompute(node);			\
		if (node->rbaugmented == augmented)			\
			break;						\
		node->rbaugmented = augmented;				\
		rb = rb_parent(&node->rbfield);				\
	}								\
}									\
static inline void							\
rbname ## _copy(rb_node_t *rb_old, rb_node_t *rb_new)			\
{									\
	rbstruct *old = rb_entry(rb_old, rbstruct, rbfield);		\
	rbstruct *new = rb_entry(rb_new, rbstruct, rbfield);		\
	new->rbaugmented = old->rbaugmented;				\
}									\
static void								\
rbname ## _rotate(rb_node_t *rb_old, rb_node_t *rb_new)			\
{									\
	rbstruct *old = rb_entry(rb_old, rbstruct, rbfield);		\
	rbstruct *new = rb_entry(rb_new, rbstruct, rbfield);		\
	new->rbaugmented = old->rbaugmented;				\
	old->rbaugmented = rbcompute(old);				\
}									\
rbstatic const struct rb_augment_callbacks rbname = {			\
	rbname ## _propagate, rbname ## _copy, rbname ## _rotate	\
};

#define	RB_RED		0
#define	RB_BLACK	1

#define __rb_parent(pc)    ((rb_node_t *)(pc & ~3))

#define __rb_color(pc)     ((pc) & 1)
#define __rb_is_black(pc)  __rb_color(pc)
#define __rb_is_red(pc)    (!__rb_color(pc))
#define rb_color(rb)       __rb_color((rb)->__rb_parent_color)
#define rb_is_red(rb)      __rb_is_red((rb)->__rb_parent_color)
#define rb_is_black(rb)    __rb_is_black((rb)->__rb_parent_color)

static inline
void
rb_set_parent(rb_node_t *rb, rb_node_t *p)
{
	rb->__rb_parent_color = rb_color(rb) | (unsigned long)p;
}

static inline
void
rb_set_parent_color(rb_node_t *rb, rb_node_t *p, int color)
{
	rb->__rb_parent_color = (unsigned long)p | color;
}

static inline
void
__rb_change_child(rb_node_t *old, rb_node_t *new,
		  rb_node_t *parent, rb_root_t *root)
{
	if (parent) {
		if (parent->rb_left == old)
			parent->rb_left = new;
		else
			parent->rb_right = new;
	} else
		root->rb_node = new;
}

extern void __rb_erase_color(rb_node_t *parent, rb_root_t *root,
	void (*augment_rotate)(rb_node_t *old, rb_node_t *new));

static __always_inline
rb_node_t *
__rb_erase_augmented(rb_node_t *node, rb_root_t *root,
	const struct rb_augment_callbacks *augment)
{
	rb_node_t *child = node->rb_right, *tmp = node->rb_left;
	rb_node_t *parent, *rebalance;
	unsigned long pc;

	if (!tmp) {
		pc = node->__rb_parent_color;
		parent = __rb_parent(pc);
		__rb_change_child(node, child, parent, root);
		if (child) {
			child->__rb_parent_color = pc;
			rebalance = NULL;
		} else
			rebalance = __rb_is_black(pc) ? parent : NULL;
		tmp = parent;
	} else if (!child) {
		tmp->__rb_parent_color = pc = node->__rb_parent_color;
		parent = __rb_parent(pc);
		__rb_change_child(node, tmp, parent, root);
		rebalance = NULL;
		tmp = parent;
	} else {
		rb_node_t *successor = child, *child2;
		tmp = child->rb_left;
		if (!tmp) {
			parent = successor;
			child2 = successor->rb_right;
			augment->copy(node, successor);
		} else {
			do {
				parent = successor;
				successor = tmp;
				tmp = tmp->rb_left;
			} while (tmp);

			parent->rb_left = child2 = successor->rb_right;
			successor->rb_right = child;
			rb_set_parent(child, successor);
			augment->copy(node, successor);
			augment->propagate(parent, successor);
		}

		successor->rb_left = tmp = node->rb_left;
		rb_set_parent(tmp, successor);

		pc = node->__rb_parent_color;
		tmp = __rb_parent(pc);
		__rb_change_child(node, successor, tmp, root);
		if (child2) {
			successor->__rb_parent_color = pc;
			rb_set_parent_color(child2, parent, RB_BLACK);
			rebalance = NULL;
		} else {
			unsigned long pc2 = successor->__rb_parent_color;
			successor->__rb_parent_color = pc;
			rebalance = __rb_is_black(pc2) ? parent : NULL;
		}
		tmp = successor;
	}

	augment->propagate(tmp, NULL);
	return rebalance;
}

static __always_inline
void
rb_erase_augmented(rb_node_t *node, rb_root_t *root,
	const struct rb_augment_callbacks *augment)
{
	rb_node_t *rebalance = __rb_erase_augmented(node, root, augment);
	if (rebalance)
		__rb_erase_color(rebalance, root, augment->rotate);
}

#endif	

