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

#include <eth/datastruct/rbtree.h>

static inline
void
rb_set_black(rb_node_t *rb)
{
	rb->__rb_parent_color |= RB_BLACK;
}

static inline
rb_node_t *
rb_red_parent(rb_node_t *red)
{
	return (rb_node_t *)red->__rb_parent_color;
}

static inline
void
__rb_rotate_set_parents(rb_node_t *old, rb_node_t *new, rb_root_t *root, int color)
{
	rb_node_t *parent = rb_parent(old);
	new->__rb_parent_color = old->__rb_parent_color;
	rb_set_parent_color(old, new, color);
	__rb_change_child(old, new, parent, root);
}

static inline
void
__rb_insert(rb_node_t *node, rb_root_t *root,
	void (*augment_rotate)(rb_node_t *old, rb_node_t *new))
{
	rb_node_t *parent = rb_red_parent(node), *gparent, *tmp;

	while (true) {
		if (!parent) {
			rb_set_parent_color(node, NULL, RB_BLACK);
			break;
		} else if (rb_is_black(parent))
			break;
		gparent = rb_red_parent(parent);
		tmp = gparent->rb_right;
		if (parent != tmp) {
			if (tmp && rb_is_red(tmp)) {
				rb_set_parent_color(tmp, gparent, RB_BLACK);
				rb_set_parent_color(parent, gparent, RB_BLACK);
				node = gparent;
				parent = rb_parent(node);
				rb_set_parent_color(node, parent, RB_RED);
				continue;
			}
			tmp = parent->rb_right;
			if (node == tmp) {
				parent->rb_right = tmp = node->rb_left;
				node->rb_left = parent;
				if (tmp)
					rb_set_parent_color(tmp, parent,
							RB_BLACK);
				rb_set_parent_color(parent, node, RB_RED);
				augment_rotate(parent, node);
				parent = node;
				tmp = node->rb_right;
			}
			gparent->rb_left = tmp;
			parent->rb_right = gparent;
			if (tmp)
				rb_set_parent_color(tmp, gparent, RB_BLACK);
			__rb_rotate_set_parents(gparent, parent, root, RB_RED);
			augment_rotate(gparent, parent);
			break;
		} else {
			tmp = gparent->rb_left;
			if (tmp && rb_is_red(tmp)) {
				rb_set_parent_color(tmp, gparent, RB_BLACK);
				rb_set_parent_color(parent, gparent, RB_BLACK);
				node = gparent;
				parent = rb_parent(node);
				rb_set_parent_color(node, parent, RB_RED);
				continue;
			}
			tmp = parent->rb_left;
			if (node == tmp) {
				parent->rb_left = tmp = node->rb_right;
				node->rb_right = parent;
				if (tmp)
					rb_set_parent_color(tmp, parent,
							RB_BLACK);
				rb_set_parent_color(parent, node, RB_RED);
				augment_rotate(parent, node);
				parent = node;
				tmp = node->rb_left;
			}
			gparent->rb_right = tmp;
			parent->rb_left = gparent;
			if (tmp)
				rb_set_parent_color(tmp, gparent, RB_BLACK);
			__rb_rotate_set_parents(gparent, parent, root, RB_RED);
			augment_rotate(gparent, parent);
			break;
		}
	}
}

static inline
void
____rb_erase_color(rb_node_t *parent, rb_root_t *root,
	void (*augment_rotate)(rb_node_t *old, rb_node_t *new))
{
	rb_node_t *node = NULL, *sibling, *tmp1, *tmp2;
	while (true) {
		sibling = parent->rb_right;
		if (node != sibling) {
			if (rb_is_red(sibling)) {
				parent->rb_right = tmp1 = sibling->rb_left;
				sibling->rb_left = parent;
				rb_set_parent_color(tmp1, parent, RB_BLACK);
				__rb_rotate_set_parents(parent, sibling, root,
						RB_RED);
				augment_rotate(parent, sibling);
				sibling = tmp1;
			}
			tmp1 = sibling->rb_right;
			if (!tmp1 || rb_is_black(tmp1)) {
				tmp2 = sibling->rb_left;
				if (!tmp2 || rb_is_black(tmp2)) {
					rb_set_parent_color(sibling, parent,
							RB_RED);
					if (rb_is_red(parent))
						rb_set_black(parent);
					else {
						node = parent;
						parent = rb_parent(node);
						if (parent)
							continue;
					}
					break;
				}
				sibling->rb_left = tmp1 = tmp2->rb_right;
				tmp2->rb_right = sibling;
				parent->rb_right = tmp2;
				if (tmp1)
					rb_set_parent_color(tmp1, sibling,
							RB_BLACK);
				augment_rotate(sibling, tmp2);
				tmp1 = sibling;
				sibling = tmp2;
			}
			parent->rb_right = tmp2 = sibling->rb_left;
			sibling->rb_left = parent;
			rb_set_parent_color(tmp1, sibling, RB_BLACK);
			if (tmp2)
				rb_set_parent(tmp2, parent);
			__rb_rotate_set_parents(parent, sibling, root,
					RB_BLACK);
			augment_rotate(parent, sibling);
			break;
		} else {
			sibling = parent->rb_left;
			if (rb_is_red(sibling)) {
				parent->rb_left = tmp1 = sibling->rb_right;
				sibling->rb_right = parent;
				rb_set_parent_color(tmp1, parent, RB_BLACK);
				__rb_rotate_set_parents(parent, sibling, root,
						RB_RED);
				augment_rotate(parent, sibling);
				sibling = tmp1;
			}
			tmp1 = sibling->rb_left;
			if (!tmp1 || rb_is_black(tmp1)) {
				tmp2 = sibling->rb_right;
				if (!tmp2 || rb_is_black(tmp2)) {
					rb_set_parent_color(sibling, parent,
							RB_RED);
					if (rb_is_red(parent))
						rb_set_black(parent);
					else {
						node = parent;
						parent = rb_parent(node);
						if (parent)
							continue;
					}
					break;
				}
				sibling->rb_right = tmp1 = tmp2->rb_left;
				tmp2->rb_left = sibling;
				parent->rb_left = tmp2;
				if (tmp1)
					rb_set_parent_color(tmp1, sibling,
							RB_BLACK);
				augment_rotate(sibling, tmp2);
				tmp1 = sibling;
				sibling = tmp2;
			}
			parent->rb_left = tmp2 = sibling->rb_right;
			sibling->rb_right = parent;
			rb_set_parent_color(tmp1, sibling, RB_BLACK);
			if (tmp2)
				rb_set_parent(tmp2, parent);
			__rb_rotate_set_parents(parent, sibling, root,
					RB_BLACK);
			augment_rotate(parent, sibling);
			break;
		}
	}
}

void
__rb_erase_color(rb_node_t *parent, rb_root_t *root,
	void (*augment_rotate)(rb_node_t *old, rb_node_t *new))
{
	____rb_erase_color(parent, root, augment_rotate);
}

static inline void dummy_propagate(rb_node_t *node, rb_node_t *stop) {}
static inline void dummy_copy(rb_node_t *old, rb_node_t *new) {}
static inline void dummy_rotate(rb_node_t *old, rb_node_t *new) {}
static const struct rb_augment_callbacks dummy_callbacks = {
	dummy_propagate, dummy_copy, dummy_rotate
};

void
rb_insert_color(rb_node_t *node, rb_root_t *root)
{
	__rb_insert(node, root, dummy_rotate);
}

void
rb_erase(rb_node_t *node, rb_root_t *root)
{
	rb_node_t *rebalance;
	rebalance = __rb_erase_augmented(node, root, &dummy_callbacks);
	if (rebalance)
		____rb_erase_color(rebalance, root, dummy_rotate);
}

void
__rb_insert_augmented(rb_node_t *node, rb_root_t *root,
		void (*augment_rotate)(rb_node_t *old, rb_node_t *new))
{
	__rb_insert(node, root, augment_rotate);
}

rb_node_t *
rb_first(const rb_root_t *root)
{
	rb_node_t *n;
	n = root->rb_node;
	if (!n)
		return NULL;
	while (n->rb_left)
		n = n->rb_left;
	return n;
}

rb_node_t *
rb_last(const rb_root_t *root)
{
	rb_node_t *n;
	n = root->rb_node;
	if (!n)
		return NULL;
	while (n->rb_right)
		n = n->rb_right;
	return n;
}

rb_node_t *
rb_next(const rb_node_t *node)
{
	rb_node_t *parent;
	if (RB_EMPTY_NODE(node))
		return NULL;
	if (node->rb_right) {
		node = node->rb_right;
		while (node->rb_left)
			node=node->rb_left;
		return (rb_node_t *)node;
	}
	while ((parent = rb_parent(node)) && node == parent->rb_right)
		node = parent;
	return parent;
}

rb_node_t *
rb_prev(const rb_node_t *node)
{
	rb_node_t *parent;
	if (RB_EMPTY_NODE(node))
		return NULL;
	if (node->rb_left) {
		node = node->rb_left;
		while (node->rb_right)
			node=node->rb_right;
		return (rb_node_t *)node;
	}
	while ((parent = rb_parent(node)) && node == parent->rb_left)
		node = parent;
	return parent;
}

void
rb_replace_node(rb_node_t *victim, rb_node_t *new, rb_root_t *root)
{
	rb_node_t *parent = rb_parent(victim);
	__rb_change_child(victim, new, parent, root);
	if (victim->rb_left)
		rb_set_parent(victim->rb_left, new);
	if (victim->rb_right)
		rb_set_parent(victim->rb_right, new);
	*new = *victim;
}

static
rb_node_t *
rb_left_deepest_node(const rb_node_t *node)
{
	for (;;) {
		if (node->rb_left)
			node = node->rb_left;
		else if (node->rb_right)
			node = node->rb_right;
		else
			return (rb_node_t *)node;
	}
}

rb_node_t *
rb_next_postorder(const rb_node_t *node)
{
	const rb_node_t *parent;
	if (!node)
		return NULL;
	parent = rb_parent(node);
	if (parent && node == parent->rb_left && parent->rb_right) {
		return rb_left_deepest_node(parent->rb_right);
	} else
		return (rb_node_t *)parent;
}

rb_node_t *
rb_first_postorder(const rb_root_t *root)
{
	if (!root->rb_node)
		return NULL;
	return rb_left_deepest_node(root->rb_node);
}

