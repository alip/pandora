/*
 * Routines to provide a memory-efficient hashtable.
 *
 * Copyright (C) 2007-2009 Wayne Davison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, visit the http://fsf.org website.
 */

#include "byteorder.h"
#include "hashtable.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#define HASH_LOAD_LIMIT(size) ((size)*3/4)

int
hashtable_create(int size, int key64, hashtable_t **tbl)
{
	int req = size;
	hashtable_t *htbl;
	int node_size = key64 ? sizeof (ht_int64_node_t)
			      : sizeof (ht_int32_node_t);

	assert(tbl);

	/* Pick a power of 2 that can hold the requested size. */
	if (size & (size-1) || size < 16) {
		size = 16;
		while (size < req)
			size *= 2;
	}

	if (!(htbl = malloc(sizeof(hashtable_t))))
		return -ENOMEM;
	if (!(htbl->nodes = calloc(size * node_size, sizeof(char)))) {
		free(htbl);
		return -ENOMEM;
	}

	htbl->size = size;
	htbl->entries = 0;
	htbl->node_size = node_size;
	htbl->key64 = key64 ? 1 : 0;

	*tbl = htbl;
	return 0;
}

void
hashtable_destroy(hashtable_t *tbl)
{
	free(tbl->nodes);
	free(tbl);
}

/* This returns the node for the indicated key, either newly created or
 * already existing.  Returns NULL if not allocating and not found. */
void *
hashtable_find(hashtable_t *tbl, int64 key, int allocate_if_missing)
{
	int key64 = tbl->key64;
	ht_int32_node_t *node;
	uint32 ndx;

	assert(tbl);

	if (key64 ? key == 0 : (int32)key == 0)
		return NULL;

	if (allocate_if_missing && tbl->entries > HASH_LOAD_LIMIT(tbl->size)) {
		void *old_nodes = tbl->nodes;
		int size = tbl->size * 2;
		int i;

		if (!(tbl->nodes = calloc(size * tbl->node_size, sizeof(char))))
			return NULL;
		tbl->size = size;
		tbl->entries = 0;

		for (i = size / 2; i-- > 0; ) {
			ht_int32_node_t *move_node = HT_NODE(tbl, old_nodes, i);
			int64 move_key = HT_KEY(move_node, key64);
			if (move_key == 0)
				continue;
			node = hashtable_find(tbl, move_key, 1);
			node->data = move_node->data;
		}

		free(old_nodes);
	}

	if (!key64) {
		/* Based on Jenkins One-at-a-time hash. */
		unsigned char buf[4], *keyp = buf;
		int i;

		SIVALu(buf, 0, key);
		for (ndx = 0, i = 0; i < 4; i++) {
			ndx += keyp[i];
			ndx += (ndx << 10);
			ndx ^= (ndx >> 6);
		}
		ndx += (ndx << 3);
		ndx ^= (ndx >> 11);
		ndx += (ndx << 15);
	} else {
		/* Based on Jenkins hashword() from lookup3.c. */
		uint32 a, b, c;

		/* Set up the internal state */
		a = b = c = 0xdeadbeef + (8 << 2);

#define rot(x,k) (((x)<<(k)) ^ ((x)>>(32-(k))))
#if SIZEOF_INT64 >= 8
		b += (uint32)(key >> 32);
#endif
		a += (uint32)key;
		c ^= b; c -= rot(b, 14);
		a ^= c; a -= rot(c, 11);
		b ^= a; b -= rot(a, 25);
		c ^= b; c -= rot(b, 16);
		a ^= c; a -= rot(c, 4);
		b ^= a; b -= rot(a, 14);
		c ^= b; c -= rot(b, 24);
#undef rot
		ndx = c;
	}

	/* If it already exists, return the node.  If we're not
	 * allocating, return NULL if the key is not found. */
	while (1) {
		int64 nkey;

		ndx &= tbl->size - 1;
		node = HT_NODE(tbl, tbl->nodes, ndx);
		nkey = HT_KEY(node, key64);

		if (nkey == key)
			return node;
		if (nkey == 0) {
			if (!allocate_if_missing)
				return NULL;
			break;
		}
		ndx++;
	}

	/* Take over this empty spot and then return the node. */
	if (key64)
		((ht_int64_node_t*)node)->key = key;
	else
		node->key = (int32)key;
	tbl->entries++;
	return node;
}
