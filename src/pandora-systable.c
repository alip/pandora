/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010 Ali Polatel <alip@exherbo.org>
 *
 * This file is part of Pandora's Box. pandora is free software;
 * you can redistribute it and/or modify it under the terms of the GNU General
 * Public License version 2, as published by the Free Software Foundation.
 *
 * pandora is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "pandora-defs.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "hashtable.h"

#if PINKTRACE_BITNESS_32_SUPPORTED
static hashtable_t *systable32 = NULL;
#endif
#if PINKTRACE_BITNESS_64_SUPPORTED
static hashtable_t *systable64 = NULL;
#endif

static void
systable_add_full(long no, pink_bitness_t bit, const char *name, sysfunc_t fenter, sysfunc_t fexit)
{
	sysentry_t *entry;

	entry = xmalloc(sizeof(sysentry_t));
	entry->name = name;
	entry->enter = fenter;
	entry->exit = fexit;

#if PINKTRACE_BITNESS_32_SUPPORTED
	if (bit == PINK_BITNESS_32) {
		ht_int32_node_t *node32 = hashtable_find(systable32, no, 1);
		node32->data = entry;
	}
#endif
#if PINKTRACE_BITNESS_64_SUPPORTED
	if (bit == PINK_BITNESS_64) {
		ht_int64_node_t *node64 = hashtable_find(systable64, no, 1);
		node64->data = entry;
	}
#endif
}

void
systable_init(void)
{
	int r;
#if PINKTRACE_BITNESS_32_SUPPORTED
	if ((r = hashtable_create(64, 0, &systable32) < 0)) {
		errno = -r;
		die_errno(-1, "hashtable_create");
	}
#endif
#if PINKTRACE_BITNESS_64_SUPPORTED
	if ((r = hashtable_create(64, 1, &systable64)) < 0) {
		errno = -r;
		die_errno(-1, "hashtable_create");
	}
#endif
}

void
systable_free(void)
{
#if PINKTRACE_BITNESS_32_SUPPORTED
	for (int i = 0; i < systable32->size; i++) {
		ht_int32_node_t *node = HT_NODE(systable32, systable32->nodes, i);
		if (node->data)
			free(node->data);
	}

	hashtable_destroy(systable32);
#endif
#if PINKTRACE_BITNESS_64_SUPPORTED
	for (int j = 0; j < systable64->size; j++) {
		ht_int64_node_t *node = HT_NODE(systable64, systable64->nodes, j);
		if (node->data)
			free(node->data);
	}

	hashtable_destroy(systable64);
#endif
}

void
systable_add(const char *name, sysfunc_t fenter, sysfunc_t fexit)
{
	long no;

#if PINKTRACE_BITNESS_32_SUPPORTED
	no = pink_name_lookup(name, PINK_BITNESS_32);
	if (no > 0)
		systable_add_full(no, PINK_BITNESS_32, name, fenter, fexit);
#endif /* PINKTRACE_BITNESS_32_SUPPORTED */

#if PINKTRACE_BITNESS_64_SUPPORTED
	no = pink_name_lookup(name, PINK_BITNESS_64);
	if (no > 0)
		systable_add_full(no, PINK_BITNESS_64, name, fenter, fexit);
#endif /* PINKTRACE_BITNESS_64_SUPPORTED */
}

const sysentry_t *
systable_lookup(long no, pink_bitness_t bit)
{
#if PINKTRACE_BITNESS_32_SUPPORTED
	if (bit == PINK_BITNESS_32) {
		ht_int32_node_t *node = hashtable_find(systable32, no, 0);
		return node ? node->data : NULL;
	}
#endif
#if PINKTRACE_BITNESS_64_SUPPORTED
	if (bit == PINK_BITNESS_64) {
		ht_int64_node_t *node = hashtable_find(systable64, no, 0);
		return node ? node->data : NULL;
	}
#endif
	return NULL;
}
