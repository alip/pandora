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

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "slist.h"

static slist_t *systable[PINKTRACE_BITNESS_COUNT_SUPPORTED] = {
#if PINKTRACE_BITNESS_32_SUPPORTED
	[PINK_BITNESS_32] = NULL,
#endif /* PINKTRACE_BITNESS_32_SUPPORTED */
#if PINKTRACE_BITNESS_64_SUPPORTED
	[PINK_BITNESS_64] = NULL,
#endif /* PINKTRACE_BITNESS_64_SUPPORTED */
};

static int
systable_add_full(long no, pink_bitness_t bit, const char *name, sysfunc_t func)
{
	sysentry_t *node;

	if (no < 0)
		return -1;

	node = xmalloc(sizeof(sysentry_t));
	node->no = no;
	node->name = name;
	node->func = func;

	systable[bit] = slist_prepend(systable[bit], node);
	if (!systable[bit])
		die_errno(-1, "Out of memory");

	return 0;
}

void
systable_free(void)
{
#if PINKTRACE_BITNESS_32_SUPPORTED
	slist_free(systable[PINK_BITNESS_32], free);
#endif /* PINKTRACE_BITNESS_32_SUPPORTED */
#if PINKTRACE_BITNESS_64_SUPPORTED
	slist_free(systable[PINK_BITNESS_64], free);
#endif /* PINKTRACE_BITNESS_64_SUPPORTED */
}

void
systable_add(const char *name, sysfunc_t func)
{
	long no;

#if PINKTRACE_BITNESS_32_SUPPORTED
	no = pink_name_lookup(name, PINK_BITNESS_32);
	systable_add_full(no, PINK_BITNESS_32, name, func);
#endif /* PINKTRACE_BITNESS_32_SUPPORTED */

#if PINKTRACE_BITNESS_64_SUPPORTED
	no = pink_name_lookup(name, PINK_BITNESS_64);
	systable_add_full(no, PINK_BITNESS_64, name, func);
#endif /* PINKTRACE_BITNESS_64_SUPPORTED */
}

const sysentry_t *
systable_lookup(long no, pink_bitness_t bit)
{
	slist_t *slist;
	sysentry_t *node;

	switch (bit) {
#if PINKTRACE_BITNESS_32_SUPPORTED
	case PINK_BITNESS_32:
		for (slist = systable[PINK_BITNESS_32]; slist; slist = slist->next) {
			node = (sysentry_t *)slist->data;
			if (node->no == no)
				return node;
		}
		return NULL;
#endif /* PINKTRACE_BITNESS_32_SUPPORTED */
#if PINKTRACE_BITNESS_64_SUPPORTED
	case PINK_BITNESS_64:
		for (slist = systable[PINK_BITNESS_64]; slist; slist = slist->next) {
			node = (sysentry_t *)slist->data;
			if (node->no == no)
				return node;
		}
		return NULL;
#endif /* PINKTRACE_BITNESS_64_SUPPORTED */
	default:
		return NULL;
	}
}
