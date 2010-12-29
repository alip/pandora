/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010 Ali Polatel <alip@exherbo.org>
 * Based in part upon rsync which is:
 *   Copyright (C) 1996, 2000 Andrew Tridgell
 *   Copyright (C) 1996 Paul Mackerras
 *   Copyright (C) 2001, 2002 Martin Pool <mbp@samba.org>
 *   Copyright (C) 2003-2008 Wayne Davison
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

#ifndef HASHTABLE_H
#define HASHTABLE_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>
#include <unistd.h>

/* Find a variable that is either exactly 32-bits or longer.
 * If some code depends on 32-bit truncation, it will need to
 * take special action in a "#if SIZEOF_INT32 > 4" section. */
#ifndef int32
#if SIZEOF_INT32_T == 4
# define int32 int32_t
# define SIZEOF_INT32 4
#elif SIZEOF_INT == 4
# define int32 int
# define SIZEOF_INT32 4
#elif SIZEOF_LONG == 4
# define int32 long
# define SIZEOF_INT32 4
#elif SIZEOF_SHORT == 4
# define int32 short
# define SIZEOF_INT32 4
#elif SIZEOF_INT > 4
# define int32 int
# define SIZEOF_INT32 SIZEOF_INT
#elif SIZEOF_LONG > 4
# define int32 long
# define SIZEOF_INT32 SIZEOF_LONG
#else
# error Could not find a 32-bit integer variable
#endif
#else
# define SIZEOF_INT32 4
#endif

#ifndef uint32
#if SIZEOF_UINT32_T == 4
# define uint32 uint32_t
#else
# define uint32 unsigned int32
#endif
#endif

#if SIZEOF_OFF_T == 8 || !SIZEOF_OFF64_T || !defined HAVE_STRUCT_STAT64
#define OFF_T off_t
#define STRUCT_STAT struct stat
#define SIZEOF_CAPITAL_OFF_T SIZEOF_OFF_T
#else
#define OFF_T off64_t
#define STRUCT_STAT struct stat64
#define USE_STAT64_FUNCS 1
#define SIZEOF_CAPITAL_OFF_T SIZEOF_OFF64_T
#endif

/* CAVEAT: on some systems, int64 will really be a 32-bit integer IFF
 * that's the maximum size the file system can handle and there is no
 * 64-bit type available.  The rsync source must therefore take steps
 * to ensure that any code that really requires a 64-bit integer has
 * it (e.g. the checksum code uses two 32-bit integers for its 64-bit
 * counter). */
#if SIZEOF_INT64_T == 8
# define int64 int64_t
# define SIZEOF_INT64 8
#elif SIZEOF_LONG == 8
# define int64 long
# define SIZEOF_INT64 8
#elif SIZEOF_INT == 8
# define int64 int
# define SIZEOF_INT64 8
#elif SIZEOF_LONG_LONG == 8
# define int64 long long
# define SIZEOF_INT64 8
#elif SIZEOF_OFF64_T == 8
# define int64 off64_t
# define SIZEOF_INT64 8
#elif SIZEOF_OFF_T == 8
# define int64 off_t
# define SIZEOF_INT64 8
#elif SIZEOF_INT > 8
# define int64 int
# define SIZEOF_INT64 SIZEOF_INT
#elif SIZEOF_LONG > 8
# define int64 long
# define SIZEOF_INT64 SIZEOF_LONG
#elif SIZEOF_LONG_LONG > 8
# define int64 long long
# define SIZEOF_INT64 SIZEOF_LONG_LONG
#else
/* As long as it gets... */
# define int64 off_t
# define SIZEOF_INT64 SIZEOF_OFF_T
#endif

typedef struct {
	void *nodes;
	int32 size, entries;
	uint32 node_size;
	short key64;
} hashtable_t;

typedef struct {
	void *data;
	int32 key;
} ht_int32_node_t;

typedef struct {
	void *data;
	int64 key;
} ht_int64_node_t;

#define HT_NODE(tbl, bkts, i) ((void*)((char*)(bkts) + (i)*(tbl)->node_size))
#define HT_KEY(node, k64) ((k64)? ((ht_int64_node_t*)(node))->key \
			 : (int64)((ht_int32_node_t*)(node))->key)

int hashtable_create(int size, int key64, hashtable_t **tbl);
void hashtable_destroy(hashtable_t *tbl);
void *hashtable_find(hashtable_t *tbl, int64 key, int allocate_if_missing);

#endif /* !HASHTABLE_H */
