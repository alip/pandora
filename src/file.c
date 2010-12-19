/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010 Ali Polatel <alip@exherbo.org>
 * canonicalize_filename_mode() is based in part upon coreutils which is:
 *   Copyright (C) 1996-2008 Free Software Foundation, Inc.
 * The following functions are based in part upon systemd:
 *   - path_is_absolute()
 *   - path_make_absolute()
 *   - readlink_alloc()
 *   which is:
 *   Copyright 2010 Lennart Poettering
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "file.h"

inline
int
path_is_absolute(const char *p)
{
	return p[0] == '/';
}

/* Makes every item in the list an absolute path by prepending
 * the prefix, if specified and necessary */
char *
path_make_absolute(const char *p, const char *prefix)
{
	char *r;

	if (path_is_absolute(p) || !prefix)
		return strdup(p);

	if (asprintf(&r, "%s/%s", prefix, p) < 0)
		return NULL;

	return r;
}

/* basename() wrapper which doesn't modify its argument */
int
basename_alloc(const char *path, char **buf)
{
	char *pathc, *bname, *bnamec;

	pathc = strdup(path);
	if (!pathc)
		return -ENOMEM;

	bname = basename(pathc);

	bnamec = strdup(bname);
	if (!bnamec) {
		free(pathc);
		return -ENOMEM;
	}

	free(pathc);
	*buf = bnamec;

	return 0;
}

/* dirname() wrapper which doesn't modify its argument */
int
dirname_alloc(const char *path, char **buf)
{
	char *pathc, *dname, *dnamec;

	pathc = strdup(path);
	if (!pathc)
		return -ENOMEM;

	dname = dirname(pathc);

	dnamec = strdup(dname);
	if (!dnamec) {
		free(pathc);
		return -ENOMEM;
	}

	free(pathc);
	*buf = dnamec;

	return 0;
}

/* readlink() wrapper which does:
 * - Allocate the string itself.
 * - Appends a zero-byte at the end.
 */
int
readlink_alloc(const char *path, char **buf)
{
	size_t l = 100;

	for (;;) {
		char *c;
		ssize_t n;

		c = malloc(l * sizeof(char));
		if (!c)
			return -ENOMEM;

		if ((n = readlink(path, c, l - 1)) < 0) {
			int ret = -errno;
			free(c);
			return ret;
		}

		if ((size_t)n < l - 1) {
			c[n] = 0;
			*buf = c;
			return 0;
		}

		free(c);
		l *= 2;
	}
}

/* Return the canonical absolute name of file NAME.  A canonical name
   does not contain any `.', `..' components nor any repeated file name
   separators ('/') or symlinks.  Whether components must exist
   or not depends on canonicalize mode.  The result is malloc'd.  */
int
canonicalize_filename_mode(const char *name, can_mode_t mode, int resolve, char **path)
{
	int linkcount = 0, ret = 0;
	char *rname, *dest, *extra_buf = NULL;
	const char *start;
	const char *end;
	const char *rname_limit;
	size_t extra_len = 0;

	if (!name || name[0] == '\0' || name[0] != '/')
		return -EINVAL;

	rname = malloc(PATH_MAX * sizeof(char));
	if (!rname)
		return -ENOMEM;
	rname_limit = rname + PATH_MAX;
	rname[0] = '/';
	dest = rname + 1;

	for (start = end = name; *start; start = end) {
		/* Skip sequence of multiple file name separators.  */
		while (*start == '/')
			++start;

		/* Find end of component */
		for (end = start; *end && *end != '/'; ++end)
			/* void  */;

		if (end - start == 0)
			break;
		else if (end - start == 1 && start[0] == '.')
			/* void */;
		else if (end - start == 2 && start[0] == '.' && start[1] == '.') {
			/* Back up previous component, ignore if at root
			 * already. */
			if (dest > rname + 1) {
				while ((--dest)[-1] != '/')
					/* void */;
			}
		}
		else {
			struct stat st;

			if (dest[-1] != '/')
				*dest++ = '/';

			if (dest + (end - start) >= rname_limit) {
				ptrdiff_t dest_offset = dest - rname;
				size_t new_size = rname_limit - rname;

				if (end - start + 1 > PATH_MAX)
					new_size += end - start + 1;
				else
					new_size += PATH_MAX;

				rname = realloc(rname, new_size);
				if (!rname)
					return -ENOMEM;
				rname_limit = rname + new_size;

				dest = rname + dest_offset;
			}

			dest = memcpy(dest, start, end - start);
			dest += end - start;
			*dest = '\0';

			if (lstat(rname, &st) != 0) {
				if (mode == CAN_EXISTING)
					goto error;
				if (mode == CAN_ALL_BUT_LAST && *end)
					goto error;
				st.st_mode = 0;
			}

			if (S_ISLNK(st.st_mode)) {
				char *buf;
				size_t n, len;

				if (!resolve)
					continue;

				/* Protect against infinite loops */
#ifndef PANDORA_MAXSYMLINKS
#ifdef MAXSYMLINKS
#define PANDORA_MAXSYMLINKS MAXSYMLINKS
#else
#define PANDORA_MAXSYMLINKS 32
#endif
#endif
				if (linkcount++ > PANDORA_MAXSYMLINKS) {
					errno = ELOOP;
					goto error;
				}

				if (readlink_alloc(rname, &buf) < 0)
					goto error;

				n = strlen(buf);
				len = strlen(end);

				if (!extra_len) {
					extra_len = (n + len + 1) > PATH_MAX
						? (n + len + 1)
						: PATH_MAX;
					extra_buf = malloc(extra_len * sizeof(char));
				}
				else if (n + len + 1 > extra_len) {
					extra_len = n + len + 1;
					extra_buf = realloc(extra_buf, extra_len * sizeof(char));
				}

				if (!extra_buf) {
					free(rname);
					return -ENOMEM;
				}

				/* Careful here, end may be a pointer into
				 * extra_buf... */
				memmove(&extra_buf[n], end, len + 1);
				name = end = memcpy(extra_buf, buf, n);

				if (buf[0] == '/')
					dest = rname + 1; /* Absolute symlink */
				else {
					/* Back up to previous component,
					 * ignore if at root already. */
					if (dest > rname + 1) {
						while ((--dest)[-1] != '/')
							/* void */;
					}
				}

				free(buf);
			}
			else {
				if (!S_ISDIR(st.st_mode) && *end) {
					errno = ENOTDIR;
					goto error;
				}
			}
		}
	}

	if (dest > rname + 1 && dest[-1] == '/')
		--dest;
	*dest = '\0';

	if (rname_limit != dest + 1) {
		rname = realloc(rname, dest - rname + 1);
		if (!rname)
			goto error;
	}

	if (extra_buf)
		free(extra_buf);
	*path = rname;
	return 0;

error:
	ret = -errno;
	if (extra_buf)
		free(extra_buf);
	if (rname)
		free(rname);
	return ret;
}
