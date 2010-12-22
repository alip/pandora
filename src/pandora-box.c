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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "file.h"
#include "util.h"
#include "wildmatch.h"

static int
box_resolve_path_helper(const char *abspath, pid_t pid, int maycreat, int resolve, char **res)
{
	int ret;
	char *p;

	p = NULL;
#ifdef HAVE_PROC_SELF
	/* Special case for /proc/self.
	 * This symbolic link resolves to /proc/$pid, if we let
	 * canonicalize_filename_mode() resolve this, we'll get a different result.
	 */
	if (!strncmp(abspath, "/proc/self", 10)) {
		const char *tail = abspath + 10;
		if (!*tail || *tail == '/') {
			if (asprintf(&p, "/proc/%d%s", pid, tail) < 0)
				return -errno;
		}
	}
#endif /* HAVE_PROC_SELF */

	ret = canonicalize_filename_mode(p ? p : abspath, maycreat ? CAN_ALL_BUT_LAST : CAN_EXISTING, resolve, res);
	if (p)
		free(p);
	return ret;
}

int
box_resolve_path(const char *path, const char *prefix, pid_t pid, int maycreat, int resolve, char **res)
{
	int ret;
	char *abspath;

	abspath = path_make_absolute(path, prefix);
	if (!abspath)
		return -errno;

	ret = box_resolve_path_helper(abspath, pid, maycreat, resolve, res);
	free(abspath);
	return ret;
}

int
box_allow_path(const char *path, const slist_t *patterns)
{
	const slist_t *slist;

	for (slist = patterns; slist; slist = slist->next) {
		if (wildmatch(slist->data, path))
			return 1;
	}

	return 0;
}
