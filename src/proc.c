/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010 Ali Polatel <alip@exherbo.org>
 * Based in part upon systemd which is:
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
#include <assert.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "file.h"
#include "proc.h"

/* Useful macros */
#ifndef MAX
#define MAX(a,b)	(((a) > (b)) ? (a) : (b))
#endif
#ifndef MIN
#define MIN(a,b)	(((a) < (b)) ? (a) : (b))
#endif

/*
 * resolve /proc/$pid/cwd
 */
int
proc_cwd(pid_t pid, char **buf)
{
	int ret;
	char *cwd, *linkcwd;
	struct stat s;

	assert(pid >= 1);
	assert(buf);

	if (asprintf(&linkcwd, "/proc/%lu/cwd", (unsigned long)pid) < 0)
		return -ENOMEM;

	ret = readlink_alloc(linkcwd, &cwd);
	free(linkcwd);
	if (ret)
		return ret;

	/* If the current working directory of a process is removed after the
	 * process started, /proc/$pid/cwd is a dangling symbolic link and
	 * points to "/path/to/current/working/directory (deleted)".
	 */
	if (stat(cwd, &s) && errno == ENOENT) {
		char *c;
		if ((c = strrchr(cwd, ' ')))
			cwd[c - cwd] = '\0';
	}

	*buf = cwd;
	return 0;
}

/*
 * resolve /proc/$pid/fd/$dirfd
 */
int
proc_fd(pid_t pid, int dfd, char **buf)
{
	int ret;
	char *fd, *linkdir;

	assert(pid >= 1);
	assert(dfd >= 0);
	assert(buf);

	if (asprintf(&linkdir, "/proc/%lu/fd/%d", (unsigned long)pid, dfd) < 0)
		return -ENOMEM;

	ret = readlink_alloc(linkdir, &fd);
	free(linkdir);
	if (!ret)
		*buf = fd;
	return ret;
}

/*
 * read /proc/$pid/cmdline,
 * does not handle kernel threads which can't be traced anyway.
 */
int
proc_cmdline(pid_t pid, size_t max_length, char **buf)
{
	char *p, *r, *k;
	int c;
	bool space = false;
	size_t left;
	FILE *f;

	assert(pid >= 1);
	assert(max_length > 0);
	assert(buf);

	if (asprintf(&p, "/proc/%lu/cmdline", (unsigned long)pid) < 0)
		return -ENOMEM;

	f = fopen(p, "r");
	free(p);

	if (!f)
		return -errno;

	if (!(r = malloc(max_length * sizeof(char)))) {
		fclose(f);
		return -ENOMEM;
	}

	k = r;
	left = max_length;
	while ((c = getc(f)) != EOF) {
		if (isprint(c)) {
			if (space) {
				if (left <= 4)
					break;

				*(k++) = ' ';
				left--;
				space = false;
			}

			if (left <= 4)
				break;

			*(k++) = (char)c;
			left--;
		}
		else
			space = true;
	}

	if (left <= 4) {
		size_t n = MIN(left - 1, 3U);
		memcpy(k, "...", n);
		k[n] = 0;
	}
	else
		*k = 0;

	fclose(f);
	*buf = r;
	return 0;
}
