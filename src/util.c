/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011 Ali Polatel <alip@exherbo.org>
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

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "util.h"

int
safe_atoi(const char *s, int *ret_i)
{
	char *x = NULL;
	long l;

	errno = 0;
	l = strtol(s, &x, 0);

	if (!x || *x || errno)
		return errno ? -errno : -EINVAL;

	if ((long) (int) l != l)
		return -ERANGE;

	*ret_i = (int) l;
	return 0;
}

int
safe_atou(const char *s, unsigned *ret_u)
{
	char *x = NULL;
	unsigned long l;

	assert(s);
	assert(ret_u);

	errno = 0;
	l = strtoul(s, &x, 0);

	if (!x || *x || errno)
		return errno ? -errno : -EINVAL;

	if ((unsigned long) (unsigned) l != l)
		return -ERANGE;

	*ret_u = (unsigned) l;
	return 0;
}

int
safe_atollu(const char *s, long long unsigned *ret_llu)
{
	char *x = NULL;
	unsigned long long l;

	assert(s);
	assert(ret_llu);

	errno = 0;
	l = strtoull(s, &x, 0);

	if (!x || *x || errno)
		return errno ? -errno : -EINVAL;

	*ret_llu = l;
	return 0;
}

int
parse_pid(const char *s, pid_t *ret_pid)
{
	unsigned long ul;
	pid_t pid;
	int r;

	assert(s);
	assert(ret_pid);

	if ((r = safe_atolu(s, &ul)) < 0)
		return r;

	pid = (pid_t) ul;

	if ((unsigned long) pid != ul)
		return -ERANGE;

	if (pid <= 0)
		return -ERANGE;

	*ret_pid = pid;
	return 0;
}

int
parse_port(const char *s, unsigned *ret_port)
{
	int r;
	unsigned port;

	assert(s);
	assert(ret_port);

	if ((r = safe_atou(s, &port)) < 0)
		return r;

	if (port > 65535)
		return -ERANGE;

	*ret_port = port;
	return 0;
}

bool
startswith(const char *s, const char *prefix)
{
	size_t sl, pl;

	assert(s);
	assert(prefix);

	sl = strlen(s);
	pl = strlen(prefix);

	if (pl == 0)
		return true;

	if (sl < pl)
		return false;

	return memcmp(s, prefix, pl) == 0;
}

int
close_nointr(int fd)
{
	assert(fd >= 0);

	for (;;) {
		int r;

		if ((r = close(fd)) >= 0)
			return r;

		if (errno != EINTR)
			return r;
	}
	/* never reached */
}
