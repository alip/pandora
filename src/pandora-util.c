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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void
die(int code, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg_va(0, fmt, ap);
	va_end(ap);

	if (code < 0)
		abort();
	exit(code);
}

void
die_errno(int code, const char *fmt, ...)
{
	int save_errno;
	va_list ap;

	save_errno = errno;

	log_suffix(NULL);
	va_start(ap, fmt);
	log_msg_va(0, fmt, ap);
	va_end(ap);
	log_suffix(LOG_DEFAULT_SUFFIX);

	log_prefix(NULL);
	log_msg(0, " (errno:%d %s)", save_errno, strerror(save_errno));
	log_prefix(LOG_DEFAULT_PREFIX);

	if (code < 0)
		abort();
	exit(code);
}

void *
xmalloc(size_t size)
{
	void *ptr;

	ptr = malloc(size);
	if (!ptr)
		die_errno(-1, "malloc");

	return ptr;
}

void *
xcalloc(size_t nmemb, size_t size)
{
	void *ptr;

	ptr = calloc(nmemb, size);
	if (!ptr)
		die_errno(-1, "calloc");

	return ptr;
}

void *
xrealloc(void *ptr, size_t size)
{
	void *nptr;

	nptr = realloc(ptr, size);
	if (!nptr)
		die_errno(-1, "realloc");

	return nptr;
}

char *
xstrdup(const char *src)
{
	char *dest;

	dest = strdup(src);
	if (!dest)
		die_errno(-1, "strdup");

	return dest;
}

char *
xstrndup(const char *src, size_t n)
{
	char *dest;

	dest = strndup(src, n);
	if (!dest)
		die_errno(-1, "strndup");

	return dest;
}

int
xasprintf(char **strp, const char *fmt, ...)
{
	int r;
	char *dest;
	va_list ap;

	assert(strp);

	va_start(ap, fmt);
	r = vasprintf(&dest, fmt, ap);
	va_end(ap);

	if (r == -1) {
		errno = ENOMEM;
		die_errno(-1, "vasprintf");
	}

	*strp = dest;
	return r;
}
