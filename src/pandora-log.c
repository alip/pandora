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
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define ANSI_NORMAL         "[00;00m"
#define ANSI_MAGENTA        "[00;35m"
#define ANSI_DARK_MAGENTA   "[01;35m"

static const char *prefix = LOG_DEFAULT_PREFIX;
static const char *suffix = LOG_DEFAULT_SUFFIX;
static FILE *logfd = NULL;
static FILE *logfp = NULL;

void
log_init(void)
{
	assert(pandora);
	assert(pandora->config->core.log.fd > 0);

	logfd = fdopen(pandora->config->core.log.fd, "a");
	if (!logfd)
		die_errno(3, "failed to open log fd:%u", pandora->config->core.log.fd);

	if (pandora->config->core.log.file) {
		logfp = fopen(pandora->config->core.log.file, "a");
		if (!logfp)
			die_errno(3, "failed to open log file `%s'", pandora->config->core.log.file);
	}
}

void
log_close(void)
{
	if (logfd)
		fclose(logfd);
	if (logfp)
		fclose(logfp);
}

void
log_prefix(const char *p)
{
	prefix = p;
}

void
log_suffix(const char *s)
{
	suffix = s;
}

void
log_msg_va(unsigned level, const char *fmt, va_list ap)
{
	int tty;
	const char *p, *s;
	FILE *fd;

	if (level > pandora->config->core.log.level)
		return;

	if (level < 2) {
		fd = logfd ? logfd : stderr;
		tty = isatty(fileno(fd));

		s = tty ? ANSI_NORMAL : "";
		if (!level)
			p = tty ? ANSI_DARK_MAGENTA : "";
		else
			p = tty ? ANSI_MAGENTA : "";

		fputs(p, fd);
		if (prefix) {
			if (pandora->config->core.log.timestamp)
				fprintf(fd, "%s@%lu: ", prefix, time(NULL));
			else
				fprintf(fd, "%s: ", prefix);
		}

		vfprintf(fd, fmt, ap);

		fputs(s, fd);
		if (suffix)
			fputs(suffix, fd);
	}

	if (!logfp)
		return;

	if (prefix) {
		if (pandora->config->core.log.timestamp)
			fprintf(logfp, "%s@%lu: ", prefix, time(NULL));
		else
			fprintf(logfp, "%s: ", prefix);
	}

	vfprintf(logfp, fmt, ap);

	if (suffix)
		fprintf(logfp, "%s", suffix);
}

void
log_msg(unsigned level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg_va(level, fmt, ap);
	va_end(ap);
}
