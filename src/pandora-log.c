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

#include <stdarg.h>
#include <stdio.h>

int loglevel;
static FILE *logfp = NULL;

void
log_init(const char *filename)
{
	logfp = fopen(filename, "a");
	if (!logfp)
		die_errno(3, "log_init(`%s')", filename);
}

void
log_close(void)
{
	if (logfp)
		fclose(logfp);
}

void log_nl(int level)
{
	FILE *fd;

	fd = logfp ? logfp : stderr;

	if (level <= loglevel)
		fputc('\n', fd);
	if (level < 1 && fd != stderr)
		fputc('\n', stderr);
}

void
log_msg_va(int level, const char *fmt, va_list ap)
{
	FILE *fd;

	if (level > loglevel)
		return;

	fd = logfp ? logfp : stderr;

	if (level >= 0)
		fprintf(fd, "%s: ", progname);
	vfprintf(fd, fmt, ap);

	if (level < 2 && fd != stderr) {
		/* fatal and warning messages go to stderr as well */
		if (!level)
			fprintf(stderr, "fatal: ");
		else
			fprintf(stderr, "warning: ");
		vfprintf(stderr, fmt, ap);
	}
}

void
log_msg(int level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg_va(level, fmt, ap);
	va_end(ap);
}
