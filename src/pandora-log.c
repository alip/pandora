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

#define ANSI_NORMAL		"[00;00m"
#define ANSI_MAGENTA		"[00;35m"
#define ANSI_DARK_MAGENTA	"[01;35m"
#define ANSI_GREEN		"[00;32m"
#define ANSI_YELLOW		"[00;33m"
#define ANSI_CYAN		"[00;36m"

static const char *prefix = LOG_DEFAULT_PREFIX;
static const char *suffix = LOG_DEFAULT_SUFFIX;
static FILE *logfd = NULL;
static FILE *logfp = NULL;

#if !defined(SPARSE) && defined(__GNUC__) && __GNUC__ >= 3
__attribute__ ((format (printf, 3, 0)))
#endif
inline
static void
log_me(FILE *fd, unsigned level, const char *fmt, va_list ap)
{
	int tty;
	const char *p, *s;

	tty = isatty(fileno(fd));

	switch (level) {
	case 0: /* fatal */
		p = tty ? ANSI_DARK_MAGENTA : "";
		s = tty ? ANSI_NORMAL : "";
		break;
	case 1: /* warning */
		p = tty ? ANSI_MAGENTA : "";
		s = tty ? ANSI_NORMAL : "";
		break;
	case 2: /* message */
		p = tty ? ANSI_GREEN : "";
		s = tty ? ANSI_NORMAL : "";
		break;
	case 3: /* info */
		p = tty ? ANSI_YELLOW : "";
		s = tty ? ANSI_NORMAL : "";
		break;
	case 4: /* debug */
		p = tty ? ANSI_CYAN : "";
		s = tty ? ANSI_NORMAL : "";
		break;
	default:
		p = s = "";
		break;
	}

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
	if (level > pandora->config->core.log.level)
		return;

	if (logfp) {
		log_me(logfp, level, fmt, ap);
		if (level < 2)
			log_me(logfd ? logfd : stderr, level, fmt, ap);
	}
	else
		log_me(logfd ? logfd : stderr, level, fmt, ap);
}

void
log_msg(unsigned level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg_va(level, fmt, ap);
	va_end(ap);
}
