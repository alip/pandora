/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011 Ali Polatel <alip@exherbo.org>
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
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "util.h"

#define ANSI_NORMAL		"[00;00m"
#define ANSI_MAGENTA		"[00;35m"
#define ANSI_DARK_MAGENTA	"[01;35m"
#define ANSI_GREEN		"[00;32m"
#define ANSI_YELLOW		"[00;33m"
#define ANSI_CYAN		"[00;36m"

static const char *prefix = LOG_DEFAULT_PREFIX;
static const char *suffix = LOG_DEFAULT_SUFFIX;
static int logfd = -1;

PINK_GCC_ATTR((format (printf, 3, 0)))
inline
static void
log_me(int fd, unsigned level, const char *fmt, va_list ap)
{
	int tty;
	const char *p, *s;

	tty = isatty(fd);

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

	dprintf(fd, "%s", p);
	if (prefix) {
		if (pandora->config.log_timestamp)
			dprintf(fd, "%s@%lu: ", prefix, time(NULL));
		else
			dprintf(fd, "%s: ", prefix);
	}
	vdprintf(fd, fmt, ap);
	dprintf(fd, "%s%s", s, suffix ? suffix : "");
}

void
log_init(void)
{
	assert(pandora);

	if (pandora->config.log_file) {
		logfd = open(pandora->config.log_file, O_WRONLY|O_APPEND|O_CREAT, 0640);
		if (logfd < 0)
			die_errno(3, "failed to open log file `%s'", pandora->config.log_file);
	}
}

void
log_close(void)
{
	if (logfd != -1)
		close_nointr(logfd);
	logfd = -1;
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
	if (level > pandora->config.log_level)
		return;

	if (logfd != -1) {
		log_me(logfd, level, fmt, ap);
		if (level < 2)
			log_me(pandora->config.log_console_fd, level, fmt, ap);
	}
	else
		log_me(pandora->config.log_console_fd, level, fmt, ap);
}

void
log_msg(unsigned level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	log_msg_va(level, fmt, ap);
	va_end(ap);
}
