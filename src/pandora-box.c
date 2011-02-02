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

#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <arpa/inet.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "file.h"
#include "proc.h"
#include "util.h"
#include "wildmatch.h"

static void
box_report_violation_path(pink_easy_process_t *current, const sysinfo_t *info, const char *name, const char *path)
{
	if (info->at) {
		switch (info->index) {
		case 1:
			violation(current, "%s(\"%s\", prefix=\"%s\")",
					name, path ? path : "?",
					info->prefix ? info->prefix : "?");
			break;
		case 2:
			violation(current, "%s(?, \"%s\", prefix=\"%s\")",
					name, path ? path : "?",
					info->prefix ? info->prefix : "?");
			break;
		case 3:
			violation(current, "%s(?, ?, \"%s\", prefix=\"%s\")",
					name, path ? path : "?",
					info->prefix ? info->prefix : "?");
			break;
		default:
			violation(current, "%s(?)", name);
			break;
		}
	}
	else {
		switch (info->index) {
		case 0:
			violation(current, "%s(\"%s\")",
					name,
					path ? path : "?");
			break;
		case 1:
			violation(current, "%s(?, \"%s\")",
					name,
					path ? path : "?");
			break;
		case 2:
			violation(current, "%s(?, ?, \"%s\")",
					name,
					path ? path : "?");
			break;
		case 3:
			violation(current, "%s(?, ?, ?, \"%s\")",
					name,
					path ? path : "?");
			break;
		default:
			violation(current, "%s(?)", name);
			break;
		}
	}
}

static void
box_report_violation_sock(pink_easy_process_t *current, const sysinfo_t *info, const char *name, const pink_socket_address_t *paddr)
{
	char ip[64];

	switch (paddr->family) {
	case AF_UNIX:
		violation(current, "%s(%ld, %s:%s)",
				name,
				info->fd ? *info->fd : -1,
				*paddr->u.sa_un.sun_path ? "unix" : "unix-abstract",
				*paddr->u.sa_un.sun_path
					? paddr->u.sa_un.sun_path
					: paddr->u.sa_un.sun_path + 1);
		break;
	case AF_INET:
		inet_ntop(AF_INET, &paddr->u.sa_in.sin_addr, ip, sizeof(ip));
		violation(current, "%s(%ld, inet:%s@%d)",
				name,
				info->fd ? *info->fd : -1,
				ip, ntohs(paddr->u.sa_in.sin_port));
		break;
#if PANDORA_HAVE_IPV6
	case AF_INET6:
		inet_ntop(AF_INET6, &paddr->u.sa6.sin6_addr, ip, sizeof(ip));
		violation(current, "%s(%ld, inet6:%s@%d)",
				name,
				info->fd ? *info->fd : -1,
				ip, ntohs(paddr->u.sa6.sin6_port));
		break;
#endif
	default:
		break;
	}
}

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
			if (asprintf(&p, "/proc/%lu%s", (unsigned long)pid, tail) < 0)
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
box_match_path(const char *path, const slist_t *patterns, const char **match)
{
	const slist_t *slist;

	for (slist = patterns; slist; slist = slist->next) {
		if (wildmatch(slist->data, path)) {
			if (match)
				*match = slist->data;
			return 1;
		}
	}

	return 0;
}

int
box_check_path(pink_easy_process_t *current, const char *name, sysinfo_t *info)
{
	int r;
	char *path, *abspath, *prefix;
	const char *myabspath = NULL;
	proc_data_t *data = pink_easy_process_get_data(current);

	info->prefix = prefix = path = abspath = NULL;

	if (info->abspath) {
		/* Expect path resolving is done, skip to match! */
		goto match;
	}

#define HANDLE_RETURN(f)					\
	do {							\
		switch ((r)) {					\
		case -1:					\
			r = deny(current);			\
			goto end;				\
		case -2:					\
			r = deny(current);			\
			goto report;				\
		default:					\
			if ((f))				\
				abort();			\
			return r; /* PINK_EASY_CFLAG_* */	\
		}						\
	} while (0)

	if (info->at && (r = path_prefix(current, info)))
		HANDLE_RETURN(0);

	if ((r = path_decode(current, info->index, &path)))
		HANDLE_RETURN(0);

	if ((r = path_resolve(current, info, path, &abspath)))
		HANDLE_RETURN(1);

#undef HANDLE_RETURN

	if (info->buf) {
		/* Don't do any matching, return the absolute path to the
		 * caller. */
		*info->buf = abspath;
		goto end;
	}

match:
	myabspath = info->abspath ? info->abspath : abspath;
	if (box_match_path(myabspath, info->allow ? info->allow : data->config.allow.path, NULL))
		goto end;

	if (info->create == 2) {
		/* The system call *must* create the file */
		int sr;
		struct stat buf;

		sr = info->resolv ? stat(myabspath, &buf) : lstat(myabspath, &buf);
		if (!sr) {
			/* Yet the file exists... */
			errno = EEXIST;
			if (pandora->config->core.violation.ignore_safe) {
				r = deny(current);
				goto end;
			}
		}
		else
			errno = info->deny_errno ? info->deny_errno : EPERM;
	}
	else
		errno = info->deny_errno ? info->deny_errno : EPERM;
	r = deny(current);

report:
	if (!box_match_path(myabspath, info->filter ? info->filter : pandora->config->filter.path, NULL))
		box_report_violation_path(current, info, name, path);
end:
	if (prefix)
		free(prefix);
	if (path)
		free(path);
	if (!info->buf && abspath)
		free(abspath);
	info->prefix = NULL;

	return r;
}

int
box_check_sock(pink_easy_process_t *current, const char *name, sysinfo_t *info)
{
	int r;
	char *abspath;
	slist_t *slist;
	sock_match_t *m;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	pink_socket_address_t *psa;

	assert(info);

	r = 0;
	abspath = NULL;
	psa = xmalloc(sizeof(pink_socket_address_t));

	if (!pink_decode_socket_address(pid, bit, info->index, info->fd, psa)) {
		if (errno != ESRCH) {
			warning("pink_decode_socket_address(%lu, \"%s\", %u): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					info->index,
					errno, strerror(errno));
			r = panic(current);
			goto end;
		}
		r = PINK_EASY_CFLAG_DROP;
		goto end;
	}

	if (psa->family == AF_UNIX && *psa->u.sa_un.sun_path != 0) {
		/* Non-abstract UNIX socket, resolve the path. */
		if ((r = path_resolve(current, info, psa->u.sa_un.sun_path, &abspath))) {
			switch (r) {
			case -1:
				r = deny(current);
				goto end;
			case -2:
				r = deny(current);
				goto report;
			default:
				abort();
			}
		}

		for (slist = info->allow; slist; slist = slist->next) {
			m = slist->data;
			if (m->family == AF_UNIX
					&& !m->match.sa_un.abstract
					&& wildmatch(m->match.sa_un.path, abspath))
				goto end;
		}

		errno = info->deny_errno;
		r = deny(current);
		goto report;
	}

	for (slist = info->allow; slist; slist = slist->next) {
		if (sock_match(slist->data, psa))
			goto end;
	}

	errno = info->deny_errno;
	r = deny(current);

report:
	if (psa->family == AF_UNIX && *psa->u.sa_un.sun_path != 0) {
		/* Non-abstract UNIX socket */
		for (slist = info->filter; slist; slist = slist->next) {
			m = slist->data;
			if (m->family == AF_UNIX
					&& !m->match.sa_un.abstract
					&& wildmatch(m->match.sa_un.path, abspath))
				goto end;
		}
	}
	else {
		for (slist = info->filter; slist; slist = slist->next) {
			if (sock_match(slist->data, psa))
				goto end;
		}
	}

	box_report_violation_sock(current, info, name, psa);
end:
	if (!r) {
		if (info->unix_abspath)
			*info->unix_abspath = abspath;
		else if (abspath)
			free(abspath);

		if (info->addr)
			*info->addr = psa;
		else
			free(psa);
	}
	else {
		if (abspath)
			free(abspath);
		free(psa);
	}

	return r;
}
