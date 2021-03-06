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
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <arpa/inet.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"
#include "addrfamily.h"
#include "file.h"
#include "proc.h"
#include "util.h"
#include "wildmatch.h"

inline
static void
box_report_violation_path(pink_easy_process_t *current, const char *name, unsigned ind, const char *path)
{
	switch (ind) {
	case 0:
		violation(current, "%s(\"%s\")", name, path);
		break;
	case 1:
		violation(current, "%s(?, \"%s\")", name, path);
		break;
	case 2:
		violation(current, "%s(?, ?, \"%s\")", name, path);
		break;
	case 3:
		violation(current, "%s(?, ?, ?, \"%s\")", name, path);
		break;
	default:
		violation(current, "%s(?)", name);
		break;
	}
}

inline
static void
box_report_violation_path_at(pink_easy_process_t *current, const char *name, unsigned ind, const char *path, const char *prefix)
{
	switch (ind) {
	case 1:
		violation(current, "%s(\"%s\", prefix=\"%s\")", name, path, prefix);
		break;
	case 2:
		violation(current, "%s(?, \"%s\", prefix=\"%s\")", name, path, prefix);
		break;
	case 3:
		violation(current, "%s(?, ?, \"%s\", prefix=\"%s\")", name, path, prefix);
		break;
	default:
		violation(current, "%s(?)", name);
		break;
	}
}

static void
box_report_violation_sock(pink_easy_process_t *current, const sys_info_t *info, const char *name, const pink_socket_address_t *paddr)
{
	char ip[64];
	const char *f;

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
		f = address_family_to_string(paddr->family);
		violation(current, "%s(-1, ?:%s)", name, f ? f : "AF_???");
		break;
	}
}

static int
box_resolve_path_helper(const char *abspath, pid_t pid, int maycreat, int resolve, char **res)
{
	int r;
	char *p;

	p = NULL;
#ifdef HAVE_PROC_SELF
	/* Special case for /proc/self.
	 * This symbolic link resolves to /proc/$pid, if we let
	 * canonicalize_filename_mode() resolve this, we'll get a different result.
	 */
	if (startswith(abspath, "/proc/self")) {
		const char *tail = abspath + STRLEN_LITERAL("/proc/self");
		if (!*tail || *tail == '/') {
			if (asprintf(&p, "/proc/%lu%s", (unsigned long)pid, tail) < 0)
				return -errno;
		}
	}
#endif /* HAVE_PROC_SELF */

	r = canonicalize_filename_mode(p ? p : abspath, maycreat ? CAN_ALL_BUT_LAST : CAN_EXISTING, resolve, res);
	if (p)
		free(p);
	return r;
}

int
box_resolve_path(const char *path, const char *prefix, pid_t pid, int maycreat, int resolve, char **res)
{
	int r;
	char *abspath;

	abspath = path_make_absolute(path, prefix);
	if (!abspath)
		return -errno;

	r = box_resolve_path_helper(abspath, pid, maycreat, resolve, res);
	free(abspath);
	return r;
}

int
box_match_path(const char *path, const slist_t *patterns, const char **match)
{
	struct snode *node;

	SLIST_FOREACH(node, patterns, up) {
		if (wildmatch_ext(node->data, path)) {
			if (match)
				*match = node->data;
			return 1;
		}
	}

	return 0;
}

int
box_check_path(pink_easy_process_t *current, const char *name, sys_info_t *info)
{
	int r;
	char *prefix, *path, *abspath;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	slist_t *wblist;

	assert(current);
	assert(info);

	prefix = path = abspath = NULL;

	if (info->at && (r = path_prefix(current, info->index - 1, &prefix))) {
		if (r < 0) {
			errno = EPERM; /* or -r for the real errno */
			r = deny(current);
			if (pandora->config.violation_raise_fail)
				violation(current, "%s()", name);
		}
		return r;
	}

	r = path_decode(current, info->index, &path);
	if (r < 0) {
		errno = EPERM; /* or -r for the real errno */
		r = deny(current);
		if (pandora->config.violation_raise_fail)
			violation(current, "%s()", name);
		goto end;
	}
	else if (r /* > 0 */)
		goto end;

	if ((r = box_resolve_path(path, prefix ? prefix : data->cwd, pid, info->create > 0, info->resolv, &abspath)) < 0) {
		warning("resolving path:\"%s\" [%s() index:%u prefix:\"%s\"] failed for process:%lu [%s name:\"%s\" cwd:\"%s\"] (errno:%d %s)",
				path, name, info->index, prefix,
				(unsigned long)pid, pink_bitness_name(bit),
				data->comm, data->cwd,
				-r, strerror(-r));
		errno = EPERM; /* or -r for the real errno */
		r = deny(current);
		if (pandora->config.violation_raise_fail)
			violation(current, "%s()", name);
		goto end;
	}
	debug("resolved path:\"%s\" to absolute path:\"%s\" [name=%s() create=%d resolv=%d] for process:%lu [%s name:\"%s\" cwd:\"%s\"]",
			path, abspath, name, info->create, info->resolv,
			(unsigned long)pid, pink_bitness_name(bit),
			data->comm, data->cwd);

	if (info->wblist)
		wblist = info->wblist;
	else if (info->whitelisting)
		wblist = &data->config.whitelist_write;
	else
		wblist = &data->config.blacklist_write;

	if (info->whitelisting) {
		if (box_match_path(abspath, wblist, NULL)) {
			/* Path matches one of the whitelisted path patterns.
			 * Allow access!
			 */
			r = 0;
			goto end;
		}
	}
	else if (!box_match_path(abspath, wblist, NULL)) {
		/* Path does not match one of the blacklisted path patterns.
		 * Allow access
		 */
		r = 0;
		goto end;
	}

	errno = info->deny_errno ? info->deny_errno : EPERM;

	if (info->safe && !pandora->config.violation_raise_safe) {
		r = deny(current);
		goto end;
	}

	if (info->create == 2) {
		/* The system call *must* create the file */
		int sr;
		struct stat buf;

		sr = info->resolv ? stat(abspath, &buf) : lstat(abspath, &buf);
		if (!sr) {
			/* Yet the file exists... */
			debug("system call %s() must create existant path:\"%s\" for process:%lu [%s name:\"%s\" cwd:\"%s\"]",
					name, abspath,
					(unsigned long)pid, pink_bitness_name(bit),
					data->comm, data->cwd);

			debug("denying system call %s() with -EEXIST", name);
			errno = EEXIST;
			r = deny(current);

			if (!pandora->config.violation_raise_safe)
				goto end;
		}
		else
			errno = info->deny_errno ? info->deny_errno : EPERM;
	}

	r = deny(current);

	if (!box_match_path(abspath, info->filter ? info->filter : &pandora->config.filter_write, NULL)) {
		if (info->at)
			box_report_violation_path_at(current, name, info->index, path, prefix);
		else
			box_report_violation_path(current, name, info->index, path);
	}

end:
	if (prefix)
		free(prefix);
	if (path)
		free(path);
	if (abspath)
		free(abspath);

	return r;
}

int
box_check_sock(pink_easy_process_t *current, const char *name, sys_info_t *info)
{
	int r;
	char *abspath;
	struct snode *node;
	sock_match_t *m;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	pink_socket_address_t *psa;

	assert(current);
	assert(info);

	r = 0;
	abspath = NULL;
	psa = xmalloc(sizeof(pink_socket_address_t));

	if (!pink_decode_socket_address(pid, bit, info->index, info->fd, psa)) {
		if (errno != ESRCH) {
			warning("pink_decode_socket_address(%lu, \"%s\", %u) failed (errno:%d %s)",
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

	/* Check for supported socket family. */
	switch (psa->family) {
	case AF_UNIX:
	case AF_INET:
#if PANDORA_HAVE_IPV6
	case AF_INET6:
#endif
		break;
	default:
		if (pandora->config.whitelist_unsupported_socket_families)
			goto end;
		errno = EAFNOSUPPORT;
		r = deny(current);
		goto report;
	}

	if (psa->family == AF_UNIX && *psa->u.sa_un.sun_path != 0) {
		/* Non-abstract UNIX socket, resolve the path. */
		if ((r = box_resolve_path(psa->u.sa_un.sun_path, data->cwd, pid, 1, info->resolv, &abspath)) < 0) {
			warning("resolving path:\"%s\" [%s() index:%u] failed for process:%lu [%s name:\"%s\" cwd:\"%s\"] (errno:%d %s)",
					psa->u.sa_un.sun_path, name, info->index,
					(unsigned long)pid, pink_bitness_name(bit),
					data->comm, data->cwd,
					-r, strerror(-r));
			errno = EPERM; /* or -r for the real errno */
			r = deny(current);
			if (pandora->config.violation_raise_fail)
				violation(current, "%s()", name);
			goto end;
		}

		SLIST_FOREACH(node, info->wblist, up) {
			m = node->data;
			if (m->family == AF_UNIX && !m->match.sa_un.abstract) {
				if (info->whitelisting) {
					if (wildmatch_ext(m->match.sa_un.path, abspath))
						goto end;
				}
				else if (!wildmatch_ext(m->match.sa_un.path, abspath))
					goto end;
			}
		}

		errno = info->deny_errno;
		r = deny(current);
		goto filter;
	}

	SLIST_FOREACH(node, info->wblist, up) {
		if (info->whitelisting) {
			if (sock_match(node->data, psa))
				goto end;
		}
		else if (!sock_match(node->data, psa))
			goto end;
	}

	errno = info->deny_errno;
	r = deny(current);

filter:
	if (psa->family == AF_UNIX && *psa->u.sa_un.sun_path != 0) {
		/* Non-abstract UNIX socket */
		SLIST_FOREACH(node, info->filter, up) {
			m = node->data;
			if (m->family == AF_UNIX
					&& !m->match.sa_un.abstract
					&& wildmatch_ext(m->match.sa_un.path, abspath))
				goto end;
		}
	}
	else {
		SLIST_FOREACH(node, info->filter, up) {
			if (sock_match(node->data, psa))
				goto end;
		}
	}

report:
	box_report_violation_sock(current, info, name, psa);

end:
	if (!r) {
		if (info->abspath)
			*info->abspath = abspath;
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
