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

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "file.h"
#include "proc.h"
#include "util.h"
#include "wildmatch.h"

static void
box_report_violation(pink_easy_process_t *current, const sysinfo_t *info, const char *name, const char *path)
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

/* FIXME: This function is overly complicated and needs to be refactored! */
int
box_check_path(pink_easy_process_t *current, const char *name, sysinfo_t *info)
{
	int r;
	int ret;
	long fd;
	char *path, *abspath, *prefix;
	const char *myabspath;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	info->prefix = prefix = path = abspath = NULL;

	if (info->abspath) {
		/* Expect path resolving is done, skip to match! */
		goto match;
	}

	if (info->at) {
		if (!pink_util_get_arg(pid, bit, info->index - 1, &fd)) {
			if (errno != ESRCH) {
				warning("pink_util_get_arg(%lu, \"%s\", %u): %d(%s)",
						(unsigned long)pid,
						pink_bitness_name(bit),
						info->index - 1,
						errno, strerror(errno));
				return panic(current);
			}
			return PINK_EASY_CFLAG_DROP;
		}

		if (fd < 0) {
			errno = EBADF;
			r = deny(current);
			goto end;
		}

		if (fd != AT_FDCWD) {
			if ((ret = proc_fd(pid, fd, &prefix)) < 0) {
				errno = ret == -ENOENT ? EBADF : -ret;
				r = deny(current);
				goto end;
			}
		}

		info->prefix = prefix;
	}

	if ((r = path_decode(current, info->index, &path))) {
		switch (r) {
		case -2:
			r = deny(current);
			goto report;
		case -1:
			r = deny(current);
			goto end;
		default:
			/* PINK_EASY_CFLAG_* */
			return r;
		}
	}

	if ((r = path_resolve(current, info, path, &abspath))) {
		switch (r) {
		case -2:
			r = deny(current);
			goto report;
		case -1:
			r = deny(current);
			goto end;
		default:
			free(path);
			return r;
		}
	}

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
	box_report_violation(current, info, name, path);
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
