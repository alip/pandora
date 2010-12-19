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

#ifndef _ATFILE_SOURCE
#define _ATFILE_SOURCE
#endif

#include <errno.h>
#include <fnmatch.h>
#include <stdio.h>
#include <stdlib.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "file.h"
#include "number.h"

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
		if (asprintf(&p, "/proc/%d/%s", pid, abspath + 10) < 0)
			return -errno;
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
box_allow_path(const char *path, const slist_t *prefixes)
{
	int flags;
	const slist_t *slist;

	flags = 0;
	if (config->core.fnmatch_slash_special)
		flags |= FNM_PATHNAME;
	if (config->core.fnmatch_period_special)
		flags |= FNM_PERIOD;

	for (slist = prefixes; slist; slist = slist->next) {
		if (!fnmatch(slist->data, path, flags))
			return 1;
	}

	return 0;
}

int
box_cast_magic(pink_easy_process_t *current, const char *path)
{
	int n, ret;
	const char *var, *val;
	proc_data_t *data;

#define MAGIC_CORE PANDORA_MAGIC_PREFIX"/core/"
#define MAGIC_ALLOW PANDORA_MAGIC_PREFIX"/allow/"
#define MAGIC_FILTER PANDORA_MAGIC_PREFIX"/filter/"

#define MAGIC_CORE_FNMATCH_SLASH_SPECIAL "fnmatch_slash_special"
#define MAGIC_CORE_FNMATCH_PERIOD_SPECIAL "fnmatch_period_special"
#define MAGIC_CORE_FOLLOWFORK "followfork"
#define MAGIC_CORE_EXIT_WAIT_ALL "exit_wait_all"
#define MAGIC_CORE_AUTO_ALLOW_PER_PROCESS_DIRS "auto_allow_per_process_dirs"
#define MAGIC_CORE_AUTO_ALLOW_SUCCESSFUL_BIND "auto_allow_successful_bind"
#define MAGIC_CORE_MAGIC_LOCK "magic_lock"
#define MAGIC_CORE_SANDBOX_EXEC "sandbox_exec"
#define MAGIC_CORE_SANDBOX_PATH "sandbox_path"
#define MAGIC_CORE_SANDBOX_SOCK "sandbox_sock"

#define MAGIC_EXEC "exec"
#define MAGIC_PATH "path"
#define MAGIC_SOCK "sock"
#define MAGIC_SOCK_BIND "bind"
#define MAGIC_SOCK_CONNECT "connect"

	errno = 0;
	data = pink_easy_process_get_data(current);

	if (strncmp(path, PANDORA_MAGIC_PREFIX, sizeof(PANDORA_MAGIC_PREFIX) - 1)) {
		/* No magic */
		return 0;
	}

	if (!strncmp(path, MAGIC_ALLOW, sizeof(MAGIC_ALLOW) - 1)) {
		var = path + sizeof(MAGIC_ALLOW) - 1;

		if (!strncmp(var, MAGIC_EXEC"/", sizeof(MAGIC_EXEC))) {
			val = var + sizeof(MAGIC_EXEC);
			if (*val)
				data->config.allow.exec = slist_prepend(data->config.allow.exec, xstrdup(val));
		}
		else if (!strncmp(var, MAGIC_PATH"/", sizeof(MAGIC_PATH))) {
			val = var + sizeof(MAGIC_PATH);
			if (*val)
				data->config.allow.path = slist_prepend(data->config.allow.path, xstrdup(val));
		}
		else if (!strncmp(var, MAGIC_SOCK"/", sizeof(MAGIC_SOCK))) {
			val = var + sizeof(MAGIC_SOCK);
			if (!strncmp(val, MAGIC_SOCK_BIND"/", sizeof(MAGIC_SOCK_BIND))) {
				val += sizeof(MAGIC_SOCK_BIND);
				if (*val)
					data->config.allow.sock.bind = slist_prepend(data->config.allow.sock.bind, xstrdup(val));
			}
			else if (!strncmp(val, MAGIC_SOCK_CONNECT"/", sizeof(MAGIC_SOCK_CONNECT))) {
				val += sizeof(MAGIC_SOCK_CONNECT);
				if (*val)
					data->config.allow.sock.connect = slist_prepend(data->config.allow.sock.connect, xstrdup(val));
			}
		}
	}

	if (!strncmp(path, MAGIC_FILTER, sizeof(MAGIC_FILTER) - 1)) {
		var = path + sizeof(MAGIC_FILTER) - 1;

		if (!strncmp(var, MAGIC_EXEC"/", sizeof(MAGIC_EXEC))) {
			val = var + sizeof(MAGIC_EXEC);
			if (*val)
				config->filter.exec = slist_prepend(config->filter.exec, xstrdup(val));
		}
		else if (!strncmp(var, MAGIC_PATH"/", sizeof(MAGIC_PATH))) {
			val = var + sizeof(MAGIC_PATH);
			if (*val)
				config->filter.path = slist_prepend(config->filter.path, xstrdup(val));
		}
		else if (!strncmp(var, MAGIC_SOCK"/", sizeof(MAGIC_SOCK))) {
			val = var + sizeof(MAGIC_SOCK);
			if (*val)
				config->filter.sock = slist_prepend(config->filter.sock, xstrdup(val));
		}
	}

	if (!strncmp(path, MAGIC_CORE, sizeof(MAGIC_CORE) - 1)) {
		var = path + sizeof(MAGIC_CORE) - 1;

		if (!strncmp(var, MAGIC_CORE_FNMATCH_SLASH_SPECIAL"/", sizeof(MAGIC_CORE_FNMATCH_SLASH_SPECIAL))) {
			ret = safe_atoi(var + sizeof(MAGIC_CORE_FNMATCH_SLASH_SPECIAL), &n);
			if (ret >= 0)
				config->core.fnmatch_slash_special = n ? 1 : 0;
		}
		else if (!strncmp(var, MAGIC_CORE_FNMATCH_PERIOD_SPECIAL"/", sizeof(MAGIC_CORE_FNMATCH_PERIOD_SPECIAL))) {
			ret = safe_atoi(var + sizeof(MAGIC_CORE_FNMATCH_PERIOD_SPECIAL), &n);
			if (ret >= 0)
				config->core.fnmatch_period_special = n ? 1 : 0;
		}
#if 0
#error Not implemented
		else if (!strncmp(var, MAGIC_CORE_FOLLOWFORK"/", sizeof(MAGIC_CORE_FOLLOWFORK))) {}
#endif
		else if (!strncmp(var, MAGIC_CORE_EXIT_WAIT_ALL"/", sizeof(MAGIC_CORE_EXIT_WAIT_ALL))) {
			ret = safe_atoi(var + sizeof(MAGIC_CORE_EXIT_WAIT_ALL), &n);
			if (ret >= 0)
				config->core.exit_wait_all = n ? 1 : 0;
		}
		else if (!strncmp(var, MAGIC_CORE_AUTO_ALLOW_PER_PROCESS_DIRS"/", sizeof(MAGIC_CORE_AUTO_ALLOW_PER_PROCESS_DIRS))) {
			ret = safe_atoi(var + sizeof(MAGIC_CORE_AUTO_ALLOW_PER_PROCESS_DIRS), &n);
			if (ret >= 0)
				config->core.auto_allow_per_process_dirs = n ? 1 : 0;
		}
		else if (!strncmp(var, MAGIC_CORE_AUTO_ALLOW_SUCCESSFUL_BIND"/", sizeof(MAGIC_CORE_AUTO_ALLOW_SUCCESSFUL_BIND))) {
			ret = safe_atoi(var + sizeof(MAGIC_CORE_AUTO_ALLOW_SUCCESSFUL_BIND), &n);
			if (ret >= 0)
				config->core.auto_allow_successful_bind = n ? 1 : 0;
		}
		else if (!strncmp(var, MAGIC_CORE_MAGIC_LOCK"/", sizeof(MAGIC_CORE_MAGIC_LOCK))) {
			val = var + sizeof(MAGIC_CORE_MAGIC_LOCK);
			if (!strcmp(val, "on"))
				data->config.core.magic_lock = LOCK_SET;
			else if (!strcmp(val, "exec"))
				data->config.core.magic_lock = LOCK_PENDING;
			/* Doesn't make sense
			 * else if (!strcmp(val, "off"))
			 *      data->config.core.magic_lock = LOCK_UNSET;
			 */
		}
		else if (!strncmp(var, MAGIC_CORE_SANDBOX_EXEC"/", sizeof(MAGIC_CORE_SANDBOX_EXEC))) {
			ret = safe_atoi(var + sizeof(MAGIC_CORE_SANDBOX_EXEC), &n);
			if (ret >= 0)
				data->config.core.sandbox_exec = n ? 1 : 0;
		}
		else if (!strncmp(var, MAGIC_CORE_SANDBOX_PATH"/", sizeof(MAGIC_CORE_SANDBOX_PATH))) {
			ret = safe_atoi(var + sizeof(MAGIC_CORE_SANDBOX_PATH), &n);
			if (ret >= 0)
				data->config.core.sandbox_path = n ? 1 : 0;
		}
		else if (!strncmp(var, MAGIC_CORE_SANDBOX_SOCK"/", sizeof(MAGIC_CORE_SANDBOX_SOCK))) {
			ret = safe_atoi(var + sizeof(MAGIC_CORE_SANDBOX_SOCK), &n);
			if (ret >= 0)
				data->config.core.sandbox_sock = n ? 1 : 0;
		}
	}

	return 1;
}
