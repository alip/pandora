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
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "util.h"

static int
_set_log_fd(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	int fd = *(const int *)val;

	if (fd <= 0)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config->core.log.fd = fd;

	return 0;
}

static int
_set_log_file(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;

	if (!str /* || !*str */)
		return MAGIC_ERROR_INVALID_VALUE;

	if (!*str) {
		if (pandora->config->core.log.file)
			free(pandora->config->core.log.file);
		pandora->config->core.log.file = NULL;
		return 0;
	}

	if (pandora->config->core.log.file)
		free(pandora->config->core.log.file);
	pandora->config->core.log.file = xstrdup(str);

	return 0;
}

static int
_set_log_level(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	int level = *(const int *)val;

	if (level < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config->core.log.level = level;

	return 0;
}

static int
_set_log_timestamp(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	pandora->config->core.log.timestamp = *(const int *)val ? 1 : 0;

	return 0;
}

static int
_set_sandbox_exec(const void *val, pink_easy_process_t *current)
{
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	box->core.sandbox.exec = *(const int *)val ? 1 : 0;

	return 0;
}

static int
_query_sandbox_exec(pink_easy_process_t *current)
{
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	return box->core.sandbox.exec;
}

static int
_set_sandbox_path(const void *val, pink_easy_process_t *current)
{
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	box->core.sandbox.path = *(const int *)val ? 1 : 0;

	return 0;
}

static int
_query_sandbox_path(pink_easy_process_t *current)
{
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	return box->core.sandbox.path;
}

static int
_set_sandbox_sock(const void *val, pink_easy_process_t *current)
{
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	box->core.sandbox.sock = *(const int *)val ? 1 : 0;

	return 0;
}

static int
_query_sandbox_sock(pink_easy_process_t *current)
{
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	return box->core.sandbox.sock;
}

static int
_set_allow_ppd(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	pandora->config->core.allow.per_process_directories = *(const int *)val ? 1 : 0;

	return 0;
}

static int
_set_allow_sb(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	pandora->config->core.allow.successful_bind = *(const int *)val ? 1 : 0;

	return 0;
}

static int
_set_abort_decision(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;

	if (!strcmp(str, "killall"))
		pandora->config->core.abort.decision = ABORT_KILLALL;
	else if (!strcmp(str, "contall"))
		pandora->config->core.abort.decision = ABORT_CONTALL;
	else
		return MAGIC_ERROR_INVALID_VALUE;

	return 0;
}

static int
_set_panic_decision(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;

	if (!strcmp(str, "kill"))
		pandora->config->core.panic.decision = PANIC_KILL;
	else if (!strcmp(str, "cont"))
		pandora->config->core.panic.decision = PANIC_CONT;
	else if (!strcmp(str, "contall"))
		pandora->config->core.panic.decision = PANIC_CONTALL;
	else if (!strcmp(str, "killall"))
		pandora->config->core.panic.decision = PANIC_KILLALL;
	else
		return MAGIC_ERROR_INVALID_VALUE;

	return 0;
}

static int
_set_panic_exit_code(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	pandora->config->core.panic.exit_code = *(const int *)val;

	return 0;
}

static int
_set_violation_decision(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;

	if (!strcmp(str, "deny"))
		pandora->config->core.violation.decision = VIOLATION_DENY;
	else if (!strcmp(str, "kill"))
		pandora->config->core.violation.decision = VIOLATION_KILL;
	else if (!strcmp(str, "killall"))
		pandora->config->core.violation.decision = VIOLATION_KILLALL;
	else if (!strcmp(str, "cont"))
		pandora->config->core.violation.decision = VIOLATION_CONT;
	else if (!strcmp(str, "contall"))
		pandora->config->core.violation.decision = VIOLATION_CONTALL;
	else
		return MAGIC_ERROR_INVALID_VALUE;

	return 0;
}

static int
_set_violation_exit_code(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	pandora->config->core.violation.exit_code = *(const int *)val;

	return 0;
}

static int
_set_violation_ignore_safe(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	pandora->config->core.violation.ignore_safe = *(const int *)val ? 1 : 0;

	return 0;
}

static int
_set_trace_followfork(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	pandora->config->core.trace.followfork = *(const int *)val ? 1 : 0;

	return 0;
}

static int
_query_trace_followfork(PINK_UNUSED pink_easy_process_t *current)
{
	return pandora->config->core.trace.followfork;
}

static int
_set_trace_exit_wait_all(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	pandora->config->core.trace.exit_wait_all = *(const int *)val ? 1 : 0;

	return 0;
}

static int
_query_trace_exit_wait_all(PINK_UNUSED pink_easy_process_t *current)
{
	return pandora->config->core.trace.exit_wait_all;
}

static int
_set_trace_magic_lock(const void *val, pink_easy_process_t *current)
{
	const char *str = val;
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	if (!strcmp(str, "on"))
		box->core.trace.magic_lock = LOCK_SET;
	else if (!strcmp(str, "off"))
		box->core.trace.magic_lock = LOCK_UNSET;
	else if (!strcmp(str, "exec"))
		box->core.trace.magic_lock = LOCK_PENDING;
	else
		return MAGIC_ERROR_INVALID_VALUE;

	return 0;
}

static int
_set_trace_kill_if_match(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config->trace.kill_if_match = slist_prepend(pandora->config->trace.kill_if_match, xstrdup(str));
	return pandora->config->trace.kill_if_match ? 0 : MAGIC_ERROR_OOM;
}

static int
_set_trace_resume_if_match(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config->trace.resume_if_match = slist_prepend(pandora->config->trace.resume_if_match, xstrdup(str));
	return pandora->config->trace.resume_if_match ? 0 : MAGIC_ERROR_OOM;
}

static int
_set_allow_exec(const void *val, pink_easy_process_t *current)
{
	const char *str = val;
	sandbox_t *box;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	box->allow.exec = slist_prepend(box->allow.exec, xstrdup(str));
	return box->allow.exec ? 0 : MAGIC_ERROR_OOM;
}

static int
_set_allow_path(const void *val, pink_easy_process_t *current)
{
	const char *str = val;
	sandbox_t *box;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	box->allow.path = slist_prepend(box->allow.path, xstrdup(str));
	return box->allow.path ? 0 : MAGIC_ERROR_OOM;
}

static int
_set_allow_sock_bind(const void *val, pink_easy_process_t *current)
{
	int c, f, r = 0;
	const char *str = val;
	char **list;
	sandbox_t *box;
	sock_match_t *match;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	/* Expand alias */
	c = f = sock_match_expand(str, &list) - 1;
	for (; c >= 0; c--) {
		if ((r = sock_match_new(list[c], &match)) < 0) {
			warning("invalid address `%s' (errno:%d %s)",
					list[c], -r, strerror(-r));
			r = MAGIC_ERROR_INVALID_VALUE;
			goto end;
		}

		box->allow.sock.bind = slist_prepend(box->allow.sock.bind, match);
		if (!box->allow.sock.bind) {
			r = MAGIC_ERROR_OOM;
			goto end;
		}
	}

end:
	for (; f >= 0; f--)
		free(list[f]);
	free(list);

	return r;
}

static int
_set_allow_sock_connect(const void *val, pink_easy_process_t *current)
{
	int c, f, r = 0;
	const char *str = val;
	char **list;
	sandbox_t *box;
	sock_match_t *match;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	/* Expand alias */
	c = f = sock_match_expand(str, &list) - 1;
	for (; c >= 0; c--) {
		if ((r = sock_match_new(list[c], &match)) < 0) {
			warning("invalid address `%s' (errno:%d %s)",
					list[c], -r, strerror(-r));
			r = MAGIC_ERROR_INVALID_VALUE;
			goto end;
		}

		box->allow.sock.connect = slist_prepend(box->allow.sock.connect, match);
		if (!box->allow.sock.connect) {
			r = MAGIC_ERROR_OOM;
			goto end;
		}
	}

end:
	for (; f >= 0; --f)
		free(list[f]);
	free(list);

	return r;
}

static int
_set_filter_exec(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config->filter.exec = slist_prepend(pandora->config->filter.exec, xstrdup(str));
	return pandora->config->filter.exec ? 0 : MAGIC_ERROR_OOM;
}

static int
_set_filter_path(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config->filter.path = slist_prepend(pandora->config->filter.path, xstrdup(str));
	return pandora->config->filter.path ? 0 : MAGIC_ERROR_OOM;
}

static int
_set_filter_sock(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config->filter.sock = slist_prepend(pandora->config->filter.sock, xstrdup(str));
	return pandora->config->filter.sock ? 0 : MAGIC_ERROR_OOM;
}

static int
_set_disallow_exec(const void *val, pink_easy_process_t *current)
{
	const char *str = val;
	slist_t *slist;
	sandbox_t *box;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	for (slist = box->allow.exec; slist; slist = slist->next) {
		if (!strcmp(slist->data, str)) {
			box->allow.exec = slist_remove_link(box->allow.exec, slist);
			slist_free(slist, free);
			break;
		}
	}

	return 0;
}

static int
_set_disallow_path(const void *val, pink_easy_process_t *current)
{
	const char *str = val;
	slist_t *slist;
	sandbox_t *box;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	for (slist = box->allow.path; slist; slist = slist->next) {
		if (!strcmp(slist->data, str)) {
			box->allow.path = slist_remove_link(box->allow.path, slist);
			slist_free(slist, free);
			break;
		}
	}

	return 0;
}

static int
_set_disallow_sock_bind(const void *val, pink_easy_process_t *current)
{
	int c, f;
	const char *str = val;
	char **list;
	slist_t *slist;
	sandbox_t *box;
	sock_match_t *m;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	c = f = sock_match_expand(str, &list) - 1;
	for (; c >= 0; c--) {
		for (slist = box->allow.sock.bind; slist; slist = slist->next) {
			m = slist->data;
			if (!strcmp(m->str, list[c])) {
				box->allow.sock.bind = slist_remove_link(box->allow.sock.bind, slist);
				slist_free(slist, free_sock_match);
				break;
			}
		}
	}

	for (; f >= 0; f--)
		free(list[f]);
	free(list);

	return 0;
}

static int
_set_disallow_sock_connect(const void *val, pink_easy_process_t *current)
{
	int c, f;
	const char *str = val;
	char **list;
	slist_t *slist;
	sandbox_t *box;
	sock_match_t *m;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &pandora->config->child;

	c = f = sock_match_expand(str, &list) - 1;
	for (; c >= 0; c--) {
		for (slist = box->allow.sock.connect; slist; slist = slist->next) {
			m = slist->data;
			if (!strcmp(m->str, list[c])) {
				box->allow.sock.connect = slist_remove_link(box->allow.sock.connect, slist);
				slist_free(slist, free_sock_match);
				break;
			}
		}
	}

	for (; f >= 0; f--)
		free(list[f]);
	free(list);

	return 0;
}

static int
_set_rmfilter_exec(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;
	slist_t *slist;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	for (slist = pandora->config->filter.exec; slist; slist = slist->next) {
		if (!strcmp(slist->data, str)) {
			pandora->config->filter.exec = slist_remove_link(pandora->config->filter.exec, slist);
			slist_free(slist, free);
			break;
		}
	}

	return 0;
}

static int
_set_rmfilter_path(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;
	slist_t *slist;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	for (slist = pandora->config->filter.path; slist; slist = slist->next) {
		if (!strcmp(slist->data, str)) {
			pandora->config->filter.path = slist_remove_link(pandora->config->filter.path, slist);
			slist_free(slist, free);
			break;
		}
	}

	return 0;
}

static int
_set_rmfilter_sock(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;
	slist_t *slist;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	for (slist = pandora->config->filter.sock; slist; slist = slist->next) {
		if (!strcmp(slist->data, str)) {
			pandora->config->filter.sock = slist_remove_link(pandora->config->filter.sock, slist);
			slist_free(slist, free);
			break;
		}
	}

	return 0;
}

struct key {
	const char *name;
	const char *lname;
	unsigned parent;
	unsigned type;
	int (*set) (const void *val, pink_easy_process_t *current);
	int (*query) (pink_easy_process_t *current);
};

static const struct key key_table[] = {
	[MAGIC_KEY_NONE] =
		{
			.lname  = "(none)",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_CORE] =
		{
			.name   = "core",
			.lname  = "core",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_LOG] =
		{
			.name   = "log",
			.lname  = "core.log",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_SANDBOX] =
		{
			.name   = "sandbox",
			.lname  = "core.sandbox",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_ALLOW] =
		{
			.name   = "allow",
			.lname  = "core.allow",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_ABORT] =
		{
			.name   = "abort",
			.lname  = "core.abort",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_PANIC] =
		{
			.name   = "panic",
			.lname  = "core.panic",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_VIOLATION] =
		{
			.name   = "violation",
			.lname  = "core.violation",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_CORE_TRACE] =
		{
			.name   = "trace",
			.lname  = "core.trace",
			.parent = MAGIC_KEY_CORE,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_TRACE] =
		{
			.name   = "trace",
			.lname  = "trace",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_ALLOW] =
		{
			.name   = "allow",
			.lname  = "allow",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_ALLOW_SOCK] =
		{
			.name   = "sock",
			.lname  = "allow.sock",
			.parent = MAGIC_KEY_ALLOW,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_DISALLOW] =
		{
			.name   = "disallow",
			.lname  = "disallow",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_DISALLOW_SOCK] =
		{
			.name   = "sock",
			.lname  = "disallow.sock",
			.parent = MAGIC_KEY_DISALLOW,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_FILTER] =
		{
			.name   = "filter",
			.lname  = "filter",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_RMFILTER] =
		{
			.name   = "rmfilter",
			.lname  = "rmfilter",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_CORE_LOG_FD] =
		{
			.name   = "fd",
			.lname  = "core.log.fd",
			.parent = MAGIC_KEY_CORE_LOG,
			.type   = MAGIC_TYPE_INTEGER,
			.set    = _set_log_fd,
		},
	[MAGIC_KEY_CORE_LOG_FILE] =
		{
			.name   = "file",
			.lname  = "core.log.file",
			.parent = MAGIC_KEY_CORE_LOG,
			.type   = MAGIC_TYPE_STRING,
			.set    = _set_log_file,
		},
	[MAGIC_KEY_CORE_LOG_LEVEL] =
		{
			.name   = "level",
			.lname  = "core.log.level",
			.parent = MAGIC_KEY_CORE_LOG,
			.type   = MAGIC_TYPE_INTEGER,
			.set    = _set_log_level,
		},
	[MAGIC_KEY_CORE_LOG_TIMESTAMP] =
		{
			.name   = "timestamp",
			.lname  = "core.log.timestamp",
			.parent = MAGIC_KEY_CORE_LOG,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_log_timestamp,
			.query  = NULL,
		},

	[MAGIC_KEY_CORE_SANDBOX_EXEC] =
		{
			.name   = "exec",
			.lname  = "core.sandbox.exec",
			.parent = MAGIC_KEY_CORE_SANDBOX,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_sandbox_exec,
			.query  = _query_sandbox_exec,
		},
	[MAGIC_KEY_CORE_SANDBOX_PATH] =
		{
			.name   = "path",
			.lname  = "core.sandbox.path",
			.parent = MAGIC_KEY_CORE_SANDBOX,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_sandbox_path,
			.query  = _query_sandbox_path,
		},
	[MAGIC_KEY_CORE_SANDBOX_SOCK] =
		{
			.name   = "sock",
			.lname  = "core.sandbox.sock",
			.parent = MAGIC_KEY_CORE_SANDBOX,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_sandbox_sock,
			.query  = _query_sandbox_sock,
		},

	[MAGIC_KEY_CORE_ALLOW_PER_PROCESS_DIRECTORIES] =
		{
			.name   = "per_process_directories",
			.lname  = "core.allow.per_process_directories",
			.parent = MAGIC_KEY_CORE_ALLOW,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_allow_ppd,
			.query  = NULL,
		},
	[MAGIC_KEY_CORE_ALLOW_SUCCESSFUL_BIND] =
		{
			.name   = "successful_bind",
			.lname  = "core.allow.successful_bind",
			.parent = MAGIC_KEY_CORE_ALLOW,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_allow_sb,
			.query  = NULL,
		},

	[MAGIC_KEY_CORE_ABORT_DECISION] =
		{
			.name   = "decision",
			.lname  = "core.abort.decision",
			.parent = MAGIC_KEY_CORE_ABORT,
			.type   = MAGIC_TYPE_STRING,
			.set    = _set_abort_decision,
		},

	[MAGIC_KEY_CORE_PANIC_DECISION] =
		{
			.name   = "decision",
			.lname  = "core.panic.decision",
			.parent = MAGIC_KEY_CORE_PANIC,
			.type   = MAGIC_TYPE_STRING,
			.set    = _set_panic_decision,
		},
	[MAGIC_KEY_CORE_PANIC_EXIT_CODE] =
		{
			.name   = "exit_code",
			.lname  = "core.panic.exit_code",
			.parent = MAGIC_KEY_CORE_PANIC,
			.type   = MAGIC_TYPE_INTEGER,
			.set    = _set_panic_exit_code,
		},

	[MAGIC_KEY_CORE_VIOLATION_DECISION] =
		{
			.name   = "decision",
			.lname  = "core.violation.decision",
			.parent = MAGIC_KEY_CORE_VIOLATION,
			.type   = MAGIC_TYPE_STRING,
			.set    = _set_violation_decision,
		},
	[MAGIC_KEY_CORE_VIOLATION_EXIT_CODE] =
		{
			.name   = "exit_code",
			.lname  = "core.violation.exit_code",
			.parent = MAGIC_KEY_CORE_VIOLATION,
			.type   = MAGIC_TYPE_INTEGER,
			.set    = _set_violation_exit_code,
		},
	[MAGIC_KEY_CORE_VIOLATION_IGNORE_SAFE] =
		{
			.name   = "ignore_safe",
			.lname  = "core.violation.ignore_safe",
			.parent = MAGIC_KEY_CORE_VIOLATION,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_violation_ignore_safe,
			.query  = NULL,
		},

	[MAGIC_KEY_CORE_TRACE_FOLLOWFORK] =
		{
			.name   = "followfork",
			.lname  = "core.trace.followfork",
			.parent = MAGIC_KEY_CORE_TRACE,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_trace_followfork,
			.query  = _query_trace_followfork
		},
	[MAGIC_KEY_CORE_TRACE_EXIT_WAIT_ALL] =
		{
			.name   = "exit_wait_all",
			.lname  = "core.trace.exit_wait_all",
			.parent = MAGIC_KEY_CORE_TRACE,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_trace_exit_wait_all,
			.query  = _query_trace_exit_wait_all,
		},
	[MAGIC_KEY_CORE_TRACE_MAGIC_LOCK] =
		{
			.name   = "magic_lock",
			.lname  = "core.trace.magic_lock",
			.parent = MAGIC_KEY_CORE_TRACE,
			.type   = MAGIC_TYPE_STRING,
			.set    = _set_trace_magic_lock,
		},

	[MAGIC_KEY_TRACE_KILL_IF_MATCH] =
		{
			.name   = "kill_if_match",
			.lname  = "trace.kill_if_match",
			.parent = MAGIC_KEY_TRACE,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_trace_kill_if_match,
		},
	[MAGIC_KEY_TRACE_RESUME_IF_MATCH] =
		{
			.name   = "resume_if_match",
			.lname  = "trace.resume_if_match",
			.parent = MAGIC_KEY_TRACE,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_trace_resume_if_match,
		},

	[MAGIC_KEY_ALLOW_EXEC] =
		{
			.name   = "exec",
			.lname  = "allow.exec",
			.parent = MAGIC_KEY_ALLOW,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_allow_exec,
		},
	[MAGIC_KEY_ALLOW_PATH] =
		{
			.name   = "path",
			.lname  = "allow.path",
			.parent = MAGIC_KEY_ALLOW,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_allow_path,
		},
	[MAGIC_KEY_ALLOW_SOCK_BIND] =
		{
			.name   = "bind",
			.lname  = "allow.sock.bind",
			.parent = MAGIC_KEY_ALLOW_SOCK,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_allow_sock_bind,
		},
	[MAGIC_KEY_ALLOW_SOCK_CONNECT] =
		{
			.name   = "connect",
			.lname  = "allow.sock.connect",
			.parent = MAGIC_KEY_ALLOW_SOCK,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_allow_sock_connect,
		},

	[MAGIC_KEY_FILTER_EXEC] =
		{
			.name   = "exec",
			.lname  = "filter.exec",
			.parent = MAGIC_KEY_FILTER,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_filter_exec,
		},
	[MAGIC_KEY_FILTER_PATH] =
		{
			.name   = "path",
			.lname  = "filter.path",
			.parent = MAGIC_KEY_FILTER,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_filter_path,
		},
	[MAGIC_KEY_FILTER_SOCK] =
		{
			.name   = "sock",
			.lname  = "filter.sock",
			.parent = MAGIC_KEY_FILTER,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_filter_sock,
		},

	[MAGIC_KEY_DISALLOW_EXEC] =
		{
			.name   = "exec",
			.lname  = "disallow.exec",
			.parent = MAGIC_KEY_DISALLOW,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_disallow_exec,
		},
	[MAGIC_KEY_DISALLOW_PATH] =
		{
			.name   = "path",
			.lname  = "disallow.path",
			.parent = MAGIC_KEY_DISALLOW,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_disallow_path,
		},
	[MAGIC_KEY_DISALLOW_SOCK_BIND] =
		{
			.name   = "bind",
			.lname  = "disallow.sock.bind",
			.parent = MAGIC_KEY_DISALLOW_SOCK,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_disallow_sock_bind,
		},
	[MAGIC_KEY_DISALLOW_SOCK_CONNECT] =
		{
			.name   = "connect",
			.lname  = "disallow.sock.connect",
			.parent = MAGIC_KEY_DISALLOW_SOCK,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_disallow_sock_connect,
		},

	[MAGIC_KEY_RMFILTER_EXEC] =
		{
			.name   = "exec",
			.lname  = "rmfilter.exec",
			.parent = MAGIC_KEY_RMFILTER,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_rmfilter_exec,
		},
	[MAGIC_KEY_RMFILTER_PATH] =
		{
			.name   = "path",
			.lname  = "rmfilter.path",
			.parent = MAGIC_KEY_RMFILTER,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_rmfilter_path,
		},
	[MAGIC_KEY_RMFILTER_SOCK] =
		{
			.name   = "sock",
			.lname  = "rmfilter.sock",
			.parent = MAGIC_KEY_RMFILTER,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_rmfilter_sock,
		},

	[MAGIC_KEY_INVALID] =
		{
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_NONE,
		},
};

const char *
magic_strerror(int error)
{
	switch (error) {
	case MAGIC_ERROR_SUCCESS:
		return "Success";
	case MAGIC_ERROR_INVALID_KEY:
		return "Invalid key";
	case MAGIC_ERROR_INVALID_TYPE:
		return "Invalid type";
	case MAGIC_ERROR_INVALID_VALUE:
		return "Invalid value";
	case MAGIC_ERROR_INVALID_QUERY:
		return "Invalid query";
	case MAGIC_ERROR_OOM:
		return "Out of memory";
	default:
		return "Unknown error";
	}
}

const char *
magic_strkey(unsigned key)
{
	return (key >= MAGIC_KEY_INVALID) ? "invalid" : key_table[key].lname;
}

unsigned
magic_key_parent(unsigned key)
{
	return (key >= MAGIC_KEY_INVALID) ? MAGIC_KEY_INVALID : key_table[key].parent;
}

unsigned
magic_key_type(unsigned key)
{
	return (key >= MAGIC_KEY_INVALID) ? MAGIC_TYPE_NONE : key_table[key].type;
}

unsigned
magic_key_lookup(unsigned key, const char *nkey, ssize_t len)
{
	if (key >= MAGIC_KEY_INVALID)
		return MAGIC_KEY_INVALID;

	for (unsigned i = 1; i < MAGIC_KEY_INVALID; i++) {
		if (key == key_table[i].parent) {
			if (len < 0) {
				if (!strcmp(nkey, key_table[i].name))
					return i;
			}
			else {
				if (!strncmp(nkey, key_table[i].name, len))
					return i;
			}
		}
	}

	return MAGIC_KEY_INVALID;
}

int
magic_cast(pink_easy_process_t *current, unsigned key, unsigned type, const void *val)
{
	struct key entry;

	if (key >= MAGIC_KEY_INVALID)
		return MAGIC_ERROR_INVALID_KEY;

	entry = key_table[key];
	if (entry.type != type)
		return MAGIC_ERROR_INVALID_TYPE;

	return entry.set(val, current);
}

static int
magic_query(pink_easy_process_t *current, unsigned key)
{
	struct key entry;

	if (key >= MAGIC_KEY_INVALID)
		return MAGIC_ERROR_INVALID_KEY;
	entry = key_table[key];

	return entry.query ? entry.query(current) : MAGIC_ERROR_INVALID_QUERY;
}

inline
static int
magic_next_key(const char *magic, unsigned key)
{
	int ret;

	for (ret = MAGIC_KEY_NONE + 1; ret < MAGIC_KEY_INVALID; ret++) {
		struct key k = key_table[ret];

		if (k.parent == key && k.name && startswith(magic, k.name))
			return ret;
	}

	return -1;
}

int
magic_cast_string(pink_easy_process_t *current, const char *magic, int prefix)
{
	int key, ret, val, query;
	const char *cmd;
	struct key entry;

	if (prefix) {
		if (!startswith(magic, PANDORA_MAGIC_PREFIX)) {
			/* No magic */
			return 0;
		}

		cmd = magic + sizeof(PANDORA_MAGIC_PREFIX) - 1;
		if (!*cmd) {
			/* Magic without command */
			return 1;
		}
		else if (*cmd != '/') {
			/* No magic, e.g. /dev/pandoraFOO */
			return 0;
		}
		else
			++cmd; /* Skip the '/' */
	}
	else
		cmd = magic;

	/* Figure out the magic command */
	for (key = MAGIC_KEY_NONE;;) {
		key = magic_next_key(cmd, key);
		if (key < 0) {
			/* Invalid key */
			return MAGIC_ERROR_INVALID_KEY;
		}

		cmd += strlen(key_table[key].name);
		switch (*cmd) {
		case '/':
			if (key_table[key].type != MAGIC_TYPE_OBJECT)
				return MAGIC_ERROR_INVALID_KEY;
			++cmd;
			continue;
		case PANDORA_MAGIC_QUERY_CHAR:
			if (key_table[key].type != MAGIC_TYPE_BOOLEAN)
				return MAGIC_ERROR_INVALID_QUERY;
			query = 1;
			break;
		case PANDORA_MAGIC_SEP_CHAR:
			query = 0;
			break;
		case 0:
		default:
			return MAGIC_ERROR_INVALID_KEY;
		}
		/* Skip the separator */
		++cmd;
		break;
	}

	entry = key_table[key];
	switch (entry.type) {
	case MAGIC_TYPE_BOOLEAN:
		if (query) {
			ret = magic_query(current, key);
			return ret < 0 ? ret : ret == 0 ? 2 : 1;
		}
		if ((ret = safe_atoi(cmd, &val)) < 0)
			return MAGIC_ERROR_INVALID_VALUE;
		if ((ret = magic_cast(current, key, MAGIC_TYPE_BOOLEAN, &val)) < 0)
			return ret;
		break;
	case MAGIC_TYPE_INTEGER:
		if ((ret = safe_atoi(cmd, &val)) < 0)
			return MAGIC_ERROR_INVALID_VALUE;
		if ((ret = magic_cast(current, key, MAGIC_TYPE_INTEGER, &val)) < 0)
			return ret;
		break;
	case MAGIC_TYPE_STRING_ARRAY:
	case MAGIC_TYPE_STRING:
		if ((ret = magic_cast(current, key, entry.type, cmd)) < 0)
			return ret;
		break;
	default:
		break;
	}

	return 1;
}
