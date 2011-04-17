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
#include <string.h>
#include <sys/queue.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "util.h"

static int
_set_log_console_fd(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	int fd = *(const int *)val;

	if (fd <= 0)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config.log_console_fd = fd;

	return 0;
}

static int
_set_log_file(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	const char *str = val;

	if (!str /* || !*str */)
		return MAGIC_ERROR_INVALID_VALUE;

	log_close();

	if (!*str) {
		if (pandora->config.log_file)
			free(pandora->config.log_file);
		pandora->config.log_file = NULL;
		return 0;
	}

	if (pandora->config.log_file)
		free(pandora->config.log_file);
	pandora->config.log_file = xstrdup(str);

	log_init();

	return 0;
}

static int
_set_log_level(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	int level = *(const int *)val;

	if (level < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config.log_level = level;

	return 0;
}

static int
_set_log_timestamp(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	pandora->config.log_timestamp = !!*(const int *)val;

	return 0;
}

static int
_set_sandbox_exec(const void *val, pink_easy_process_t *current)
{
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_userdata(current);
		box = &data->config;
	}
	else
		box = &pandora->config.child;

	box->sandbox_exec = !!*(const int *)val;

	return 0;
}

static int
_query_sandbox_exec(pink_easy_process_t *current)
{
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_userdata(current);
		box = &data->config;
	}
	else
		box = &pandora->config.child;

	return box->sandbox_exec;
}

static int
_set_sandbox_path(const void *val, pink_easy_process_t *current)
{
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_userdata(current);
		box = &data->config;
	}
	else
		box = &pandora->config.child;

	box->sandbox_path = !!*(const int *)val;

	return 0;
}

static int
_query_sandbox_path(pink_easy_process_t *current)
{
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_userdata(current);
		box = &data->config;
	}
	else
		box = &pandora->config.child;

	return box->sandbox_path;
}

static int
_set_sandbox_sock(const void *val, pink_easy_process_t *current)
{
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_userdata(current);
		box = &data->config;
	}
	else
		box = &pandora->config.child;

	box->sandbox_sock = !!*(const int *)val;

	return 0;
}

static int
_query_sandbox_sock(pink_easy_process_t *current)
{
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_userdata(current);
		box = &data->config;
	}
	else
		box = &pandora->config.child;

	return box->sandbox_sock;
}

static int
_set_whitelist_ppd(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	pandora->config.whitelist_per_process_directories = !!*(const int *)val;

	return 0;
}

static int
_set_whitelist_sb(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	pandora->config.whitelist_successful_bind = !!*(const int *)val;

	return 0;
}

static int
_set_abort_decision(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	const char *str = val;

	if (!strcmp(str, "killall"))
		pandora->config.abort_decision = ABORT_KILLALL;
	else if (!strcmp(str, "contall"))
		pandora->config.abort_decision = ABORT_CONTALL;
	else
		return MAGIC_ERROR_INVALID_VALUE;

	return 0;
}

static int
_set_panic_decision(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	const char *str = val;

	if (!strcmp(str, "kill"))
		pandora->config.panic_decision = PANIC_KILL;
	else if (!strcmp(str, "cont"))
		pandora->config.panic_decision = PANIC_CONT;
	else if (!strcmp(str, "contall"))
		pandora->config.panic_decision = PANIC_CONTALL;
	else if (!strcmp(str, "killall"))
		pandora->config.panic_decision = PANIC_KILLALL;
	else
		return MAGIC_ERROR_INVALID_VALUE;

	return 0;
}

static int
_set_panic_exit_code(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	pandora->config.panic_exit_code = *(const int *)val;

	return 0;
}

static int
_set_violation_decision(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	const char *str = val;

	if (!strcmp(str, "deny"))
		pandora->config.violation_decision = VIOLATION_DENY;
	else if (!strcmp(str, "kill"))
		pandora->config.violation_decision = VIOLATION_KILL;
	else if (!strcmp(str, "killall"))
		pandora->config.violation_decision = VIOLATION_KILLALL;
	else if (!strcmp(str, "cont"))
		pandora->config.violation_decision = VIOLATION_CONT;
	else if (!strcmp(str, "contall"))
		pandora->config.violation_decision = VIOLATION_CONTALL;
	else
		return MAGIC_ERROR_INVALID_VALUE;

	return 0;
}

static int
_set_violation_exit_code(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	pandora->config.violation_exit_code = *(const int *)val;

	return 0;
}

static int
_set_violation_raise_fail(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	pandora->config.violation_raise_fail = *(const int *)val ? 1 : 0;

	return 0;
}

static int
_set_violation_raise_safe(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	pandora->config.violation_raise_safe = *(const int *)val ? 1 : 0;

	return 0;
}

static int
_set_trace_follow_fork(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	pandora->config.follow_fork = !!*(const int *)val;

	return 0;
}

static int
_query_trace_follow_fork(PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	return pandora->config.follow_fork;
}

static int
_set_trace_exit_wait_all(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	pandora->config.exit_wait_all = !!*(const int *)val;

	return 0;
}

static int
_query_trace_exit_wait_all(PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	return pandora->config.exit_wait_all;
}

static int
_set_trace_magic_lock(const void *val, pink_easy_process_t *current)
{
	const char *str = val;
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_userdata(current);
		box = &data->config;
	}
	else
		box = &pandora->config.child;

	if (!strcmp(str, "on"))
		box->magic_lock = LOCK_SET;
	else if (!strcmp(str, "off"))
		box->magic_lock = LOCK_UNSET;
	else if (!strcmp(str, "exec"))
		box->magic_lock = LOCK_PENDING;
	else
		return MAGIC_ERROR_INVALID_VALUE;

	return 0;
}

static int
_set_exec_kill_if_match(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	char op;
	const char *str = val;
	struct snode *node;

	if (!str || !*str || !*(str + 1))
		return MAGIC_ERROR_INVALID_VALUE;
	else {
		op = *str;
		++str;
	}

	switch (op) {
	case PANDORA_MAGIC_ADD_CHAR:
		node = xcalloc(1, sizeof(struct snode));
		node->data = xstrdup(str);
		SLIST_INSERT_HEAD(&pandora->config.exec_kill_if_match, node, up);
		return 0;
	case PANDORA_MAGIC_REMOVE_CHAR:
		SLIST_FOREACH(node, &pandora->config.exec_kill_if_match, up) {
			if (!strcmp(node->data, str)) {
				SLIST_REMOVE(&pandora->config.exec_kill_if_match, node, snode, up);
				free(node->data);
				free(node);
				break;
			}
		}
		return 0;
	default:
		return MAGIC_ERROR_INVALID_OPERATION;
	}
}

static int
_set_exec_resume_if_match(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	char op;
	const char *str = val;
	struct snode *node;

	if (!str || !*str || !*(str + 1))
		return MAGIC_ERROR_INVALID_VALUE;
	else {
		op = *str;
		++str;
	}

	switch (op) {
	case PANDORA_MAGIC_ADD_CHAR:
		node = xcalloc(1, sizeof(struct snode));
		node->data = xstrdup(str);
		SLIST_INSERT_HEAD(&pandora->config.exec_resume_if_match, node, up);
		return 0;
	case PANDORA_MAGIC_REMOVE_CHAR:
		SLIST_FOREACH(node, &pandora->config.exec_resume_if_match, up) {
			if (!strcmp(node->data, str)) {
				SLIST_REMOVE(&pandora->config.exec_resume_if_match, node, snode, up);
				free(node->data);
				free(node);
				break;
			}
		}
		return 0;
	default:
		return MAGIC_ERROR_INVALID_OPERATION;
	}
}

static int
_set_whitelist_exec(const void *val, pink_easy_process_t *current)
{
	char op;
	const char *str = val;
	struct snode *node;
	sandbox_t *box;

	if (!str || !*str || !*(str + 1))
		return MAGIC_ERROR_INVALID_VALUE;
	else {
		op = *str;
		++str;
	}

	if (current) {
		proc_data_t *data = pink_easy_process_get_userdata(current);
		box = &data->config;
	}
	else
		box = &pandora->config.child;

	switch (op) {
	case PANDORA_MAGIC_ADD_CHAR:
		node = xcalloc(1, sizeof(struct snode));
		node->data = xstrdup(str);
		SLIST_INSERT_HEAD(&box->whitelist_exec, node, up);
		return 0;
	case PANDORA_MAGIC_REMOVE_CHAR:
		SLIST_FOREACH(node, &box->whitelist_exec, up) {
			if (!strcmp(node->data, str)) {
				SLIST_REMOVE(&box->whitelist_exec, node, snode, up);
				free(node->data);
				free(node);
				break;
			}
		}
		return 0;
	default:
		return MAGIC_ERROR_INVALID_OPERATION;
	}
}

static int
_set_whitelist_path(const void *val, pink_easy_process_t *current)
{
	char op;
	const char *str = val;
	struct snode *node;
	sandbox_t *box;

	if (!str || !*str || !*(str + 1))
		return MAGIC_ERROR_INVALID_VALUE;
	else {
		op = *str;
		++str;
	}

	if (current) {
		proc_data_t *data = pink_easy_process_get_userdata(current);
		box = &data->config;
	}
	else
		box = &pandora->config.child;

	switch (op) {
	case PANDORA_MAGIC_ADD_CHAR:
		node = xcalloc(1, sizeof(struct snode));
		node->data = xstrdup(str);
		SLIST_INSERT_HEAD(&box->whitelist_path, node, up);
		return 0;
	case PANDORA_MAGIC_REMOVE_CHAR:
		SLIST_FOREACH(node, &box->whitelist_path, up) {
			if (!strcmp(node->data, str)) {
				SLIST_REMOVE(&box->whitelist_path, node, snode, up);
				free(node->data);
				free(node);
				break;
			}
		}
		return 0;
	default:
		return MAGIC_ERROR_INVALID_OPERATION;
	}
}

static int
_set_whitelist_sock_bind(const void *val, pink_easy_process_t *current)
{
	char op;
	int c, f, r = 0;
	const char *str = val;
	char **list;
	struct snode *node;
	sandbox_t *box;
	sock_match_t *match;

	if (!str || !*str || !*(str + 1))
		return MAGIC_ERROR_INVALID_VALUE;
	else {
		op = *str;
		++str;
	}

	if (current) {
		proc_data_t *data = pink_easy_process_get_userdata(current);
		box = &data->config;
	}
	else
		box = &pandora->config.child;

	/* Expand alias */
	c = f = sock_match_expand(str, &list) - 1;
	for (; c >= 0; c--) {
		switch (op) {
		case PANDORA_MAGIC_ADD_CHAR:
			if ((r = sock_match_new(list[c], &match)) < 0) {
				warning("invalid address `%s' (errno:%d %s)",
						list[c], -r, strerror(-r));
				r = MAGIC_ERROR_INVALID_VALUE;
				goto end;
			}
			node = xcalloc(1, sizeof(struct snode));
			node->data = match;
			SLIST_INSERT_HEAD(&box->whitelist_sock_bind, node, up);
			break;
		case PANDORA_MAGIC_REMOVE_CHAR:
			SLIST_FOREACH(node, &box->whitelist_sock_bind, up) {
				match = node->data;
				if (!strcmp(match->str, str)) {
					SLIST_REMOVE(&box->whitelist_sock_bind, node, snode, up);
					free_sock_match(match);
					free(node);
					break;
				}
			}
			break;
		default:
			r = MAGIC_ERROR_INVALID_OPERATION;
			break;
		}
	}

end:
	for (; f >= 0; f--)
		free(list[f]);
	free(list);

	return r;
}

static int
_set_whitelist_sock_connect(const void *val, pink_easy_process_t *current)
{
	char op;
	int c, f, r = 0;
	const char *str = val;
	char **list;
	struct snode *node;
	sandbox_t *box;
	sock_match_t *match;

	if (!str || !*str || !*(str + 1))
		return MAGIC_ERROR_INVALID_VALUE;
	else {
		op = *str;
		++str;
	}

	if (current) {
		proc_data_t *data = pink_easy_process_get_userdata(current);
		box = &data->config;
	}
	else
		box = &pandora->config.child;

	/* Expand alias */
	c = f = sock_match_expand(str, &list) - 1;
	for (; c >= 0; c--) {
		switch (op) {
		case PANDORA_MAGIC_ADD_CHAR:
			if ((r = sock_match_new(list[c], &match)) < 0) {
				warning("invalid address `%s' (errno:%d %s)",
						list[c], -r, strerror(-r));
				r = MAGIC_ERROR_INVALID_VALUE;
				goto end;
			}
			node = xcalloc(1, sizeof(struct snode));
			node->data = match;
			SLIST_INSERT_HEAD(&box->whitelist_sock_connect, node, up);
			break;
		case PANDORA_MAGIC_REMOVE_CHAR:
			SLIST_FOREACH(node, &box->whitelist_sock_connect, up) {
				match = node->data;
				if (!strcmp(match->str, str)) {
					SLIST_REMOVE(&box->whitelist_sock_connect, node, snode, up);
					free_sock_match(match);
					free(node);
					break;
				}
			}
			break;
		default:
			r = MAGIC_ERROR_INVALID_OPERATION;
			break;
		}
	}

end:
	for (; f >= 0; f--)
		free(list[f]);
	free(list);

	return r;
}

static int
_set_filter_exec(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	char op;
	const char *str = val;
	struct snode *node;

	if (!str || !*str || !*(str + 1))
		return MAGIC_ERROR_INVALID_VALUE;
	else {
		op = *str;
		++str;
	}

	switch (op) {
	case PANDORA_MAGIC_ADD_CHAR:
		node = xcalloc(1, sizeof(struct snode));
		node->data = xstrdup(str);
		SLIST_INSERT_HEAD(&pandora->config.filter_exec, node, up);
		return 0;
	case PANDORA_MAGIC_REMOVE_CHAR:
		SLIST_FOREACH(node, &pandora->config.filter_exec, up) {
			if (!strcmp(node->data, str)) {
				SLIST_REMOVE(&pandora->config.filter_exec, node, snode, up);
				free(node->data);
				free(node);
				break;
			}
		}
		return 0;
	default:
		return MAGIC_ERROR_INVALID_OPERATION;
	}
}

static int
_set_filter_path(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	char op;
	const char *str = val;
	struct snode *node;

	if (!str || !*str || !*(str + 1))
		return MAGIC_ERROR_INVALID_VALUE;
	else {
		op = *str;
		++str;
	}

	switch (op) {
	case PANDORA_MAGIC_ADD_CHAR:
		node = xcalloc(1, sizeof(struct snode));
		node->data = xstrdup(str);
		SLIST_INSERT_HEAD(&pandora->config.filter_path, node, up);
		return 0;
	case PANDORA_MAGIC_REMOVE_CHAR:
		SLIST_FOREACH(node, &pandora->config.filter_path, up) {
			if (!strcmp(node->data, str)) {
				SLIST_REMOVE(&pandora->config.filter_path, node, snode, up);
				free(node->data);
				free(node);
				break;
			}
		}
		return 0;
	default:
		return MAGIC_ERROR_INVALID_OPERATION;
	}
}

static int
_set_filter_sock(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	char op;
	int c, f, r = 0;
	const char *str = val;
	char **list;
	struct snode *node;
	sock_match_t *match;

	if (!str || !*str || !*(str + 1))
		return MAGIC_ERROR_INVALID_VALUE;
	else {
		op = *str;
		++str;
	}

	/* Expand alias */
	c = f = sock_match_expand(str, &list) - 1;
	for (; c >= 0; c--) {
		switch (op) {
		case PANDORA_MAGIC_ADD_CHAR:
			if ((r = sock_match_new(list[c], &match)) < 0) {
				warning("invalid address `%s' (errno:%d %s)",
						list[c], -r, strerror(-r));
				r = MAGIC_ERROR_INVALID_VALUE;
				goto end;
			}
			node = xcalloc(1, sizeof(struct snode));
			node->data = match;
			SLIST_INSERT_HEAD(&pandora->config.filter_sock, node, up);
			break;
		case PANDORA_MAGIC_REMOVE_CHAR:
			SLIST_FOREACH(node, &pandora->config.filter_sock, up) {
				match = node->data;
				if (!strcmp(match->str, str)) {
					SLIST_REMOVE(&pandora->config.filter_sock, node, snode, up);
					free_sock_match(match);
					free(node);
					break;
				}
			}
			break;
		default:
			r = MAGIC_ERROR_INVALID_OPERATION;
			break;
		}
	}

end:
	for (; f >= 0; f--)
		free(list[f]);
	free(list);

	return r;
}

struct key {
	const char *name;
	const char *lname;
	unsigned parent;
	enum magic_type type;
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
	[MAGIC_KEY_CORE_WHITELIST] =
		{
			.name   = "whitelist",
			.lname  = "core.whitelist",
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

	[MAGIC_KEY_EXEC] =
		{
			.name   = "exec",
			.lname  = "exec",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_FILTER] =
		{
			.name   = "filter",
			.lname  = "filter",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_WHITELIST] =
		{
			.name   = "whitelist",
			.lname  = "whitelist",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_WHITELIST_SOCK] =
		{
			.name   = "sock",
			.lname  = "whitelist.sock",
			.parent = MAGIC_KEY_WHITELIST,
			.type   = MAGIC_TYPE_OBJECT,
		},

	[MAGIC_KEY_CORE_LOG_CONSOLE_FD] =
		{
			.name   = "console_fd",
			.lname  = "core.log.console_fd",
			.parent = MAGIC_KEY_CORE_LOG,
			.type   = MAGIC_TYPE_INTEGER,
			.set    = _set_log_console_fd,
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

	[MAGIC_KEY_CORE_WHITELIST_PER_PROCESS_DIRECTORIES] =
		{
			.name   = "per_process_directories",
			.lname  = "core.whitelist.per_process_directories",
			.parent = MAGIC_KEY_CORE_WHITELIST,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_whitelist_ppd,
			.query  = NULL,
		},
	[MAGIC_KEY_CORE_WHITELIST_SUCCESSFUL_BIND] =
		{
			.name   = "successful_bind",
			.lname  = "core.whitelit.successful_bind",
			.parent = MAGIC_KEY_CORE_WHITELIST,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_whitelist_sb,
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
	[MAGIC_KEY_CORE_VIOLATION_RAISE_FAIL] =
		{
			.name   = "raise_fail",
			.lname  = "core.violation.raise_fail",
			.parent = MAGIC_KEY_CORE_VIOLATION,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_violation_raise_fail,
			.query  = NULL,
		},
	[MAGIC_KEY_CORE_VIOLATION_RAISE_SAFE] =
		{
			.name   = "raise_safe",
			.lname  = "core.violation.raise_safe",
			.parent = MAGIC_KEY_CORE_VIOLATION,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_violation_raise_safe,
			.query  = NULL,
		},

	[MAGIC_KEY_CORE_TRACE_FOLLOW_FORK] =
		{
			.name   = "follow_fork",
			.lname  = "core.trace.follow_fork",
			.parent = MAGIC_KEY_CORE_TRACE,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_trace_follow_fork,
			.query  = _query_trace_follow_fork
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

	[MAGIC_KEY_EXEC_KILL_IF_MATCH] =
		{
			.name   = "kill_if_match",
			.lname  = "exec.kill_if_match",
			.parent = MAGIC_KEY_EXEC,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_exec_kill_if_match,
		},
	[MAGIC_KEY_EXEC_RESUME_IF_MATCH] =
		{
			.name   = "resume_if_match",
			.lname  = "exec.resume_if_match",
			.parent = MAGIC_KEY_EXEC,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_exec_resume_if_match,
		},

	[MAGIC_KEY_WHITELIST_EXEC] =
		{
			.name   = "exec",
			.lname  = "whitelist.exec",
			.parent = MAGIC_KEY_WHITELIST,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_whitelist_exec,
		},
	[MAGIC_KEY_WHITELIST_PATH] =
		{
			.name   = "path",
			.lname  = "whitelist.path",
			.parent = MAGIC_KEY_WHITELIST,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_whitelist_path,
		},
	[MAGIC_KEY_WHITELIST_SOCK_BIND] =
		{
			.name   = "bind",
			.lname  = "whitelist.sock.bind",
			.parent = MAGIC_KEY_WHITELIST_SOCK,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_whitelist_sock_bind,
		},
	[MAGIC_KEY_WHITELIST_SOCK_CONNECT] =
		{
			.name   = "connect",
			.lname  = "whitelist.sock.connect",
			.parent = MAGIC_KEY_WHITELIST_SOCK,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_whitelist_sock_connect,
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

	[MAGIC_KEY_INVALID] =
		{
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_NONE,
		},
};

const char *
magic_strerror(enum magic_error error)
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
	case MAGIC_ERROR_INVALID_OPERATION:
		return "Invalid operation";
	case MAGIC_ERROR_OOM:
		return "Out of memory";
	default:
		return "Unknown error";
	}
}

const char *
magic_strkey(enum magic_key key)
{
	return (key >= MAGIC_KEY_INVALID) ? "invalid" : key_table[key].lname;
}

unsigned
magic_key_parent(enum magic_key key)
{
	return (key >= MAGIC_KEY_INVALID) ? MAGIC_KEY_INVALID : key_table[key].parent;
}

unsigned
magic_key_type(enum magic_key key)
{
	return (key >= MAGIC_KEY_INVALID) ? MAGIC_TYPE_NONE : key_table[key].type;
}

unsigned
magic_key_lookup(enum magic_key key, const char *nkey, ssize_t len)
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
magic_cast(pink_easy_process_t *current, enum magic_key key, enum magic_type type, const void *val)
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
magic_query(pink_easy_process_t *current, enum magic_key key)
{
	struct key entry;

	if (key >= MAGIC_KEY_INVALID)
		return MAGIC_ERROR_INVALID_KEY;
	entry = key_table[key];

	return entry.query ? entry.query(current) : MAGIC_ERROR_INVALID_QUERY;
}

inline
static enum magic_key
magic_next_key(const char *magic, enum magic_key key)
{
	int r;

	for (r = MAGIC_KEY_NONE + 1; r < MAGIC_KEY_INVALID; r++) {
		struct key k = key_table[r];

		if (k.parent == key && k.name && startswith(magic, k.name))
			return r;
	}

	return MAGIC_KEY_INVALID;
}

int
magic_cast_string(pink_easy_process_t *current, const char *magic, int prefix)
{
	bool query = false;
	int ret, val;
	enum magic_key key;
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
		if (key == MAGIC_KEY_INVALID) /* Invalid key */
			return MAGIC_ERROR_INVALID_KEY;

		cmd += strlen(key_table[key].name);
		switch (*cmd) {
		case '/':
			if (key_table[key].type != MAGIC_TYPE_OBJECT)
				return MAGIC_ERROR_INVALID_KEY;
			++cmd;
			continue;
		case PANDORA_MAGIC_ADD_CHAR:
		case PANDORA_MAGIC_REMOVE_CHAR:
			if (key_table[key].type != MAGIC_TYPE_STRING_ARRAY)
				return MAGIC_ERROR_INVALID_OPERATION;
			/* Don't skip the magic separator character for string
			 * arrays so that the magic callback can distinguish
			 * between add and remove operations.
			 */
			break;
		case PANDORA_MAGIC_QUERY_CHAR:
			if (key_table[key].type != MAGIC_TYPE_BOOLEAN)
				return MAGIC_ERROR_INVALID_QUERY;
			query = true;
			/* fall through */
		case PANDORA_MAGIC_SEP_CHAR:
			++cmd;
			break;
		case 0:
		default:
			return MAGIC_ERROR_INVALID_KEY;
		}
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
