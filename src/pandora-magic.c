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

#include "macro.h"
#include "util.h"

static sandbox_t *box_current(pink_easy_process_t *current)
{
	proc_data_t *data;

	if (current) {
		data = pink_easy_process_get_userdata(current);
		return &data->config;
	}

	return &pandora->config.child;
}

static slist_t *_box_whitelist_exec(pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return &box->whitelist_exec;
}

static slist_t *_box_whitelist_read(pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return &box->whitelist_read;
}

static slist_t *_box_whitelist_write(pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return &box->whitelist_write;
}

static slist_t *_box_blacklist_exec(pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return &box->blacklist_exec;
}

static slist_t *_box_blacklist_read(pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return &box->blacklist_read;
}

static slist_t *_box_blacklist_write(pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return &box->blacklist_write;
}

static slist_t *_box_whitelist_sock_bind(pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return &box->whitelist_sock_bind;
}

static slist_t *_box_whitelist_sock_connect(pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return &box->whitelist_sock_connect;
}

static slist_t *_box_blacklist_sock_bind(pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return &box->blacklist_sock_bind;
}

static slist_t *_box_blacklist_sock_connect(pink_easy_process_t *current)
{
	sandbox_t *box = box_current(current);
	return &box->blacklist_sock_connect;
}

static inline slist_t *_box_filter_exec(PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	return &pandora->config.filter_exec;
}

static inline slist_t *_box_filter_read(PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	return &pandora->config.filter_read;
}

static inline slist_t *_box_filter_write(PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	return &pandora->config.filter_write;
}

static inline slist_t *_box_filter_sock(PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	return &pandora->config.filter_sock;
}

#define DEFINE_GLOBAL_UINT_SETTING_FUNC(name, setting)							\
	static int _set_##name(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current) {	\
		int dummy = PTR_TO_INT(val);								\
		if (dummy < 0)										\
			return MAGIC_ERROR_INVALID_VALUE;						\
		setting = dummy;									\
		return 0;										\
	}

#define DEFINE_GLOBAL_INT_SETTING_FUNC(name, setting)							\
	static int _set_##name(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current) {	\
		setting = PTR_TO_INT(val);								\
		return 0;										\
	}

#define DEFINE_GLOBAL_BOOL_SETTING_FUNC(name, setting)							\
	static int _set_##name(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current) {	\
		setting = PTR_TO_BOOL(val);								\
		return 0;										\
	}												\
	static int _query_##name(PINK_GCC_ATTR((unused)) pink_easy_process_t *current) {		\
		return setting;										\
	}

#define DEFINE_SANDBOX_SETTING_FUNC(name)						\
	static int _set_##name(const void *val, pink_easy_process_t *current) {		\
		int m;									\
		const char *str = val;							\
		sandbox_t *box = box_current(current);					\
											\
		if ((m = sandbox_mode_from_string(str)) < 0)				\
			return MAGIC_ERROR_INVALID_VALUE;				\
		box->name = (enum sandbox_mode)m;					\
		return 0;								\
	}

#define DEFINE_GLOBAL_IF_MATCH_SETTING_FUNC(name, head, field)						\
	static int _set_##name(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)	\
	{												\
		char op;										\
		const char *str = val;									\
		struct snode *node;									\
													\
		if (!str || !*str || !*(str + 1))							\
			return MAGIC_ERROR_INVALID_VALUE;						\
		else {											\
			op = *str;									\
			++str;										\
		}											\
													\
		switch (op) {										\
		case PANDORA_MAGIC_ADD_CHAR:								\
			node = xcalloc(1, sizeof(struct snode));					\
			node->data = xstrdup(str);							\
			SLIST_INSERT_HEAD(head, node, field);						\
			return 0;									\
		case PANDORA_MAGIC_REMOVE_CHAR:								\
			SLIST_FOREACH(node, head, field) {						\
				if (streq(node->data, str)) {						\
					SLIST_REMOVE(head, node, snode, field);				\
					free(node->data);						\
					free(node);							\
					break;								\
				}									\
			}										\
			return 0;									\
		default:										\
			return MAGIC_ERROR_INVALID_OPERATION;						\
		}											\
	}

#define DEFINE_STRING_LIST_SETTING_FUNC(name, field)					\
	static int _set_##name(const void *val, pink_easy_process_t *current)		\
	{										\
		char op;								\
		const char *str = val;							\
		struct snode *node;							\
		slist_t *head;								\
		if (!str || !*str || !*(str + 1))					\
			return MAGIC_ERROR_INVALID_VALUE;				\
		else {									\
			op = *str;							\
			++str;								\
		}									\
											\
		head = _box_##name(current);						\
											\
		switch (op) {								\
		case PANDORA_MAGIC_ADD_CHAR:						\
			node = xcalloc(1, sizeof(struct snode));			\
			node->data = xstrdup(str);					\
			SLIST_INSERT_HEAD(head, node, field);				\
			return 0;							\
		case PANDORA_MAGIC_REMOVE_CHAR:						\
			SLIST_FOREACH(node, head, field) {				\
				if (streq(node->data, str)) {				\
					SLIST_REMOVE(head, node, snode, field);		\
					free(node->data);				\
					free(node);					\
					break;						\
				}							\
			}								\
			return 0;							\
		default:								\
			return MAGIC_ERROR_INVALID_OPERATION;				\
		}									\
	}

#define DEFINE_SOCK_LIST_SETTING_FUNC(name, field)					\
	static int _set_##name(const void *val, pink_easy_process_t *current)			\
	{											\
		char op;									\
		int c, f, r = 0;								\
		const char *str = val;								\
		char **list;									\
		struct snode *node;								\
		slist_t *head;									\
		sock_match_t *match;								\
												\
		if (!str || !*str || !*(str + 1))						\
			return MAGIC_ERROR_INVALID_VALUE;					\
		else {										\
			op = *str;								\
			++str;									\
		}										\
												\
		head = _box_##name(current);							\
												\
		/* Expand alias */								\
		c = f = sock_match_expand(str, &list) - 1;					\
		for (; c >= 0; c--) {								\
			switch (op) {								\
			case PANDORA_MAGIC_ADD_CHAR:						\
				if ((r = sock_match_new(list[c], &match)) < 0) {		\
					warning("invalid address `%s' (errno:%d %s)",		\
							list[c], -r, strerror(-r));		\
					r = MAGIC_ERROR_INVALID_VALUE;				\
					goto end;						\
				}								\
				node = xcalloc(1, sizeof(struct snode));			\
				node->data = match;						\
				SLIST_INSERT_HEAD(head, node, field);				\
				break;								\
			case PANDORA_MAGIC_REMOVE_CHAR:						\
				SLIST_FOREACH(node, head, field) {				\
					match = node->data;					\
					if (streq(match->str, str)) {				\
						SLIST_REMOVE(head, node, snode, field);		\
						free_sock_match(match);				\
						free(node);					\
						break;						\
					}							\
				}								\
				break;								\
			default:								\
				r = MAGIC_ERROR_INVALID_OPERATION;				\
				break;								\
			}									\
		}										\
												\
	end:											\
		for (; f >= 0; f--)								\
			free(list[f]);								\
		free(list);									\
												\
		return r;									\
	}

DEFINE_GLOBAL_UINT_SETTING_FUNC(log_console_fd, pandora->config.log_console_fd)
DEFINE_GLOBAL_UINT_SETTING_FUNC(log_level, pandora->config.log_level)
DEFINE_GLOBAL_BOOL_SETTING_FUNC(log_timestamp, pandora->config.log_timestamp)
DEFINE_GLOBAL_INT_SETTING_FUNC(panic_exit_code, pandora->config.panic_exit_code)
DEFINE_GLOBAL_INT_SETTING_FUNC(violation_exit_code, pandora->config.violation_exit_code)
DEFINE_GLOBAL_BOOL_SETTING_FUNC(violation_raise_fail, pandora->config.violation_raise_fail)
DEFINE_GLOBAL_BOOL_SETTING_FUNC(violation_raise_safe, pandora->config.violation_raise_safe)
DEFINE_GLOBAL_BOOL_SETTING_FUNC(trace_follow_fork, pandora->config.follow_fork)
DEFINE_GLOBAL_BOOL_SETTING_FUNC(trace_exit_wait_all, pandora->config.exit_wait_all)
DEFINE_SANDBOX_SETTING_FUNC(sandbox_exec)
DEFINE_SANDBOX_SETTING_FUNC(sandbox_read)
DEFINE_SANDBOX_SETTING_FUNC(sandbox_write)
DEFINE_SANDBOX_SETTING_FUNC(sandbox_sock)
DEFINE_GLOBAL_BOOL_SETTING_FUNC(whitelist_ppd, pandora->config.whitelist_per_process_directories)
DEFINE_GLOBAL_BOOL_SETTING_FUNC(whitelist_sb, pandora->config.whitelist_successful_bind)
DEFINE_GLOBAL_BOOL_SETTING_FUNC(whitelist_usf, pandora->config.whitelist_unsupported_socket_families)
DEFINE_GLOBAL_IF_MATCH_SETTING_FUNC(exec_kill_if_match, &pandora->config.exec_kill_if_match, up)
DEFINE_GLOBAL_IF_MATCH_SETTING_FUNC(exec_resume_if_match, &pandora->config.exec_resume_if_match, up)
DEFINE_STRING_LIST_SETTING_FUNC(whitelist_exec, up)
DEFINE_STRING_LIST_SETTING_FUNC(whitelist_read, up)
DEFINE_STRING_LIST_SETTING_FUNC(whitelist_write, up)
DEFINE_STRING_LIST_SETTING_FUNC(blacklist_exec, up)
DEFINE_STRING_LIST_SETTING_FUNC(blacklist_read, up)
DEFINE_STRING_LIST_SETTING_FUNC(blacklist_write, up)
DEFINE_SOCK_LIST_SETTING_FUNC(whitelist_sock_bind, up)
DEFINE_SOCK_LIST_SETTING_FUNC(whitelist_sock_connect, up)
DEFINE_SOCK_LIST_SETTING_FUNC(blacklist_sock_bind, up)
DEFINE_SOCK_LIST_SETTING_FUNC(blacklist_sock_connect, up)
DEFINE_STRING_LIST_SETTING_FUNC(filter_exec, up)
DEFINE_STRING_LIST_SETTING_FUNC(filter_read, up)
DEFINE_STRING_LIST_SETTING_FUNC(filter_write, up)
DEFINE_SOCK_LIST_SETTING_FUNC(filter_sock, up)

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
_set_abort_decision(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	int d;
	const char *str = val;

	if ((d = abort_decision_from_string(str)) < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config.abort_decision = (enum abort_decision)d;
	return 0;
}

static int
_set_panic_decision(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	int d;
	const char *str = val;

	if ((d = panic_decision_from_string(str)) < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config.panic_decision = (enum panic_decision)d;
	return 0;
}

static int
_set_violation_decision(const void *val, PINK_GCC_ATTR((unused)) pink_easy_process_t *current)
{
	int d;
	const char *str = val;

	if ((d = violation_decision_from_string(str)) < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	pandora->config.violation_decision = (enum violation_decision)d;
	return 0;
}

static int
_set_trace_magic_lock(const void *val, pink_easy_process_t *current)
{
	int l;
	const char *str = val;
	sandbox_t *box = box_current(current);

	if ((l = lock_state_from_string(str)) < 0)
		return MAGIC_ERROR_INVALID_VALUE;

	box->magic_lock = (enum lock_state)l;
	return 0;
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

	[MAGIC_KEY_BLACKLIST] =
		{
			.name   = "blacklist",
			.lname  = "blacklist",
			.parent = MAGIC_KEY_NONE,
			.type   = MAGIC_TYPE_OBJECT,
		},
	[MAGIC_KEY_BLACKLIST_SOCK] =
		{
			.name   = "sock",
			.lname  = "blacklist.sock",
			.parent = MAGIC_KEY_BLACKLIST,
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
			.query  = _query_log_timestamp,
		},

	[MAGIC_KEY_CORE_SANDBOX_EXEC] =
		{
			.name   = "exec",
			.lname  = "core.sandbox.exec",
			.parent = MAGIC_KEY_CORE_SANDBOX,
			.type   = MAGIC_TYPE_STRING,
			.set    = _set_sandbox_exec,
		},
	[MAGIC_KEY_CORE_SANDBOX_READ] =
		{
			.name   = "read",
			.lname  = "core.sandbox.read",
			.parent = MAGIC_KEY_CORE_SANDBOX,
			.type   = MAGIC_TYPE_STRING,
			.set    = _set_sandbox_read,
		},
	[MAGIC_KEY_CORE_SANDBOX_WRITE] =
		{
			.name   = "write",
			.lname  = "core.sandbox.write",
			.parent = MAGIC_KEY_CORE_SANDBOX,
			.type   = MAGIC_TYPE_STRING,
			.set    = _set_sandbox_write,
		},
	[MAGIC_KEY_CORE_SANDBOX_SOCK] =
		{
			.name   = "sock",
			.lname  = "core.sandbox.sock",
			.parent = MAGIC_KEY_CORE_SANDBOX,
			.type   = MAGIC_TYPE_STRING,
			.set    = _set_sandbox_sock,
		},

	[MAGIC_KEY_CORE_WHITELIST_PER_PROCESS_DIRECTORIES] =
		{
			.name   = "per_process_directories",
			.lname  = "core.whitelist.per_process_directories",
			.parent = MAGIC_KEY_CORE_WHITELIST,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_whitelist_ppd,
			.query  = _query_whitelist_ppd,
		},
	[MAGIC_KEY_CORE_WHITELIST_SUCCESSFUL_BIND] =
		{
			.name   = "successful_bind",
			.lname  = "core.whitelist.successful_bind",
			.parent = MAGIC_KEY_CORE_WHITELIST,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_whitelist_sb,
			.query  = _query_whitelist_sb,
		},
	[MAGIC_KEY_CORE_WHITELIST_UNSUPPORTED_SOCKET_FAMILIES] =
		{
			.name   = "unsupported_socket_families",
			.lname  = "core.whitelist.unsupported_socket_families",
			.parent = MAGIC_KEY_CORE_WHITELIST,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_whitelist_usf,
			.query  = _query_whitelist_usf,
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
			.query  = _query_violation_raise_fail,
		},
	[MAGIC_KEY_CORE_VIOLATION_RAISE_SAFE] =
		{
			.name   = "raise_safe",
			.lname  = "core.violation.raise_safe",
			.parent = MAGIC_KEY_CORE_VIOLATION,
			.type   = MAGIC_TYPE_BOOLEAN,
			.set    = _set_violation_raise_safe,
			.query  = _query_violation_raise_safe,
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
	[MAGIC_KEY_WHITELIST_READ] =
		{
			.name   = "read",
			.lname  = "whitelist.read",
			.parent = MAGIC_KEY_WHITELIST,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_whitelist_read,
		},
	[MAGIC_KEY_WHITELIST_WRITE] =
		{
			.name   = "write",
			.lname  = "whitelist.write",
			.parent = MAGIC_KEY_WHITELIST,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_whitelist_write,
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

	[MAGIC_KEY_BLACKLIST_EXEC] =
		{
			.name   = "exec",
			.lname  = "blacklist.exec",
			.parent = MAGIC_KEY_BLACKLIST,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_blacklist_exec,
		},
	[MAGIC_KEY_BLACKLIST_READ] =
		{
			.name   = "read",
			.lname  = "blacklist.read",
			.parent = MAGIC_KEY_BLACKLIST,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_blacklist_read,
		},
	[MAGIC_KEY_BLACKLIST_WRITE] =
		{
			.name   = "write",
			.lname  = "blacklist.write",
			.parent = MAGIC_KEY_BLACKLIST,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_blacklist_write,
		},
	[MAGIC_KEY_BLACKLIST_SOCK_BIND] =
		{
			.name   = "bind",
			.lname  = "blacklist.sock.bind",
			.parent = MAGIC_KEY_BLACKLIST_SOCK,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_blacklist_sock_bind,
		},
	[MAGIC_KEY_BLACKLIST_SOCK_CONNECT] =
		{
			.name   = "connect",
			.lname  = "blacklist.sock.connect",
			.parent = MAGIC_KEY_BLACKLIST_SOCK,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_blacklist_sock_connect,
		},

	[MAGIC_KEY_FILTER_EXEC] =
		{
			.name   = "exec",
			.lname  = "filter.exec",
			.parent = MAGIC_KEY_FILTER,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_filter_exec,
		},
	[MAGIC_KEY_FILTER_READ] =
		{
			.name   = "read",
			.lname  = "filter.read",
			.parent = MAGIC_KEY_FILTER,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_filter_read,
		},
	[MAGIC_KEY_FILTER_WRITE] =
		{
			.name   = "write",
			.lname  = "filter.write",
			.parent = MAGIC_KEY_FILTER,
			.type   = MAGIC_TYPE_STRING_ARRAY,
			.set    = _set_filter_write,
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
	case MAGIC_ERROR_NOPERM:
		return "No permission";
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
				if (streq(nkey, key_table[i].name))
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

	if (!pandora->config.core) {
		enum magic_key k = entry.parent;
		do {
			if (k == MAGIC_KEY_CORE)
				return MAGIC_ERROR_NOPERM;
			k = key_table[k].parent;
		} while (k != MAGIC_KEY_NONE);
	}

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
	bool query = false, bval;
	int ret, ival;
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
		if ((ret = parse_boolean(cmd, &bval)) < 0)
			return MAGIC_ERROR_INVALID_VALUE;
		if ((ret = magic_cast(current, key, MAGIC_TYPE_BOOLEAN, BOOL_TO_PTR(bval))) < 0)
			return ret;
		break;
	case MAGIC_TYPE_INTEGER:
		if ((ret = safe_atoi(cmd, &ival)) < 0)
			return MAGIC_ERROR_INVALID_VALUE;
		if ((ret = magic_cast(current, key, MAGIC_TYPE_INTEGER, INT_TO_PTR(ival))) < 0)
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
