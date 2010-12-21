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
_set_fnmatch_slash_special(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	config->core.fnmatch_slash_special = *(const int *)val ? 1 : 0;
	return 0;
}

static int
_set_fnmatch_period_special(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	config->core.fnmatch_period_special = *(const int *)val ? 1 : 0;
	return 0;
}

static int
_set_followfork(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	config->core.followfork = *(const int *)val ? 1 : 0;
	return 0;
}

static int
_set_exit_wait_all(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	config->core.exit_wait_all = *(const int *)val ? 1 : 0;
	return 0;
}

static int
_set_magic_lock(const void *val, pink_easy_process_t *current)
{
	const char *str = val;
	sandbox_t *box;

	if (current) {
		proc_data_t *data = pink_easy_process_get_data(current);
		box = &data->config;
	}
	else
		box = &config->child;

	if (!strcmp(str, "on"))
		box->core.magic_lock = LOCK_SET;
	else if (!strcmp(str, "off"))
		box->core.magic_lock = LOCK_UNSET;
	else if (!strcmp(str, "exec"))
		box->core.magic_lock = LOCK_PENDING;
	else
		return MAGIC_ERROR_INVALID_VALUE;

	return 0;
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
		box = &config->child;

	box->core.sandbox_path = *(const int *)val ? 1 : 0;
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
		box = &config->child;

	box->core.sandbox_exec = *(const int *)val ? 1 : 0;
	return 0;
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
		box = &config->child;

	box->core.sandbox_sock = *(const int *)val ? 1 : 0;
	return 0;
}

static int
_set_auto_allow_ppd(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	config->core.auto_allow_per_process_dirs = *(const int *)val ? 1 : 0;
	return 0;
}

static int
_set_auto_allow_sb(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	config->core.auto_allow_successful_bind = *(const int *)val ? 1 : 0;
	return 0;
}

static int
_set_on_panic(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;

	if (!strcmp(str, "kill"))
		config->core.on_panic = PANIC_KILL;
	else if (!strcmp(str, "cont"))
		config->core.on_panic = PANIC_CONT;
	else if (!strcmp(str, "contall"))
		config->core.on_panic = PANIC_CONTALL;
	else if (!strcmp(str, "killall"))
		config->core.on_panic = PANIC_KILLALL;
	else
		return MAGIC_ERROR_INVALID_VALUE;

	return 0;
}

static int
_set_panic_exit_code(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	config->core.panic_exit_code = *(const int *)val;
	return 0;
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
		box = &config->child;

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
		box = &config->child;

	box->allow.path = slist_prepend(box->allow.path, xstrdup(str));
	return box->allow.path ? 0 : MAGIC_ERROR_OOM;
}

static int
_set_allow_sock_bind(const void *val, pink_easy_process_t *current)
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
		box = &config->child;

	box->allow.sock.bind = slist_prepend(box->allow.sock.bind, xstrdup(str));
	return box->allow.sock.bind ? 0 : MAGIC_ERROR_OOM;
}

static int
_set_allow_sock_connect(const void *val, pink_easy_process_t *current)
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
		box = &config->child;

	box->allow.sock.connect = slist_prepend(box->allow.sock.connect, xstrdup(str));
	return box->allow.sock.connect ? 0 : MAGIC_ERROR_OOM;
}

static int
_set_filter_exec(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	config->filter.exec = slist_prepend(config->filter.exec, xstrdup(str));
	return config->filter.exec ? 0 : MAGIC_ERROR_OOM;
}

static int
_set_filter_path(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	config->filter.path = slist_prepend(config->filter.path, xstrdup(str));
	return config->filter.path ? 0 : MAGIC_ERROR_OOM;
}

static int
_set_filter_sock(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	config->filter.sock = slist_prepend(config->filter.sock, xstrdup(str));
	return config->filter.sock ? 0 : MAGIC_ERROR_OOM;
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
		box = &config->child;

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
		box = &config->child;

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
		box = &config->child;

	for (slist = box->allow.sock.bind; slist; slist = slist->next) {
		if (!strcmp(slist->data, str)) {
			box->allow.sock.bind = slist_remove_link(box->allow.sock.bind, slist);
			slist_free(slist, free);
			break;
		}
	}

	return 0;
}

static int
_set_disallow_sock_connect(const void *val, pink_easy_process_t *current)
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
		box = &config->child;

	for (slist = box->allow.sock.connect; slist; slist = slist->next) {
		if (!strcmp(slist->data, str)) {
			box->allow.sock.connect = slist_remove_link(box->allow.sock.connect, slist);
			slist_free(slist, free);
			break;
		}
	}

	return 0;
}

static int
_set_rmfilter_exec(const void *val, PINK_UNUSED pink_easy_process_t *current)
{
	const char *str = val;
	slist_t *slist;

	if (!str || !*str)
		return MAGIC_ERROR_INVALID_VALUE;

	for (slist = config->filter.exec; slist; slist = slist->next) {
		if (!strcmp(slist->data, str)) {
			config->filter.exec = slist_remove_link(config->filter.exec, slist);
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

	for (slist = config->filter.path; slist; slist = slist->next) {
		if (!strcmp(slist->data, str)) {
			config->filter.path = slist_remove_link(config->filter.path, slist);
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

	for (slist = config->filter.sock; slist; slist = slist->next) {
		if (!strcmp(slist->data, str)) {
			config->filter.sock = slist_remove_link(config->filter.sock, slist);
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
};

static const struct key key_table[] = {
	[MAGIC_KEY_NONE] = {NULL, "(none)",
		MAGIC_KEY_NONE, MAGIC_TYPE_OBJECT, NULL},

	[MAGIC_KEY_CORE] = {"core", "core",
		MAGIC_KEY_NONE, MAGIC_TYPE_OBJECT, NULL},
	[MAGIC_KEY_ALLOW] = {"allow", "allow",
		MAGIC_KEY_NONE, MAGIC_TYPE_OBJECT, NULL},
	[MAGIC_KEY_FILTER] = {"filter", "filter",
		MAGIC_KEY_NONE, MAGIC_TYPE_OBJECT, NULL},
	[MAGIC_KEY_ALLOW_SOCK] = {"sock", "allow.sock",
		MAGIC_KEY_ALLOW, MAGIC_TYPE_OBJECT, NULL},
	[MAGIC_KEY_DISALLOW] = {"disallow", "disallow",
		MAGIC_KEY_NONE, MAGIC_TYPE_OBJECT, NULL},
	[MAGIC_KEY_RMFILTER] = {"rmfilter", "rmfilter",
		MAGIC_KEY_NONE, MAGIC_TYPE_OBJECT, NULL},
	[MAGIC_KEY_DISALLOW_SOCK] = {"sock", "disallow.sock",
		MAGIC_KEY_DISALLOW, MAGIC_TYPE_OBJECT, NULL},

	[MAGIC_KEY_CORE_FNMATCH_SLASH_SPECIAL] = {"fnmatch_slash_special", "core.fnmatch_slash_special",
		MAGIC_KEY_CORE, MAGIC_TYPE_BOOLEAN, _set_fnmatch_slash_special},
	[MAGIC_KEY_CORE_FNMATCH_PERIOD_SPECIAL] = {"fnmatch_period_special", "core.fnmatch_period_special",
		MAGIC_KEY_CORE, MAGIC_TYPE_BOOLEAN, _set_fnmatch_period_special},
	[MAGIC_KEY_CORE_FOLLOWFORK] = {"followfork", "core.followfork",
		MAGIC_KEY_CORE, MAGIC_TYPE_BOOLEAN, _set_followfork},
	[MAGIC_KEY_CORE_EXIT_WAIT_ALL] = {"exit_wait_all", "core.exit_wait_all",
		MAGIC_KEY_CORE, MAGIC_TYPE_BOOLEAN, _set_exit_wait_all},
	[MAGIC_KEY_CORE_MAGIC_LOCK] = {"magic_lock", "core.magic_lock",
		MAGIC_KEY_CORE, MAGIC_TYPE_STRING, _set_magic_lock},
	[MAGIC_KEY_CORE_SANDBOX_PATH] = {"sandbox_path", "core.sandbox_path",
		MAGIC_KEY_CORE, MAGIC_TYPE_BOOLEAN, _set_sandbox_path},
	[MAGIC_KEY_CORE_SANDBOX_EXEC] = {"sandbox_exec", "core.sandbox_exec",
		MAGIC_KEY_CORE, MAGIC_TYPE_BOOLEAN, _set_sandbox_exec},
	[MAGIC_KEY_CORE_SANDBOX_SOCK] = {"sandbox_sock", "core.sandbox_sock",
		MAGIC_KEY_CORE, MAGIC_TYPE_BOOLEAN, _set_sandbox_sock},
	[MAGIC_KEY_CORE_AUTO_ALLOW_PER_PROCESS_DIRS] = {"auto_allow_per_process_dirs", "core.auto_allow_per_process_dirs",
		MAGIC_KEY_CORE, MAGIC_TYPE_BOOLEAN, _set_auto_allow_ppd},
	[MAGIC_KEY_CORE_AUTO_ALLOW_SUCCESSFUL_BIND] = {"auto_allow_successful_bind", "core.auto_allow_successful_bind",
		MAGIC_KEY_CORE, MAGIC_TYPE_BOOLEAN, _set_auto_allow_sb},
	[MAGIC_KEY_CORE_ON_PANIC] = {"on_panic", "core.on_panic",
		MAGIC_KEY_CORE, MAGIC_TYPE_STRING, _set_on_panic},
	[MAGIC_KEY_CORE_PANIC_EXIT_CODE] = {"panic_exit_code", "core.panic_exit_code",
		MAGIC_KEY_CORE, MAGIC_TYPE_INTEGER, _set_panic_exit_code},

	[MAGIC_KEY_ALLOW_EXEC] = {"exec", "allow.exec",
		MAGIC_KEY_ALLOW, MAGIC_TYPE_STRING_ARRAY, _set_allow_exec},
	[MAGIC_KEY_ALLOW_PATH] = {"path", "allow.path",
		MAGIC_KEY_ALLOW, MAGIC_TYPE_STRING_ARRAY, _set_allow_path},
	[MAGIC_KEY_ALLOW_SOCK_BIND] = {"bind", "allow.sock.bind",
		MAGIC_KEY_ALLOW_SOCK, MAGIC_TYPE_STRING_ARRAY, _set_allow_sock_bind},
	[MAGIC_KEY_ALLOW_SOCK_CONNECT] = {"connect", "allow.sock.connect",
		MAGIC_KEY_ALLOW_SOCK, MAGIC_TYPE_STRING_ARRAY, _set_allow_sock_connect},

	[MAGIC_KEY_FILTER_EXEC] = {"exec", "filter.exec",
		MAGIC_KEY_FILTER, MAGIC_TYPE_STRING_ARRAY, _set_filter_exec},
	[MAGIC_KEY_FILTER_PATH] = {"path", "filter.path",
		MAGIC_KEY_FILTER, MAGIC_TYPE_STRING_ARRAY, _set_filter_path},
	[MAGIC_KEY_FILTER_SOCK] = {"sock", "filter.sock",
		MAGIC_KEY_FILTER, MAGIC_TYPE_STRING_ARRAY, _set_filter_sock},

	[MAGIC_KEY_DISALLOW_EXEC] = {"exec", "disallow.exec",
		MAGIC_KEY_DISALLOW, MAGIC_TYPE_STRING_ARRAY, _set_disallow_exec},
	[MAGIC_KEY_DISALLOW_PATH] = {"path", "disallow.path",
		MAGIC_KEY_DISALLOW, MAGIC_TYPE_STRING_ARRAY, _set_disallow_path},
	[MAGIC_KEY_DISALLOW_SOCK_BIND] = {"bind", "disallow.sock.bind",
		MAGIC_KEY_DISALLOW_SOCK, MAGIC_TYPE_STRING_ARRAY, _set_disallow_sock_bind},
	[MAGIC_KEY_DISALLOW_SOCK_CONNECT] = {"connect", "disallow.sock.connect",
		MAGIC_KEY_DISALLOW_SOCK, MAGIC_TYPE_STRING_ARRAY, _set_disallow_sock_connect},

	[MAGIC_KEY_RMFILTER_EXEC] = {"exec", "rmfilter.exec",
		MAGIC_KEY_RMFILTER, MAGIC_TYPE_STRING_ARRAY, _set_rmfilter_exec},
	[MAGIC_KEY_RMFILTER_PATH] = {"path", "rmfilter.path",
		MAGIC_KEY_RMFILTER, MAGIC_TYPE_STRING_ARRAY, _set_rmfilter_path},
	[MAGIC_KEY_RMFILTER_SOCK] = {"sock", "rmfilter.sock",
		MAGIC_KEY_RMFILTER, MAGIC_TYPE_STRING_ARRAY, _set_rmfilter_sock},


	[MAGIC_KEY_INVALID] = {NULL, NULL, MAGIC_KEY_NONE, MAGIC_TYPE_NONE, NULL},
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

	for (unsigned i = 1; i <= MAGIC_KEY_INVALID; i++) {
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
	char c;
	int key, ret, val;
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
			/* No magic, e.g. /dev/sydboxFOO */
			return 0;
		}
		else
			cmd += 1; /* Skip the '/' */
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
		if (!*cmd) {
			/* Invalid key! */
			return MAGIC_ERROR_INVALID_KEY;
		}

		c = key_table[key].type == MAGIC_TYPE_OBJECT ? '/' : PANDORA_MAGIC_SEP_CHAR;
		if (*cmd != c) {
			/* Invalid key! */
			return MAGIC_ERROR_INVALID_KEY;
		}

		/* Skip the separator */
		cmd += 1;
		if (c == PANDORA_MAGIC_SEP_CHAR)
			break;
	}

	entry = key_table[key];
	switch (entry.type) {
	case MAGIC_TYPE_BOOLEAN:
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
	default:
		break;
	}

	return 0;
}
