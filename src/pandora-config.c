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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "JSON_parser.h"
#include "file.h"
#include "shell.h"

enum {
	KEY_NONE = 0,

	KEY_CORE,
	KEY_CORE_FNMATCH_SLASH_SPECIAL,
	KEY_CORE_FNMATCH_PERIOD_SPECIAL,
	KEY_CORE_FOLLOWFORK,
	KEY_CORE_EXIT_WAIT_ALL,
	KEY_CORE_MAGIC_LOCK,
	KEY_CORE_SANDBOX_PATH,
	KEY_CORE_SANDBOX_EXEC,
	KEY_CORE_SANDBOX_SOCK,
	KEY_CORE_AUTO_ALLOW_PER_PROCESS_DIRS,
	KEY_CORE_AUTO_ALLOW_SUCCESSFUL_BIND,

	KEY_ALLOW,
	KEY_ALLOW_EXEC,
	KEY_ALLOW_PATH,
	KEY_ALLOW_SOCK,
	KEY_ALLOW_SOCK_BIND,
	KEY_ALLOW_SOCK_CONNECT,

	KEY_FILTER,
	KEY_FILTER_EXEC,
	KEY_FILTER_PATH,
	KEY_FILTER_SOCK,
};

typedef struct {
	unsigned inarray:2;
	unsigned depth;
	unsigned key;
} state_t;

static int _core;
static const char *_filename;
static JSON_parser _parser;
/* Keep a reference to the state so we can free() it in config_destroy() */
static state_t *_state;

config_t *config;

static const char *
JSON_strerror(JSON_error error)
{
	switch (error) {
	case JSON_E_NONE:
		return "success";
	case JSON_E_INVALID_CHAR:
		return "invalid char";
	case JSON_E_INVALID_KEYWORD:
		return "invalid keyword";
	case JSON_E_INVALID_ESCAPE_SEQUENCE:
		return "invalid escape sequence";
	case JSON_E_INVALID_UNICODE_SEQUENCE:
		return "invalid unicode sequence";
	case JSON_E_INVALID_NUMBER:
		return "invalid number";
	case JSON_E_NESTING_DEPTH_REACHED:
		return "nesting depth reached";
	case JSON_E_UNBALANCED_COLLECTION:
		return "unbalanced collection";
	case JSON_E_EXPECTED_KEY:
		return "expected key";
	case JSON_E_EXPECTED_COLON:
		return "expected colon";
	case JSON_E_OUT_OF_MEMORY:
		return "out of memory";
	default:
		return "unknown";
	}
}

static const char *
key_str(unsigned key)
{
	switch (key) {
	case KEY_CORE:
		return "core";
	case KEY_CORE_FNMATCH_SLASH_SPECIAL:
		return "core.fnmatch_slash_special";
	case KEY_CORE_FNMATCH_PERIOD_SPECIAL:
		return "core.fnmatch_period_special";
	case KEY_CORE_FOLLOWFORK:
		return "core.followfork";
	case KEY_CORE_EXIT_WAIT_ALL:
		return "core.exit_wait_all";
	case KEY_CORE_MAGIC_LOCK:
		return "core.magic_lock";
	case KEY_CORE_SANDBOX_PATH:
		return "core.sandbox_path";
	case KEY_CORE_SANDBOX_EXEC:
		return "core.sandbox_exec";
	case KEY_CORE_SANDBOX_SOCK:
		return "core.sandbox_sock";
	case KEY_CORE_AUTO_ALLOW_PER_PROCESS_DIRS:
		return "core.auto_allow_per_process_dirs";
	case KEY_CORE_AUTO_ALLOW_SUCCESSFUL_BIND:
		return "core.auto_allow_successful_bind";

	case KEY_ALLOW:
		return "core.allow";
	case KEY_ALLOW_EXEC:
		return "core.allow.exec";
	case KEY_ALLOW_PATH:
		return "core.allow.path";
	case KEY_ALLOW_SOCK:
		return "core.allow.sock";
	case KEY_ALLOW_SOCK_BIND:
		return "core.allow.sock.bind";
	case KEY_ALLOW_SOCK_CONNECT:
		return "core.allow.sock.connect";

	case KEY_FILTER:
		return "core.filter";
	case KEY_FILTER_EXEC:
		return "core.filter.exec";
	case KEY_FILTER_PATH:
		return "core.filter.path";
	case KEY_FILTER_SOCK:
		return "core.filter.sock";

	default:
		return "unknown";
	}
}

static unsigned
key_prev(unsigned key)
{
	switch (key) {
	case KEY_CORE:
	case KEY_ALLOW:
	case KEY_FILTER:
		return KEY_NONE;

	case KEY_CORE_FNMATCH_SLASH_SPECIAL:
	case KEY_CORE_FNMATCH_PERIOD_SPECIAL:
	case KEY_CORE_FOLLOWFORK:
	case KEY_CORE_EXIT_WAIT_ALL:
	case KEY_CORE_MAGIC_LOCK:
	case KEY_CORE_SANDBOX_PATH:
	case KEY_CORE_SANDBOX_EXEC:
	case KEY_CORE_SANDBOX_SOCK:
	case KEY_CORE_AUTO_ALLOW_PER_PROCESS_DIRS:
	case KEY_CORE_AUTO_ALLOW_SUCCESSFUL_BIND:
		return KEY_CORE;

	case KEY_ALLOW_EXEC:
	case KEY_ALLOW_PATH:
	case KEY_ALLOW_SOCK:
		return KEY_ALLOW;

	case KEY_ALLOW_SOCK_BIND:
	case KEY_ALLOW_SOCK_CONNECT:
		return KEY_ALLOW_SOCK;

	case KEY_FILTER_EXEC:
	case KEY_FILTER_PATH:
	case KEY_FILTER_SOCK:
		return KEY_FILTER;

	case KEY_NONE:
	default:
		return KEY_NONE;
	}
}

static int
key_validate(int key, const char *nkey)
{
	switch (key) {
	case KEY_NONE:
		if (!strcmp(nkey, "core")) {
			if (!_core)
				die(2, "key `core' not allowed in `%s'", _filename);
			return KEY_CORE;
		}
		if (!strcmp(nkey, "allow"))
			return KEY_ALLOW;
		if (!strcmp(nkey, "filter"))
			return KEY_FILTER;
		break;
	case KEY_CORE:
		if (!strcmp(nkey, "fnmatch_slash_special"))
			return KEY_CORE_FNMATCH_SLASH_SPECIAL;
		if (!strcmp(nkey, "fnmatch_period_special"))
			return KEY_CORE_FNMATCH_PERIOD_SPECIAL;
		if (!strcmp(nkey, "followfork"))
			return KEY_CORE_FOLLOWFORK;
		if (!strcmp(nkey, "exit_wait_all"))
			return KEY_CORE_EXIT_WAIT_ALL;
		if (!strcmp(nkey, "magic_lock"))
			return KEY_CORE_MAGIC_LOCK;
		if (!strcmp(nkey, "sandbox_exec"))
			return KEY_CORE_SANDBOX_EXEC;
		if (!strcmp(nkey, "sandbox_path"))
			return KEY_CORE_SANDBOX_PATH;
		if (!strcmp(nkey, "sandbox_sock"))
			return KEY_CORE_SANDBOX_SOCK;
		if (!strcmp(nkey, "auto_allow_per_process_dirs"))
			return KEY_CORE_AUTO_ALLOW_PER_PROCESS_DIRS;
		if (!strcmp(nkey, "auto_allow_successful_bind"))
			return KEY_CORE_AUTO_ALLOW_SUCCESSFUL_BIND;
		break;
	case KEY_ALLOW:
		if (!strcmp(nkey, "exec"))
			return KEY_ALLOW_EXEC;
		if (!strcmp(nkey, "path"))
			return KEY_ALLOW_PATH;
		if (!strcmp(nkey, "sock"))
			return KEY_ALLOW_SOCK;
		break;
	case KEY_ALLOW_SOCK:
		if (!strcmp(nkey, "bind"))
			return KEY_ALLOW_SOCK_BIND;
		if (!strcmp(nkey, "connect"))
			return KEY_ALLOW_SOCK_CONNECT;
		break;
	case KEY_FILTER:
		if (!strcmp(nkey, "exec"))
			return KEY_FILTER_EXEC;
		if (!strcmp(nkey, "path"))
			return KEY_FILTER_PATH;
		if (!strcmp(nkey, "sock"))
			return KEY_FILTER_SOCK;
		break;
	default:
		break;
	}

	die(2, "undefined key `%s' for `%s' in `%s'",
			nkey, key_str(key),
			_filename);
}

static int
parser_callback(void *ctx, int type, const JSON_value *value)
{
	int expand, val;
	const char *name;
	char *str;
	slist_t **slist;
	state_t *state;

	state = (state_t *)ctx;

	expand = 0;
	val = 0;
	name = NULL;
	slist = NULL;
	switch (type) {
	case JSON_T_OBJECT_BEGIN:
	case JSON_T_OBJECT_END:
		switch (state->key) {
		case KEY_NONE:
		case KEY_CORE:
		case KEY_ALLOW:
		case KEY_ALLOW_SOCK:
		case KEY_FILTER:
			break;
		default:
			die(2, "unexpected object for %s in `%s'",
					key_str(state->key), _filename);
		}

		if (type == JSON_T_OBJECT_END) {
			--state->depth;
			state->key = key_prev(state->key);
		}
		else
			++state->depth;
		break;
	case JSON_T_ARRAY_BEGIN:
	case JSON_T_ARRAY_END:
		switch (state->key) {
		case KEY_ALLOW_EXEC:
		case KEY_ALLOW_PATH:
		case KEY_ALLOW_SOCK_BIND:
		case KEY_ALLOW_SOCK_CONNECT:
		case KEY_FILTER_EXEC:
		case KEY_FILTER_PATH:
		case KEY_FILTER_SOCK:
			break;
		default:
			die(2, "unexpected array for %s in `%s'",
					key_str(state->key), _filename);
		}

		if (type == JSON_T_ARRAY_BEGIN)
			state->inarray = 1;
		else {
			state->inarray = 0;
			state->key = key_prev(state->key);
		}
		break;
	case JSON_T_KEY:
		state->key = key_validate(state->key, value->vu.str.value);
		break;
	case JSON_T_TRUE:
		val = 1;
		/* fall through */
	case JSON_T_FALSE:
		switch (state->key) {
		case KEY_CORE_FNMATCH_SLASH_SPECIAL:
			config->core.fnmatch_slash_special = val;
			break;
		case KEY_CORE_FNMATCH_PERIOD_SPECIAL:
			config->core.fnmatch_period_special = val;
			break;
		case KEY_CORE_FOLLOWFORK:
			config->core.followfork = val;
			break;
		case KEY_CORE_EXIT_WAIT_ALL:
			config->core.exit_wait_all = val;
			break;
		case KEY_CORE_SANDBOX_EXEC:
			config->child.core.sandbox_exec = val;
			break;
		case KEY_CORE_SANDBOX_PATH:
			config->child.core.sandbox_path = val;
			break;
		case KEY_CORE_SANDBOX_SOCK:
			config->child.core.sandbox_sock = val;
			break;
		case KEY_CORE_AUTO_ALLOW_PER_PROCESS_DIRS:
			config->core.auto_allow_per_process_dirs = val;
			break;
		case KEY_CORE_AUTO_ALLOW_SUCCESSFUL_BIND:
			config->core.auto_allow_successful_bind = val;
			break;
		default:
			die(2, "unexpected boolean for %s in `%s'",
					key_str(state->key), _filename);
		}

		if (!state->inarray)
			state->key = key_prev(state->key);
		break;
	case JSON_T_STRING:
		switch (state->key) {
		case KEY_CORE_MAGIC_LOCK:
			if (!strcmp(value->vu.str.value, "on"))
				config->child.core.magic_lock = LOCK_SET;
			else if (!strcmp(value->vu.str.value, "off"))
				config->child.core.magic_lock = LOCK_UNSET;
			else if (!strcmp(value->vu.str.value, "exec"))
				config->child.core.magic_lock = LOCK_PENDING;
			else
				die(2, "undefined value `%s' for %s in `%s'",
						value->vu.str.value,
						key_str(state->key),
						_filename);
			break;
		case KEY_ALLOW_EXEC:
			expand = 1;
			slist = &config->child.allow.exec;
			break;
		case KEY_ALLOW_PATH:
			expand = 1;
			slist = &config->child.allow.path;
			break;
		case KEY_ALLOW_SOCK_BIND:
			/* FIXME: slist = &config->child.allow.sock.bind; */
			break;
		case KEY_ALLOW_SOCK_CONNECT:
			/* FIXME: slist = &config->child.allow.sock.connect; */
			break;
		case KEY_FILTER_EXEC:
			slist = &config->filter.exec;
			break;
		case KEY_FILTER_PATH:
			slist = &config->filter.path;
			break;
		case KEY_FILTER_SOCK:
			slist = &config->filter.sock;
			break;
		default:
			die(2, "unexpected string for %s in `%s'",
					key_str(state->key), _filename);
		}

		if (state->inarray) {
			if (!slist)
				break;

			if (expand) {
				str = shell_expand(value->vu.str.value, value->vu.str.length);
				if (!str)
					die_errno(2, "shell_expand(%s)", value->vu.str.value);

				/* Warning: shell_expand() may return
				 * empty string! In this case we just
				 * ignore the return value.
				 */
				if (str[0] == '\0') {
					free(str);
					break;
				}
			}
			else
				str = xstrndup(value->vu.str.value, value->vu.str.length);

			*slist = slist_prepend(*slist, str);
			if (!*slist)
				die_errno(-1, "Out of memory");
		}
		else
			state->key = key_prev(state->key);
		break;
	/* Unused types */
	case JSON_T_INTEGER:
		if (!name)
			name = "integer";
		/* fall through */
	case JSON_T_FLOAT:
		if (!name)
			name = "float";
		/* fall through */
	case JSON_T_NULL:
		if (!name)
			name = "null";
		/* fall through */
	case JSON_T_MAX:
	default:
		die(2, "unexpected %s for %s in `%s'",
				name, key_str(state->key),
				_filename);
	}

	return 1;
}

void
config_init(void)
{
	JSON_config jc;

	config = xcalloc(1, sizeof(config_t));
	_state = xcalloc(1, sizeof(state_t));

	/* Set sane defaults for configuration */
	config->core.followfork = 1;
	config->core.exit_wait_all = 1;
	config->core.auto_allow_per_process_dirs = 1;
	config->child.core.magic_lock = LOCK_UNSET;

	init_JSON_config(&jc);
	jc.depth = -1;
	jc.allow_comments = 1;
	jc.handle_floats_manually = 0;
	jc.callback = parser_callback;
	jc.callback_ctx = _state;

	_parser = new_JSON_parser(&jc);
}

void
config_destroy(void)
{
	free(_state);
	delete_JSON_parser(_parser);
}

void
config_reset(void)
{
	JSON_parser_reset(_parser);
}

void
config_parse_file(const char *filename, int core)
{
	int c;
	unsigned count;
	FILE *fp;

	_core = core;
	_filename = filename;

	if ((fp = fopen(filename, "r")) == NULL)
		die_errno(2, "open(`%s')", filename);

	count = 0;
	for (;; ++count) {
		if ((c = fgetc(fp)) == EOF)
			break;
		if (!JSON_parser_char(_parser, c))
			die(2, "JSON_parser_char: byte %u, char:%#x in `%s': %s",
					count, (unsigned)c, filename,
					JSON_strerror(JSON_parser_get_last_error(_parser)));
	}

	if (!JSON_parser_done(_parser))
		die(2, "JSON_parser_done: in `%s': %s",
				filename,
				JSON_strerror(JSON_parser_get_last_error(_parser)));

	fclose(fp);
}

void
config_parse_spec(const char *pathspec, int core)
{
	size_t len;
	char *filename;

	if (pathspec[0] == PANDORA_PROFILE_CHAR) {
		++pathspec;
		len = sizeof(DATADIR) + sizeof(PACKAGE) + strlen(pathspec);
		filename = xcalloc(len, sizeof(char));

		strcpy(filename, DATADIR "/" PACKAGE "/");
		strcat(filename, pathspec);

		config_parse_file(filename, core);
		free(filename);
	}
	else
		config_parse_file(pathspec, core);
}
