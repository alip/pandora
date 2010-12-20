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

static int
parser_callback(void *ctx, int type, const JSON_value *value)
{
	int ret, val;
	const char *name;
	char *str;
	slist_t **slist;
	state_t *state;

	state = (state_t *)ctx;

	name = NULL;
	slist = NULL;
	switch (type) {
	case JSON_T_OBJECT_BEGIN:
	case JSON_T_OBJECT_END:
		if (magic_key_type(state->key) != MAGIC_TYPE_OBJECT)
			die(2, "unexpected object for %s in `%s'",
					magic_strkey(state->key), _filename);

		if (type == JSON_T_OBJECT_END) {
			--state->depth;
			state->key = magic_key_parent(state->key);
		}
		else
			++state->depth;
		break;
	case JSON_T_ARRAY_BEGIN:
	case JSON_T_ARRAY_END:
		if (magic_key_type(state->key) != MAGIC_TYPE_STRING_ARRAY)
			die(2, "unexpected array for %s in `%s'",
					magic_strkey(state->key), _filename);

		if (type == JSON_T_ARRAY_BEGIN)
			state->inarray = 1;
		else {
			state->inarray = 0;
			state->key = magic_key_parent(state->key);
		}
		break;
	case JSON_T_KEY:
		state->key = magic_key_lookup(state->key, value->vu.str.value, value->vu.str.length);
		break;
	case JSON_T_TRUE:
	case JSON_T_FALSE:
		val = (type == JSON_T_TRUE);
		if ((ret = magic_cast(NULL, state->key, MAGIC_TYPE_BOOLEAN, &val) < 0))
			die(2, "error parsing %s in `%s': %s",
					magic_strkey(state->key),
					_filename,
					magic_strerror(ret));
		if (!state->inarray)
			state->key = magic_key_parent(state->key);
		break;
	case JSON_T_STRING:
		str = xstrndup(value->vu.str.value, value->vu.str.length);
		if ((ret = magic_cast(NULL, state->key,
						state->inarray ? MAGIC_TYPE_STRING_ARRAY : MAGIC_TYPE_STRING,
						str)) < 0)
			die(2, "error parsing %s in `%s': %s",
					magic_strkey(state->key),
					_filename,
					magic_strerror(ret));
		free(str);
		if (!state->inarray)
			state->key = magic_key_parent(state->key);
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
				name, magic_strkey(state->key),
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
