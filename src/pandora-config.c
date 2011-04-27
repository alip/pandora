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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "JSON_parser.h"
#include "file.h"
#include "macro.h"

struct config_state {
	unsigned core:2;
	unsigned inarray:2;
	unsigned depth;
	unsigned key;
	const char *filename;
};

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
	int ret;
	const char *name;
	char *str;
	slist_t **slist;
	config_state_t *state = ctx;

	name = NULL;
	slist = NULL;
	switch (type) {
	case JSON_T_OBJECT_BEGIN:
	case JSON_T_OBJECT_END:
		if (magic_key_type(state->key) != MAGIC_TYPE_OBJECT)
			die(2, "unexpected object for %s in `%s'",
					magic_strkey(state->key), pandora->config.state->filename);

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
					magic_strkey(state->key), pandora->config.state->filename);

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
		if ((ret = magic_cast(NULL, state->key, MAGIC_TYPE_BOOLEAN,
						UINT_TO_PTR(type == JSON_T_TRUE)) < 0))
			die(2, "error parsing %s in `%s': %s",
					magic_strkey(state->key),
					pandora->config.state->filename,
					magic_strerror(ret));
		if (!state->inarray)
			state->key = magic_key_parent(state->key);
		break;
	case JSON_T_STRING:
		if (state->inarray) {
			/* Slight hack, magic_cast expects operation character
			 * in front of the string to distinguish between add
			 * and remove.
			 */
			str = malloc(sizeof(char) * (value->vu.str.length + 1));
			sprintf(str, "%c%s", PANDORA_MAGIC_ADD_CHAR, value->vu.str.value);
		}
		else
			str = xstrndup(value->vu.str.value, value->vu.str.length);

		if ((ret = magic_cast(NULL, state->key,
						state->inarray ? MAGIC_TYPE_STRING_ARRAY : MAGIC_TYPE_STRING,
						str)) < 0)
			die(2, "error parsing %s in `%s': %s",
					magic_strkey(state->key),
					pandora->config.state->filename,
					magic_strerror(ret));
		free(str);
		if (!state->inarray)
			state->key = magic_key_parent(state->key);
		break;
	case JSON_T_INTEGER:
		if ((ret = magic_cast(NULL, state->key, MAGIC_TYPE_INTEGER, INT_TO_PTR(value->vu.integer_value))) < 0)
			die(2, "error parsing %s in `%s': %s",
					magic_strkey(state->key),
					pandora->config.state->filename,
					magic_strerror(ret));
		if (!state->inarray)
			state->key = magic_key_parent(state->key);
		break;
	/* Unused types */
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
				pandora->config.state->filename);
	}

	return 1;
}

void
config_init(void)
{
	JSON_config jc;

	assert(pandora);

	memset(&pandora->config, 0, sizeof(config_t));
	pandora->config.state = xcalloc(1, sizeof(config_state_t));

	/* Set sane defaults for configuration */
	pandora->config.log_console_fd = STDERR_FILENO;
	pandora->config.log_level = 2;
	pandora->config.log_timestamp = true;
	pandora->config.follow_fork = 1;
	pandora->config.exit_wait_all = 1;
	pandora->config.whitelist_per_process_directories = true;
	pandora->config.abort_decision = ABORT_CONTALL;
	pandora->config.panic_decision = PANIC_KILL;
	pandora->config.panic_exit_code = -1;
	pandora->config.violation_decision = VIOLATION_DENY;
	pandora->config.violation_exit_code = -1;
	pandora->config.child.magic_lock = LOCK_UNSET;

	init_JSON_config(&jc);
	jc.depth = -1;
	jc.allow_comments = 1;
	jc.handle_floats_manually = 0;
	jc.callback = parser_callback;
	jc.callback_ctx = pandora->config.state;

	pandora->config.parser = new_JSON_parser(&jc);
}

void
config_destroy(void)
{
	if (pandora->config.log_file) {
		free(pandora->config.log_file);
		pandora->config.log_file = NULL;
	}
	if (pandora->config.state) {
		free(pandora->config.state);
		pandora->config.state = NULL;
	}
	if (pandora->config.parser) {
		delete_JSON_parser(pandora->config.parser);
		pandora->config.parser = NULL;
	}
}

void
config_reset(void)
{
	JSON_parser_reset(pandora->config.parser);
	memset(pandora->config.state, 0, sizeof(config_state_t));
}

void
config_parse_file(const char *filename, int core)
{
	bool debug;
	int c;
	unsigned count;
	FILE *fp;

	pandora->config.state->core = core != 0;
	pandora->config.state->filename = filename;

	if ((fp = fopen(filename, "r")) == NULL)
		die_errno(2, "open(`%s')", filename);

	debug = !!getenv(PANDORA_JSON_DEBUG_ENV);
	count = 0;
	for (;; ++count) {
		if ((c = fgetc(fp)) == EOF)
			break;
		if (debug) {
			fputc(c, stderr);
			fflush(stderr);
		}
		if (!JSON_parser_char(pandora->config.parser, c))
			die(2, "JSON_parser_char: byte %u, char:%#x in `%s': %s",
					count, (unsigned)c, filename,
					JSON_strerror(JSON_parser_get_last_error(pandora->config.parser)));
	}

	if (!JSON_parser_done(pandora->config.parser))
		die(2, "JSON_parser_done: in `%s': %s",
				filename,
				JSON_strerror(JSON_parser_get_last_error(pandora->config.parser)));

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
