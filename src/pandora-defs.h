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

#ifndef PANDORA_GUARD_DEFS_H
#define PANDORA_GUARD_DEFS_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "slist.h"

/* Definitions */
#ifndef PANDORA_PROFILE_CHAR
#define PANDORA_PROFILE_CHAR '@'
#endif /* !PANDORA_PROFILE_CHAR */

#ifndef PANDORA_CONFIG_ENV
#define PANDORA_CONFIG_ENV "PANDORA_CONFIG"
#endif /* !PANDORA_CONFIG_ENV */

#ifndef PANDORA_MAGIC_PREFIX
#define PANDORA_MAGIC_PREFIX "/dev/sydbox"
#endif /* !PANDORA_MAGIC_PREFIX */

#ifndef PANDORA_MAGIC_SEP_CHAR
#define PANDORA_MAGIC_SEP_CHAR ':'
#endif /* !PANDORA_MAGIC_SEP_CHAR */

#define TRACE_OPTIONS (\
		PINK_TRACE_OPTION_SYSGOOD |\
		PINK_TRACE_OPTION_EXEC |\
		PINK_TRACE_OPTION_EXIT)

/* Enumerations */
enum {
	LOCK_UNSET = 0,
	LOCK_SET,
	LOCK_PENDING,
};

enum {
	MAGIC_TYPE_NONE = 0,

	MAGIC_TYPE_OBJECT,
	MAGIC_TYPE_BOOLEAN,
	MAGIC_TYPE_STRING,
	MAGIC_TYPE_STRING_ARRAY,

	MAGIC_TYPE_INVALID,
};

enum {
	MAGIC_KEY_NONE = 0,

	MAGIC_KEY_CORE,
	MAGIC_KEY_CORE_FNMATCH_SLASH_SPECIAL,
	MAGIC_KEY_CORE_FNMATCH_PERIOD_SPECIAL,
	MAGIC_KEY_CORE_FOLLOWFORK,
	MAGIC_KEY_CORE_EXIT_WAIT_ALL,
	MAGIC_KEY_CORE_MAGIC_LOCK,
	MAGIC_KEY_CORE_SANDBOX_PATH,
	MAGIC_KEY_CORE_SANDBOX_EXEC,
	MAGIC_KEY_CORE_SANDBOX_SOCK,
	MAGIC_KEY_CORE_AUTO_ALLOW_PER_PROCESS_DIRS,
	MAGIC_KEY_CORE_AUTO_ALLOW_SUCCESSFUL_BIND,

	MAGIC_KEY_ALLOW,
	MAGIC_KEY_ALLOW_EXEC,
	MAGIC_KEY_ALLOW_PATH,
	MAGIC_KEY_ALLOW_SOCK,
	MAGIC_KEY_ALLOW_SOCK_BIND,
	MAGIC_KEY_ALLOW_SOCK_CONNECT,

	MAGIC_KEY_FILTER,
	MAGIC_KEY_FILTER_EXEC,
	MAGIC_KEY_FILTER_PATH,
	MAGIC_KEY_FILTER_SOCK,

	MAGIC_KEY_DISALLOW,
	MAGIC_KEY_DISALLOW_EXEC,
	MAGIC_KEY_DISALLOW_PATH,
	MAGIC_KEY_DISALLOW_SOCK,
	MAGIC_KEY_DISALLOW_SOCK_BIND,
	MAGIC_KEY_DISALLOW_SOCK_CONNECT,

	MAGIC_KEY_RMFILTER,
	MAGIC_KEY_RMFILTER_EXEC,
	MAGIC_KEY_RMFILTER_PATH,
	MAGIC_KEY_RMFILTER_SOCK,

	MAGIC_KEY_INVALID,
};

enum {
	MAGIC_ERROR_SUCCESS = 0,
	MAGIC_ERROR_INVALID_KEY = -1,
	MAGIC_ERROR_INVALID_TYPE = -2,
	MAGIC_ERROR_INVALID_VALUE = -3,
	MAGIC_ERROR_OOM = -4,
};

/* Type declarations */
typedef struct {
	struct {
		unsigned magic_lock:3;
		unsigned sandbox_exec:2;
		unsigned sandbox_path:2;
		unsigned sandbox_sock:2;
	} core;

	struct {
		slist_t *exec;
		slist_t *path;
		struct {
			slist_t *bind;
			slist_t *connect;
		} sock;
	} allow;
} sandbox_t;

typedef struct {
	/* Was the last system call denied? */
	unsigned deny:2;

	/* Should we stop the last system call at exit? */
	unsigned exstop:2;

	/* Current working directory */
	char *cwd;

	/* Last system call */
	unsigned long sno;

	/* Denied system call will return this value */
	long ret;

	/* Per-process configuration */
	sandbox_t config;
} proc_data_t;

typedef struct {
	/* Per-process sandboxing data */
	sandbox_t child;

	/* Non-inherited, "global" configuration data */
	struct {
		unsigned fnmatch_slash_special:2;
		unsigned fnmatch_period_special:2;
		unsigned followfork:2;
		unsigned exit_wait_all:2;
		unsigned auto_allow_per_process_dirs:2;
		unsigned auto_allow_successful_bind:2;
	} core;

	struct {
		slist_t *exec;
		slist_t *path;
		slist_t *sock;
	} filter;
} config_t;

typedef struct {
	/* Exit code */
	int code;

	/* Eldest child */
	pid_t eldest;
} ctx_data_t;

typedef short (*sysfunc_t) (const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name);

typedef struct {
	unsigned stop:3;
	long no;
	const char *name;
	sysfunc_t func;
} sysentry_t;

/* Global variables */
extern int loglevel;
extern const char *progname;
extern config_t *config;

/* Global functions */
PINK_NORETURN
#if !defined(SPARSE) && defined(__GNUC__) && __GNUC__ >= 3
__attribute__ ((format (printf, 2, 3)))
#endif
void die(int code, const char *fmt, ...);
PINK_NORETURN
#if !defined(SPARSE) && defined(__GNUC__) && __GNUC__ >= 3
__attribute__ ((format (printf, 2, 3)))
#endif
void die_errno(int code, const char *fmt, ...);
PINK_MALLOC void *xmalloc(size_t size);
PINK_MALLOC void *xcalloc(size_t nmemb, size_t size);
void *xrealloc(void *ptr, size_t size);
PINK_MALLOC char *xstrdup(const char *src);
PINK_MALLOC char *xstrndup(const char *src, size_t n);

void log_init(const char *filename);
void log_close(void);
void log_prefix(const char *prefix);
void log_nl(int level);
#if !defined(SPARSE) && defined(__GNUC__) && __GNUC__ >= 3
__attribute__ ((format (printf, 2, 0)))
#endif
void log_msg_va(int level, const char *fmt, va_list ap);
#if !defined(SPARSE) && defined(__GNUC__) && __GNUC__ >= 3
__attribute__ ((format (printf, 2, 3)))
#endif
void log_msg(int level, const char *fmt, ...);
#define fatal(...)				\
	do {					\
		log_msg(0, __VA_ARGS__);	\
		log_nl(0);			\
	} while (0)
#define warning(...)				\
	do {					\
		log_msg(1, __VA_ARGS__);	\
		log_nl(1);			\
	} while (0)
#define message(...)				\
	do {					\
		log_msg(2, __VA_ARGS__);	\
		log_nl(2);			\
	} while (0)
#define info(...)				\
	do {					\
		log_msg(3, __VA_ARGS__);	\
		log_nl(3);			\
	} while (0)
#define debug(...)				\
	do {					\
		log_msg(4, __VA_ARGS__);	\
		log_nl(4);			\
	} while (0)

const char *magic_strerror(int error);
const char *magic_strkey(unsigned key);
unsigned magic_key_type(unsigned key);
unsigned magic_key_parent(unsigned key);
unsigned magic_key_lookup(unsigned key, const char *nkey, ssize_t len);
int magic_cast(pink_easy_process_t *current, unsigned key, unsigned type, const void *val);
int magic_cast_string(pink_easy_process_t *current, const char *magic, int prefix);

void config_init(void);
void config_destroy(void);
void config_reset(void);
PINK_NONNULL(1) void config_parse_file(const char *filename, int core);
PINK_NONNULL(1) void config_parse_spec(const char *filename, int core);

pink_easy_callback_table_t *callback_init(void);

int box_resolve_path(const char *path, const char *prefix, pid_t pid, int maycreat, int resolve, char **res);
int box_allow_path(const char *path, const slist_t *patterns);

void systable_free(void);
void systable_add(const char *name, sysfunc_t func);
const sysentry_t *systable_lookup(long no, pink_bitness_t bit);

void sysinit(void);
int sysenter(const pink_easy_context_t *ctx, pink_easy_process_t *current);
int sysexit(const pink_easy_context_t *ctx, pink_easy_process_t *current);

inline
static void
free_proc(void *data)
{
	proc_data_t *p = data;

	if (!p)
		return;

	/* Free current working directory */
	if (p->cwd)
		free(p->cwd);

	/* Free path lists */
	slist_free(p->config.allow.exec, free);
	slist_free(p->config.allow.path, free);

	/* Free the rest */
	free(p);
}

#endif /* !PANDORA_GUARD_DEFS_H */
