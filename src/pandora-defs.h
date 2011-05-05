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

#ifndef PANDORA_GUARD_DEFS_H
#define PANDORA_GUARD_DEFS_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#ifndef _ATFILE_SOURCE
#define _ATFILE_SOURCE 1
#endif /* !_ATFILE_SOURCE */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif /* !_GNU_SOURCE */

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/queue.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <sys/un.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "JSON_parser.h"
#include "hashtable.h"
#include "slist.h"
#include "util.h"

/* Definitions */
#ifndef PANDORA_PROFILE_CHAR
#define PANDORA_PROFILE_CHAR '@'
#endif /* !PANDORA_PROFILE_CHAR */

#ifndef PANDORA_CONFIG_ENV
#define PANDORA_CONFIG_ENV "PANDORA_CONFIG"
#endif /* !PANDORA_CONFIG_ENV */

#ifndef PANDORA_JSON_DEBUG_ENV
#define PANDORA_JSON_DEBUG_ENV "PANDORA_JSON_DEBUG"
#endif /* !PANDORA_JSON_DEBUG_ENV */

#ifndef PANDORA_MAGIC_PREFIX
#define PANDORA_MAGIC_PREFIX "/dev/pandora"
#endif /* !PANDORA_MAGIC_PREFIX */

#ifndef PANDORA_MAGIC_SEP_CHAR
#define PANDORA_MAGIC_SEP_CHAR ':'
#endif /* !PANDORA_MAGIC_SEP_CHAR */

#ifndef PANDORA_MAGIC_QUERY_CHAR
#define PANDORA_MAGIC_QUERY_CHAR '?'
#endif /* !PANDORA_MAGIC_QUERY_CHAR */

#ifndef PANDORA_MAGIC_ADD_CHAR
#define PANDORA_MAGIC_ADD_CHAR '+'
#endif /* !PANDORA_MAGIC_ADD_CHAR */

#ifndef PANDORA_MAGIC_REMOVE_CHAR
#define PANDORA_MAGIC_REMOVE_CHAR '-'
#endif /* !PANDORA_MAGIC_REMOVE_CHAR */

/* Enumerations */
enum sandbox_mode {
	SANDBOX_OFF,
	SANDBOX_ALLOW,
	SANDBOX_DENY,
};
static const char *const sandbox_mode_table[] = {
	[SANDBOX_OFF] = "off",
	[SANDBOX_DENY] = "deny",
	[SANDBOX_ALLOW] = "allow",
};
DEFINE_STRING_TABLE_LOOKUP(sandbox_mode, int)

enum create_mode {
	NO_CREATE,
	MAY_CREATE,
	MUST_CREATE,
};

enum lock_state {
	LOCK_UNSET,
	LOCK_SET,
	LOCK_PENDING,
};
static const char *const lock_state_table[] = {
	[LOCK_UNSET] = "off",
	[LOCK_SET] = "on",
	[LOCK_PENDING] = "exec",
};
DEFINE_STRING_TABLE_LOOKUP(lock_state, int)

enum abort_decision {
	ABORT_KILLALL,
	ABORT_CONTALL,
};
static const char *const abort_decision_table[] = {
	[ABORT_KILLALL] = "killall",
	[ABORT_CONTALL] = "contall",
};
DEFINE_STRING_TABLE_LOOKUP(abort_decision, int)

enum panic_decision {
	PANIC_KILL,
	PANIC_CONT,
	PANIC_CONTALL,
	PANIC_KILLALL,
};
static const char *const panic_decision_table[] = {
	[PANIC_KILL] = "kill",
	[PANIC_CONT] = "cont",
	[PANIC_CONTALL] = "contall",
	[PANIC_KILLALL] = "killall",
};
DEFINE_STRING_TABLE_LOOKUP(panic_decision, int)

enum violation_decision {
	VIOLATION_DENY,
	VIOLATION_KILL,
	VIOLATION_KILLALL,
	VIOLATION_CONT,
	VIOLATION_CONTALL,
};
static const char *const violation_decision_table[] = {
	[VIOLATION_DENY] = "deny",
	[VIOLATION_KILL] = "kill",
	[VIOLATION_KILLALL] = "killall",
	[VIOLATION_CONT] = "cont",
	[VIOLATION_CONTALL] = "contall",
};
DEFINE_STRING_TABLE_LOOKUP(violation_decision, int)

enum magic_type {
	MAGIC_TYPE_NONE,

	MAGIC_TYPE_OBJECT,
	MAGIC_TYPE_BOOLEAN,
	MAGIC_TYPE_INTEGER,
	MAGIC_TYPE_STRING,
	MAGIC_TYPE_STRING_ARRAY,

	MAGIC_TYPE_INVALID,
};

enum magic_key {
	MAGIC_KEY_NONE,

	MAGIC_KEY_CORE,

	MAGIC_KEY_CORE_LOG,
	MAGIC_KEY_CORE_LOG_CONSOLE_FD,
	MAGIC_KEY_CORE_LOG_FILE,
	MAGIC_KEY_CORE_LOG_LEVEL,
	MAGIC_KEY_CORE_LOG_TIMESTAMP,

	MAGIC_KEY_CORE_SANDBOX,
	MAGIC_KEY_CORE_SANDBOX_EXEC,
	MAGIC_KEY_CORE_SANDBOX_READ,
	MAGIC_KEY_CORE_SANDBOX_WRITE,
	MAGIC_KEY_CORE_SANDBOX_SOCK,

	MAGIC_KEY_CORE_WHITELIST,
	MAGIC_KEY_CORE_WHITELIST_PER_PROCESS_DIRECTORIES,
	MAGIC_KEY_CORE_WHITELIST_SUCCESSFUL_BIND,
	MAGIC_KEY_CORE_WHITELIST_UNSUPPORTED_SOCKET_FAMILIES,

	MAGIC_KEY_CORE_ABORT,
	MAGIC_KEY_CORE_ABORT_DECISION,

	MAGIC_KEY_CORE_PANIC,
	MAGIC_KEY_CORE_PANIC_DECISION,
	MAGIC_KEY_CORE_PANIC_EXIT_CODE,

	MAGIC_KEY_CORE_VIOLATION,
	MAGIC_KEY_CORE_VIOLATION_DECISION,
	MAGIC_KEY_CORE_VIOLATION_EXIT_CODE,
	MAGIC_KEY_CORE_VIOLATION_RAISE_FAIL,
	MAGIC_KEY_CORE_VIOLATION_RAISE_SAFE,

	MAGIC_KEY_CORE_TRACE,
	MAGIC_KEY_CORE_TRACE_FOLLOW_FORK,
	MAGIC_KEY_CORE_TRACE_EXIT_WAIT_ALL,
	MAGIC_KEY_CORE_TRACE_MAGIC_LOCK,

	MAGIC_KEY_EXEC,
	MAGIC_KEY_EXEC_KILL_IF_MATCH,
	MAGIC_KEY_EXEC_RESUME_IF_MATCH,

	MAGIC_KEY_WHITELIST,
	MAGIC_KEY_WHITELIST_EXEC,
	MAGIC_KEY_WHITELIST_READ,
	MAGIC_KEY_WHITELIST_WRITE,
	MAGIC_KEY_WHITELIST_SOCK,
	MAGIC_KEY_WHITELIST_SOCK_BIND,
	MAGIC_KEY_WHITELIST_SOCK_CONNECT,

	MAGIC_KEY_BLACKLIST,
	MAGIC_KEY_BLACKLIST_EXEC,
	MAGIC_KEY_BLACKLIST_READ,
	MAGIC_KEY_BLACKLIST_WRITE,
	MAGIC_KEY_BLACKLIST_SOCK,
	MAGIC_KEY_BLACKLIST_SOCK_BIND,
	MAGIC_KEY_BLACKLIST_SOCK_CONNECT,

	MAGIC_KEY_FILTER,
	MAGIC_KEY_FILTER_EXEC,
	MAGIC_KEY_FILTER_READ,
	MAGIC_KEY_FILTER_WRITE,
	MAGIC_KEY_FILTER_SOCK,

	MAGIC_KEY_INVALID,
};

enum magic_error {
	MAGIC_ERROR_SUCCESS = 0,
	MAGIC_ERROR_INVALID_KEY = -1,
	MAGIC_ERROR_INVALID_TYPE = -2,
	MAGIC_ERROR_INVALID_VALUE = -3,
	MAGIC_ERROR_INVALID_QUERY = -4,
	MAGIC_ERROR_INVALID_OPERATION = -5,
	MAGIC_ERROR_NOPERM = -6,
	MAGIC_ERROR_OOM = -7,
};

/* Type declarations */
typedef struct {
	char *path;
	pink_socket_address_t *addr;
} sock_info_t;

typedef struct {
	/* The actual pattern, useful for disallowing */
	char *str;

	int family;

	union {
		struct {
			bool abstract;
			char *path;
		} sa_un;

		struct {
			unsigned netmask;
			unsigned port[2];
			struct in_addr addr;
		} sa_in;

#if PANDORA_HAVE_IPV6
		struct {
			unsigned netmask;
			unsigned port[2];
			struct in6_addr addr;
		} sa6;
#endif
	} match;
} sock_match_t;

typedef struct {
	enum sandbox_mode sandbox_exec;
	enum sandbox_mode sandbox_read;
	enum sandbox_mode sandbox_write;
	enum sandbox_mode sandbox_sock;

	enum lock_state magic_lock;

	slist_t whitelist_exec;
	slist_t whitelist_read;
	slist_t whitelist_write;
	slist_t whitelist_sock_bind;
	slist_t whitelist_sock_connect;

	slist_t blacklist_exec;
	slist_t blacklist_read;
	slist_t blacklist_write;
	slist_t blacklist_sock_bind;
	slist_t blacklist_sock_connect;
} sandbox_t;

typedef struct {
	/* Last system call */
	unsigned long sno;

	/* Last (socket) subcall */
	long subcall;

	/* Arguments of last system call */
	long args[PINK_MAX_INDEX];

	/* Is the last system call denied? */
	bool deny;

	/* Denied system call will return this value */
	long ret;

	/* Resolved path argument for specially treated system calls like execve() */
	char *abspath;

	/* Current working directory, read from /proc/$pid/cwd */
	char *cwd;

	/* Process name, read from /proc/$pid/comm for initial process and
	 * updated after successful execve() */
	char *comm;

	/* Information about the last bind address with port zero */
	sock_info_t *savebind;

	/* fd -> sock_info_t mappings  */
	hashtable_t *sockmap;

	/* Per-process configuration */
	sandbox_t config;
} proc_data_t;

typedef struct config_state config_state_t;

typedef struct {
	/* Config parser & state */
	bool core;
	JSON_parser parser;
	config_state_t *state;

	/* Per-process sandboxing data */
	sandbox_t child;

	/* Non-inherited, "global" configuration data */
	unsigned log_console_fd;
	unsigned log_level;
	bool log_timestamp;
	char *log_file;

	bool whitelist_per_process_directories;
	bool whitelist_successful_bind;
	bool whitelist_unsupported_socket_families;

	enum abort_decision abort_decision;

	enum panic_decision panic_decision;
	int panic_exit_code;

	enum violation_decision violation_decision;
	int violation_exit_code;
	bool violation_raise_fail;
	bool violation_raise_safe;

	bool follow_fork;
	bool exit_wait_all;

	slist_t exec_kill_if_match;
	slist_t exec_resume_if_match;

	slist_t filter_exec;
	slist_t filter_read;
	slist_t filter_write;
	slist_t filter_sock;
} config_t;

typedef struct {
	/* Eldest child */
	pid_t eldest;

	/* Exit code */
	int exit_code;

	/* This is true if an access violation has occured, false otherwise. */
	bool violation;

	/* Callback table */
	pink_easy_callback_table_t callback_table;

	/* Tracing context */
	pink_easy_context_t *ctx;

	/* Global configuration */
	config_t config;
} pandora_t;

typedef int (*sysfunc_t) (pink_easy_process_t *current, const char *name);

typedef struct {
	const char *name;
	sysfunc_t enter;
	sysfunc_t exit;
} sysentry_t;

typedef struct {
	unsigned index;

	bool at;
	bool resolv;
	enum create_mode create;

	bool safe;
	int deny_errno;

	bool whitelisting;
	slist_t *wblist;

	slist_t *filter;

	long *fd;
	char **abspath;
	pink_socket_address_t **addr;
} sys_info_t;

/* Global variables */
extern pandora_t *pandora;

/* Global functions */
void die(int code, const char *fmt, ...) PINK_GCC_ATTR((noreturn, format (printf, 2, 3)));
void die_errno(int code, const char *fmt, ...) PINK_GCC_ATTR((noreturn, format (printf, 2, 3)));
void *xmalloc(size_t size) PINK_GCC_ATTR((malloc));
void *xcalloc(size_t nmemb, size_t size) PINK_GCC_ATTR((malloc));
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *src) PINK_GCC_ATTR((malloc));
char *xstrndup(const char *src, size_t n) PINK_GCC_ATTR((malloc));
int xasprintf(char **strp, const char *fmt, ...) PINK_GCC_ATTR((format (printf, 2, 3)));

#define LOG_DEFAULT_PREFIX PACKAGE
#define LOG_DEFAULT_SUFFIX "\n"

void log_init(void);
void log_close(void);
void log_prefix(const char *p);
void log_suffix(const char *s);
void log_msg_va(unsigned level, const char *fmt, va_list ap) PINK_GCC_ATTR((format (printf, 2, 0)));
void log_msg(unsigned level, const char *fmt, ...) PINK_GCC_ATTR((format (printf, 2, 3)));
#define fatal(...)	log_msg(0, __VA_ARGS__)
#define warning(...)	log_msg(1, __VA_ARGS__)
#define message(...)	log_msg(2, __VA_ARGS__)
#define info(...)	log_msg(3, __VA_ARGS__)
#define debug(...)	log_msg(4, __VA_ARGS__)
#define trace(...)	log_msg(5, __VA_ARGS__)

void abort_all(void);
int deny(pink_easy_process_t *current);
int restore(pink_easy_process_t *current);
int panic(pink_easy_process_t *current);
int violation(pink_easy_process_t *current, const char *fmt, ...) PINK_GCC_ATTR((format (printf, 2, 3)));

sock_info_t *sock_info_xdup(sock_info_t *src);

int sock_match_expand(const char *src, char ***buf);
int sock_match_new(const char *src, sock_match_t **buf);
int sock_match_new_pink(const sock_info_t *src, sock_match_t **buf);
sock_match_t *sock_match_xdup(const sock_match_t *src);
int sock_match(const sock_match_t *haystack, const pink_socket_address_t *needle);

const char *magic_strerror(int error);
const char *magic_strkey(enum magic_key key);
unsigned magic_key_type(enum magic_key key);
unsigned magic_key_parent(enum magic_key key);
unsigned magic_key_lookup(enum magic_key key, const char *nkey, ssize_t len);
int magic_cast(pink_easy_process_t *current, enum magic_key key, enum magic_type type, const void *val);
int magic_cast_string(pink_easy_process_t *current, const char *magic, int prefix);

void config_init(void);
void config_destroy(void);
void config_reset(void);
void config_parse_file(const char *filename) PINK_GCC_ATTR((nonnull(1)));
void config_parse_spec(const char *filename) PINK_GCC_ATTR((nonnull(1)));

void callback_init(void);

int box_resolve_path(const char *path, const char *prefix, pid_t pid, int maycreat, int resolve, char **res);
int box_match_path(const char *path, const slist_t *patterns, const char **match);
int box_check_path(pink_easy_process_t *current, const char *name, sys_info_t *info);
int box_check_sock(pink_easy_process_t *current, const char *name, sys_info_t *info);

int path_decode(pink_easy_process_t *current, unsigned ind, char **buf);
int path_prefix(pink_easy_process_t *current, unsigned ind, char **buf);

void systable_init(void);
void systable_free(void);
void systable_add(const char *name, sysfunc_t fenter, sysfunc_t fexit);
const sysentry_t *systable_lookup(long no, pink_bitness_t bit);

void sysinit(void);
int sysenter(pink_easy_process_t *current);
int sysexit(pink_easy_process_t *current);

int sys_chmod(pink_easy_process_t *current, const char *name);
int sys_fchmodat(pink_easy_process_t *current, const char *name);
int sys_chown(pink_easy_process_t *current, const char *name);
int sys_lchown(pink_easy_process_t *current, const char *name);
int sys_fchownat(pink_easy_process_t *current, const char *name);
int sys_open(pink_easy_process_t *current, const char *name);
int sys_openat(pink_easy_process_t *current, const char *name);
int sys_creat(pink_easy_process_t *current, const char *name);
int sys_close(pink_easy_process_t *current, const char *name);
int sys_mkdir(pink_easy_process_t *current, const char *name);
int sys_mkdirat(pink_easy_process_t *current, const char *name);
int sys_mknod(pink_easy_process_t *current, const char *name);
int sys_mknodat(pink_easy_process_t *current, const char *name);
int sys_rmdir(pink_easy_process_t *current, const char *name);
int sys_truncate(pink_easy_process_t *current, const char *name);
int sys_mount(pink_easy_process_t *current, const char *name);
int sys_umount(pink_easy_process_t *current, const char *name);
int sys_umount2(pink_easy_process_t *current, const char *name);
int sys_utime(pink_easy_process_t *current, const char *name);
int sys_utimes(pink_easy_process_t *current, const char *name);
int sys_utimensat(pink_easy_process_t *current, const char *name);
int sys_futimesat(pink_easy_process_t *current, const char *name);
int sys_unlink(pink_easy_process_t *current, const char *name);
int sys_unlinkat(pink_easy_process_t *current, const char *name);
int sys_link(pink_easy_process_t *current, const char *name);
int sys_linkat(pink_easy_process_t *current, const char *name);
int sys_rename(pink_easy_process_t *current, const char *name);
int sys_renameat(pink_easy_process_t *current, const char *name);
int sys_symlink(pink_easy_process_t *current, const char *name);
int sys_symlinkat(pink_easy_process_t *current, const char *name);
int sys_setxattr(pink_easy_process_t *current, const char *name);
int sys_lsetxattr(pink_easy_process_t *current, const char *name);
int sys_removexattr(pink_easy_process_t *current, const char *name);
int sys_lremovexattr(pink_easy_process_t *current, const char *name);

int sys_access(pink_easy_process_t *current, const char *name);
int sys_faccessat(pink_easy_process_t *current, const char *name);

int sys_dup(pink_easy_process_t *current, const char *name);
int sys_dup3(pink_easy_process_t *current, const char *name);
int sys_fcntl(pink_easy_process_t *current, const char *name);

int sys_execve(pink_easy_process_t *current, const char *name);
int sys_stat(pink_easy_process_t *current, const char *name);

int sys_socketcall(pink_easy_process_t *current, const char *name);
int sys_bind(pink_easy_process_t *current, const char *name);
int sys_connect(pink_easy_process_t *current, const char *name);
int sys_sendto(pink_easy_process_t *current, const char *name);
int sys_recvfrom(pink_easy_process_t *current, const char *name);
int sys_getsockname(pink_easy_process_t *current, const char *name);

int sysx_chdir(pink_easy_process_t *current, const char *name);
int sysx_close(pink_easy_process_t *current, const char *name);
int sysx_dup(pink_easy_process_t *current, const char *name);
int sysx_fcntl(pink_easy_process_t *current, const char *name);
int sysx_socketcall(pink_easy_process_t *current, const char *name);
int sysx_bind(pink_easy_process_t *current, const char *name);
int sysx_getsockname(pink_easy_process_t *current, const char *name);

inline
static void
free_sock_info(void *data)
{
	sock_info_t *info = data;

	if (info->path)
		free(info->path);
	free(info->addr);
	free(info);
}

inline
static void
free_sock_match(void *data)
{
	sock_match_t *m = data;

	if (m->str)
		free(m->str);
	if (m->family == AF_UNIX && m->match.sa_un.path)
		free(m->match.sa_un.path);
	free(m);
}

inline
static void
free_sandbox(sandbox_t *box)
{
	struct snode *node;

	SLIST_FLUSH(node, &box->whitelist_exec, up, free);
	SLIST_FLUSH(node, &box->whitelist_read, up, free);
	SLIST_FLUSH(node, &box->whitelist_write, up, free);
	SLIST_FLUSH(node, &box->whitelist_sock_bind, up, free_sock_match);
	SLIST_FLUSH(node, &box->whitelist_sock_connect, up, free_sock_match);

	SLIST_FLUSH(node, &box->blacklist_exec, up, free);
	SLIST_FLUSH(node, &box->blacklist_read, up, free);
	SLIST_FLUSH(node, &box->blacklist_write, up, free);
	SLIST_FLUSH(node, &box->blacklist_sock_bind, up, free_sock_match);
	SLIST_FLUSH(node, &box->blacklist_sock_connect, up, free_sock_match);
}

inline
static void
free_proc(void *data)
{
	proc_data_t *p = data;

	if (!p)
		return;

	if (p->abspath)
		free(p->abspath);

	if (p->cwd)
		free(p->cwd);

	if (p->comm)
		free(p->comm);

	if (p->savebind)
		free_sock_info(p->savebind);

	/* Free the fd -> address mappings */
	for (int i = 0; i < p->sockmap->size; i++) {
		ht_int64_node_t *node = HT_NODE(p->sockmap, p->sockmap->nodes, i);
		if (node->data)
			free_sock_info(node->data);
	}
	hashtable_destroy(p->sockmap);

	/* Free the sandbox */
	free_sandbox(&p->config);

	/* Free the rest */
	free(p);
}

inline
static void
clear_proc(void *data)
{
	proc_data_t *p = data;

	p->deny = false;
	p->ret = 0;
	p->subcall = 0;
	for (unsigned i = 0; i < PINK_MAX_INDEX; i++)
		p->args[i] = 0;

	if (p->savebind)
		free_sock_info(p->savebind);
	p->savebind = NULL;
}

#endif /* !PANDORA_GUARD_DEFS_H */
