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

#include <sys/types.h>
#include <sys/wait.h>
#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "proc.h"

#ifndef NR_OPEN
#define NR_OPEN 1024
#endif

static int
callback_child_error(pink_easy_child_error_t error)
{
	fprintf(stderr, "child error: %s (errno:%d %s)\n",
			pink_easy_child_strerror(error),
			errno, strerror(errno));
	return -1;
}

static void
callback_error(const pink_easy_context_t *ctx, ...)
{
	int status;
	pid_t pid;
	va_list ap;
	pink_easy_error_t error;
	pink_easy_process_t *current;

	error = pink_easy_context_get_error(ctx);
	va_start(ap, ctx);

	switch (error) {
	case PINK_EASY_ERROR_ALLOC:
	case PINK_EASY_ERROR_ATTACH:
	case PINK_EASY_ERROR_WAIT_ELDEST:
	case PINK_EASY_ERROR_SETUP_ELDEST:
	case PINK_EASY_ERROR_BITNESS_ELDEST:
	case PINK_EASY_ERROR_GETEVENTMSG_EXIT:
		pid = va_arg(ap, pid_t);
		fatal("error (pid:%lu): %s (errno:%d %s)",
				(unsigned long)pid,
				pink_easy_strerror(error),
				errno, strerror(errno));
		break;
	case PINK_EASY_ERROR_STOP_ELDEST:
		pid = va_arg(ap, pid_t);
		status = va_arg(ap, int);
		fatal("error (pid:%lu status:%#x): %s",
				(unsigned long)pid,
				(unsigned)status,
				pink_easy_strerror(error));
		break;
	case PINK_EASY_ERROR_SETUP:
	case PINK_EASY_ERROR_BITNESS:
	case PINK_EASY_ERROR_STEP_INITIAL:
	case PINK_EASY_ERROR_STEP_STOP:
	case PINK_EASY_ERROR_STEP_TRAP:
	case PINK_EASY_ERROR_STEP_SYSCALL:
	case PINK_EASY_ERROR_STEP_FORK:
	case PINK_EASY_ERROR_STEP_EXEC:
	case PINK_EASY_ERROR_STEP_EXIT:
	case PINK_EASY_ERROR_GETEVENTMSG_FORK:
		current = va_arg(ap, pink_easy_process_t *);
		fatal("error (pid:%lu [%s]): %s (errno:%d %s)",
				(unsigned long)pink_easy_process_get_pid(current),
				pink_bitness_name(pink_easy_process_get_bitness(current)),
				pink_easy_strerror(error),
				errno, strerror(errno));
		break;
	case PINK_EASY_ERROR_STEP_SIGNAL:
	case PINK_EASY_ERROR_EVENT_UNKNOWN:
		current = va_arg(ap, pink_easy_process_t *);
		status = va_arg(ap, int);
		fatal("error (pid:%lu [%s] status:%#x): %s (errno:%d %s)",
				(unsigned long)pink_easy_process_get_pid(current),
				pink_bitness_name(pink_easy_process_get_bitness(current)),
				status,
				pink_easy_strerror(error),
				errno, strerror(errno));
		break;
	default:
		fatal("error: %s (errno:%d %s)",
				pink_easy_strerror(error),
				errno, strerror(errno));
		break;
	}

	va_end(ap);
}

static void
callback_birth(PINK_UNUSED const pink_easy_context_t *ctx, pink_easy_process_t *current, pink_easy_process_t *parent)
{
	int ret;
	pid_t pid;
	pink_bitness_t bit;
	char *cwd, *proc_pid;
	slist_t *slist;
	proc_data_t *data, *pdata;
	sandbox_t *inherit;

	pid = pink_easy_process_get_pid(current);
	bit = pink_easy_process_get_bitness(current);
	data = xcalloc(1, sizeof(proc_data_t));

	if (!parent) {
		pandora->eldest = pid;

		/* Figure out the current working directory */
		if ((ret = proc_cwd(pid, &cwd))) {
			warning("failed to get working directory of the initial process:%lu [%s] (errno:%d %s)",
					(unsigned long)pid, pink_bitness_name(bit),
					-ret, strerror(-ret));
			free(data);
			panic(current);
			return;
		}

		info("initial process:%lu [%s cwd:\"%s\"]",
				(unsigned long)pid, pink_bitness_name(bit),
				cwd);

		inherit = &pandora->config->child;
	}
	else {
		pdata = (proc_data_t *)pink_easy_process_get_data(parent);
		cwd = xstrdup(pdata->cwd);

		info("new process:%lu [%s cwd:\"%s\"]",
				(unsigned long)pid, pink_bitness_name(bit),
				cwd);
		info("parent process:%lu [%s cwd:\"%s\"]",
				(unsigned long)pink_easy_process_get_pid(parent),
				pink_bitness_name(pink_easy_process_get_bitness(parent)),
				cwd);

		inherit = &pdata->config;
	}

	/* Copy the configuration */
	data->config.core.sandbox.exec = inherit->core.sandbox.exec;
	data->config.core.sandbox.path = inherit->core.sandbox.path;
	data->config.core.sandbox.sock = inherit->core.sandbox.sock;
	data->config.core.trace.magic_lock = inherit->core.trace.magic_lock;
	data->cwd = cwd;

	/* Copy the lists  */
	data->config.allow.exec = NULL;
	for (slist = inherit->allow.exec; slist; slist = slist->next) {
		data->config.allow.exec = slist_prepend(data->config.allow.exec, xstrdup((char *)slist->data));
		if (!data->config.allow.exec)
			die_errno(-1, "Out of memory");
	}

	data->config.allow.path = NULL;
	for (slist = inherit->allow.path; slist; slist = slist->next) {
		data->config.allow.path = slist_prepend(data->config.allow.path, xstrdup((char *)slist->data));
		if (!data->config.allow.path)
			die_errno(-1, "Out of memory");
	}

	data->config.allow.sock.bind = NULL;
	for (slist = inherit->allow.sock.bind; slist; slist = slist->next) {
		data->config.allow.sock.bind = slist_prepend(data->config.allow.sock.bind, sock_match_xdup((sock_match_t *)slist->data));
		if (!data->config.allow.sock.bind)
			die_errno(-1, "Out of memory");
	}

	data->config.allow.sock.connect = NULL;
	for (slist = inherit->allow.sock.connect; slist; slist = slist->next) {
		data->config.allow.sock.connect = slist_prepend(data->config.allow.sock.connect, sock_match_xdup((sock_match_t *)slist->data));
		if (!data->config.allow.sock.connect)
			die_errno(-1, "Out of memory");
	}

	if (pandora->config->core.allow.per_process_directories) {
		/* Allow /proc/$pid */
		xasprintf(&proc_pid, "/proc/%lu", (unsigned long)pid);
		data->config.allow.path = slist_prepend(data->config.allow.path, proc_pid);
		if (!data->config.allow.path)
			die_errno(-1, "Out of memory");
	}

	/* Create the fd -> address hash table */
	if ((ret = hashtable_create(NR_OPEN, 1, &data->bind_zero)) < 0) {
		errno = -ret;
		die_errno(-1, "hashtable_create");
	}

	pink_easy_process_set_data(current, data, free_proc);
}

static int
callback_end(PINK_UNUSED const pink_easy_context_t *ctx, PINK_UNUSED bool echild)
{
	if (pandora->violation) {
		if (pandora->config->core.violation.exit_code > 0)
			return pandora->config->core.violation.exit_code;
		else if (!pandora->config->core.violation.exit_code)
			return 128 + pandora->code;
	}
	return pandora->code;
}

static int
callback_pre_exit(PINK_UNUSED const pink_easy_context_t *ctx, pid_t pid, unsigned long status)
{
	if (pid == pandora->eldest) {
		/* Eldest child, keep return code */
		if (WIFEXITED(status)) {
			pandora->code = WEXITSTATUS(status);
			message("initial process:%lu exited with code:%d (status:%#lx)",
					(unsigned long)pid, pandora->code,
					status);
		}
		else if (WIFSIGNALED(status)) {
			pandora->code = 128 + WTERMSIG(status);
			message("initial process:%lu was terminated with signal:%d (status:%#lx)",
					(unsigned long)pid, pandora->code - 128,
					status);
		}
		else {
			warning("initial process:%lu exited with unknown status:%#lx",
					(unsigned long)pid, status);
			warning("don't know how to determine exit code");
		}
	}
	else {
		if (WIFEXITED(status))
			info("process:%lu exited with code:%d (status:%#lx)",
					(unsigned long)pid,
					WEXITSTATUS(status),
					status);
		else if (WIFSIGNALED(status))
			info("process:%lu exited was terminated with signal:%d (status:%#lx)",
					(unsigned long)pid,
					WTERMSIG(status),
					status);
		else
			warning("process:%lu exited with unknown status:%#lx",
					(unsigned long)pid, status);
	}

	return 0;
}

static int
callback_exec(PINK_UNUSED const pink_easy_context_t *ctx, pink_easy_process_t *current, PINK_UNUSED pink_bitness_t orig_bitness)
{
	int ret;
	const char *match;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	if (data->config.core.trace.magic_lock == LOCK_PENDING) {
		info("locking magic commands for process:%lu (%s)",
				(unsigned long)pid,
				pink_bitness_name(bit));
		data->config.core.trace.magic_lock = LOCK_SET;
	}

	if (!data->exec_abspath) {
		/* Nothing to do */
		return 0;
	}

	/* kill_if_match and resume_if_match */
	ret = 0;
	if (box_match_path(data->exec_abspath, pandora->config->trace.kill_if_match, &match)) {
		warning("kill_if_match pattern `%s' matches execve path `%s'", match, data->exec_abspath);
		warning("killing process:%lu (%s)", (unsigned long)pid, pink_bitness_name(bit));
		pkill(pid);
		ret = PINK_EASY_CFLAG_DROP;
	}
	else if (box_match_path(data->exec_abspath, pandora->config->trace.resume_if_match, &match)) {
		warning("resume_if_match pattern `%s' matches execve path `%s'", match, data->exec_abspath);
		warning("resuming process:%lu (%s)", (unsigned long)pid, pink_bitness_name(bit));
		pink_trace_resume(pid, 0);
		ret = PINK_EASY_CFLAG_DROP;
	}

	free(data->exec_abspath);
	data->exec_abspath = NULL;

	return ret;
}

static int
callback_syscall(PINK_UNUSED const pink_easy_context_t *ctx, pink_easy_process_t *current, bool entering)
{
	return entering ? sysenter(current) : sysexit(current);
}

void
callback_init(void)
{
	assert(!pandora->tbl);

	pandora->tbl = xcalloc(1, sizeof(pink_easy_callback_table_t));
	pandora->tbl->birth = callback_birth;
	pandora->tbl->end = callback_end;
	pandora->tbl->pre_exit = callback_pre_exit;
	pandora->tbl->exec = callback_exec;
	pandora->tbl->syscall = callback_syscall;
	pandora->tbl->error = callback_error;
	pandora->tbl->cerror = callback_child_error;
}
