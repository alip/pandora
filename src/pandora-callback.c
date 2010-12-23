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
#include <stdio.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "proc.h"

static int
callback_child_error(pink_easy_child_error_t error)
{
	fprintf(stderr, "child: %s (errno:%d %s)\n",
			pink_easy_child_strerror(error),
			errno, strerror(errno));
	return -1;
}

static void
callback_error(const pink_easy_context_t *ctx, ...)
{
	pink_easy_error_t error;

	/* TODO: Nicer error messages */
	error = pink_easy_context_get_error(ctx);
	fprintf(stderr, "error: %s\n", pink_easy_strerror(error));
}

static void
callback_birth(PINK_UNUSED const pink_easy_context_t *ctx, pink_easy_process_t *current, pink_easy_process_t *parent)
{
	int ret;
	pid_t pid;
	char proc_pid[32];
	char *cwd;
	slist_t *slist;
	proc_data_t *data, *pdata;
	sandbox_t *inherit;

	pid = pink_easy_process_get_pid(current);
	data = xcalloc(1, sizeof(proc_data_t));

	if (!parent) {
		inherit = &pandora->config->child;

		/* Figure out the current working directory */
		if ((ret = proc_cwd(pid, &cwd))) {
			errno = -ret;
			/* FIXME: This isn't right! */
			die_errno(99, "proc_getcwd(%d)", pid);
		}
	}
	else {
		pdata = (proc_data_t *)pink_easy_process_get_data(parent);
		inherit = &pdata->config;

		cwd = xstrdup(pdata->cwd);
	}

	/* Copy the configuration */
	memcpy(&data->config, inherit, sizeof(sandbox_t));
	data->cwd = cwd;

	/* TODO: Copy network addresses */

	/* Copy string arrays  */
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

	if (pandora->config->core.allow.per_process_directories) {
		/* Allow /proc/$pid */
		snprintf(proc_pid, 32, "/proc/%d", pid);
		data->config.allow.path = slist_prepend(data->config.allow.path, xstrdup(proc_pid));
		if (!data->config.allow.path)
			die_errno(-1, "Out of memory");
	}

	pink_easy_process_set_data(current, data, free_proc);
}

static int
callback_end(PINK_UNUSED const pink_easy_context_t *ctx, PINK_UNUSED bool echild)
{
	/* Free the global configuration */
	slist_free(pandora->config->child.allow.exec, free);
	slist_free(pandora->config->child.allow.path, free);
	slist_free(pandora->config->child.allow.sock.bind, free);
	slist_free(pandora->config->child.allow.sock.connect, free);

	slist_free(pandora->config->filter.exec, free);
	slist_free(pandora->config->filter.path, free);
	slist_free(pandora->config->filter.path, free);

	systable_free();

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
		if (WIFEXITED(status))
			pandora->code = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			pandora->code = 128 + WTERMSIG(status);
		/* TODO: else warn here! */
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

	if (!data->exec_abspath) {
		/* Nothing to do */
		return 0;
	}

	/* kill_if_match and resume_if_match */
	if (box_match_path(data->exec_abspath, pandora->config->trace.kill_if_match, &match)) {
		warning("kill_if_match pattern `%s' matches execve path `%s'", match, data->exec_abspath);
		warning("killing process:%lu (%s)", (unsigned long)pid, pink_bitness_name(bit));
		kill(pid, SIGTERM);
		kill(pid, SIGKILL);
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

	return 0;
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
