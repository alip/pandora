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
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "proc.h"

/* Pandora's callback table */
static pink_easy_callback_table_t *ptbl;

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
	ctx_data_t *cdata;
	proc_data_t *data, *pdata;
	sandbox_t *inherit;

	pid = pink_easy_process_get_pid(current);
	data = xcalloc(1, sizeof(proc_data_t));

	if (!parent) {
		inherit = &config->child;

		/* Figure out the current working directory */
		if ((ret = proc_cwd(pid, &cwd))) {
			errno = -ret;
			die_errno(99, "proc_getcwd(%d)", pid);
		}

		/* Save the process ID of the eldest child */
		cdata = (ctx_data_t *)pink_easy_context_get_data(ctx);
		cdata->eldest = pid;

		info("initial process:%d", pid);
	}
	else {
		pdata = (proc_data_t *)pink_easy_process_get_data(parent);
		inherit = &pdata->config;

		cwd = xstrdup(pdata->cwd);

		info("new process:%d parent:%d", pid, pink_easy_process_get_pid(parent));
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

	if (config->core.auto_allow_per_process_dirs) {
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
	ctx_data_t *data;

	/* Free the global configuration */
	slist_free(config->child.allow.exec, free);
	slist_free(config->child.allow.path, free);

	slist_free(config->filter.exec, free);
	slist_free(config->filter.path, free);
	slist_free(config->filter.path, free);

	free(config);

	/* Free callbacks */
	free(ptbl);

	systable_free();

	data = (ctx_data_t *)pink_easy_context_get_data(ctx);
	return data->code;
}

static short
callback_pre_exit(const pink_easy_context_t *ctx, pink_easy_process_t *current, unsigned long status)
{
	pid_t pid;
	ctx_data_t *data;

	data = pink_easy_context_get_data(ctx);
	pid = pink_easy_process_get_pid(current);

	info("dead process:%d", pid);

	if (pid == data->eldest) {
		/* Eldest child, keep return code */
		if (WIFEXITED(status))
			data->code = WEXITSTATUS(status);
		else if (WIFSIGNALED(status))
			data->code = 128 + WTERMSIG(status);
		/* TODO: else warn here! */
	}

	return 0;
}

static short
callback_syscall(const pink_easy_context_t *ctx, pink_easy_process_t *current, bool entering)
{
	return entering ? sysenter(ctx, current) : sysexit(ctx, current);
}

pink_easy_callback_table_t *
callback_init(void)
{
	ptbl = xcalloc(1, sizeof(pink_easy_callback_table_t));
	ptbl->birth = callback_birth;
	ptbl->end = callback_end;
	ptbl->pre_exit = callback_pre_exit;
	ptbl->syscall = callback_syscall;
	ptbl->error = callback_error;
	ptbl->cerror = callback_child_error;

	return ptbl;
}
