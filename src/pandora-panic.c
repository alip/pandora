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
#include <stdbool.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

static bool
cont_one(pink_easy_process_t *proc, PINK_UNUSED void *userdata)
{
	pid_t pid = pink_easy_process_get_pid(proc);
	pink_trace_resume(pid, 0);
	return true;
}

static bool
kill_one(pink_easy_process_t *proc, PINK_UNUSED void *userdata)
{
	pid_t pid = pink_easy_process_get_pid(proc);
	pink_trace_kill(pid);
	return true;
}

short
panic(const pink_easy_context_t *ctx, pink_easy_process_t *current)
{
	unsigned count;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_easy_process_tree_t *tree = pink_easy_context_get_tree(ctx);
	ctx_data_t *data = pink_easy_context_get_data(ctx);

	switch (config->core.on_panic) {
	case PANIC_KILL:
		warning("panic! killing process:%lu", (unsigned long)pid);
		pink_trace_kill(pid);
		return PINK_EASY_CFLAG_DEAD;
	case PANIC_CONT:
		warning("panic! resuming process:%lu", (unsigned long)pid);
		pink_trace_resume(pid, 0);
		return PINK_EASY_CFLAG_DEAD;
	case PANIC_CONTALL:
		warning("panic! resuming all processes");
		count = pink_easy_process_tree_walk(tree, cont_one, NULL);
		warning("resumed %u processes, exiting", count);
		exit(config->core.panic_exit_code > 0 ? config->core.panic_exit_code : data->code);
	case PANIC_KILLALL:
		warning("panic! killing all processes");
		count = pink_easy_process_tree_walk(tree, kill_one, NULL);
		warning("killed %u processes, exiting", count);
		exit(config->core.panic_exit_code > 0 ? config->core.panic_exit_code : data->code);
	default:
		abort();
	}
}
