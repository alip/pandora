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

#include <sys/types.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "proc.h"

inline
static int
errno2retval(void)
{
	if (errno == EIO)
		return -EFAULT;
	return -errno;
}

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
	kill(pid, SIGTERM);
	kill(pid, SIGKILL);
	return true;
}

void
abort_all(void)
{
	unsigned count;
	pink_easy_process_tree_t *tree = pink_easy_context_get_tree(pandora->ctx);

	switch (pandora->config->core.abort.decision) {
	case ABORT_CONTALL:
		count = pink_easy_process_tree_walk(tree, cont_one, NULL);
		fprintf(stderr, "resumed %u processes\n", count);
		break;
	case ABORT_KILLALL:
		count = pink_easy_process_tree_walk(tree, kill_one, NULL);
		fprintf(stderr, "killed %u processes\n", count);
		break;
	default:
		break;
	}
}

#if !defined(SPARSE) && defined(__GNUC__) && __GNUC__ >= 3
__attribute__ ((format (printf, 2, 0)))
#endif
static void
report(pink_easy_process_t *current, const char *fmt, va_list ap)
{
	char *cmdline;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	warning("-- Access Violation! --");
	warning("process id:%lu (%s)", (unsigned long)pid, pink_bitness_name(bit));
	warning("cwd: `%s'", data->cwd);

	if (!proc_cmdline(pid, 128, &cmdline)) {
		warning("cmdline: `%s'", cmdline);
		free(cmdline);
	}

	log_msg_va(1, fmt, ap);
}

int
deny(pink_easy_process_t *current)
{
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	data->deny = 1;
	data->ret = errno2retval();

	if (!pink_util_set_syscall(pid, bit, PINKTRACE_INVALID_SYSCALL)) {
		if (errno != ESRCH) {
			warning("pink_util_set_syscall(%d, \"%s\", 0xbadca11): %d(%s)",
					pid, pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	return 0;
}

int
restore(pink_easy_process_t *current)
{
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	/* Restore system call number */
	if (!pink_util_set_syscall(pid, bit, data->sno)) {
		if (errno == ESRCH)
			return PINK_EASY_CFLAG_DROP;
		warning("pink_util_set_syscall(%d, %s, %s): errno:%d (%s)",
				pid, pink_bitness_name(bit),
				pink_name_syscall(data->sno, bit),
				errno, strerror(errno));
	}

	/* Return the saved return value */
	if (!pink_util_set_return(pid, data->ret)) {
		if (errno == ESRCH)
			return PINK_EASY_CFLAG_DROP;
		warning("pink_util_set_return(%d, %s, %s): errno:%d (%s)",
				pid, pink_bitness_name(bit),
				pink_name_syscall(data->sno, bit),
				errno, strerror(errno));
	}

	return 0;
}

int
panic(pink_easy_process_t *current)
{
	unsigned count;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_easy_process_tree_t *tree = pink_easy_context_get_tree(pandora->ctx);

	switch (pandora->config->core.panic.decision) {
	case PANIC_KILL:
		warning("panic! killing process:%lu", (unsigned long)pid);
		pink_trace_kill(pid);
		return PINK_EASY_CFLAG_DROP;
	case PANIC_CONT:
		warning("panic! resuming process:%lu", (unsigned long)pid);
		pink_trace_resume(pid, 0);
		return PINK_EASY_CFLAG_DROP;
	case PANIC_CONTALL:
		warning("panic! resuming all processes");
		count = pink_easy_process_tree_walk(tree, cont_one, NULL);
		warning("resumed %u processes, exiting", count);
		break;
	case PANIC_KILLALL:
		warning("panic! killing all processes");
		count = pink_easy_process_tree_walk(tree, kill_one, NULL);
		warning("killed %u processes, exiting", count);
		break;
	default:
		abort();
	}

	/* exit */
	exit(pandora->config->core.panic.exit_code > 0 ? pandora->config->core.panic.exit_code : pandora->code);
}

int
violation(pink_easy_process_t *current, const char *fmt, ...)
{
	unsigned count;
	va_list ap;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_easy_process_tree_t *tree = pink_easy_context_get_tree(pandora->ctx);

	pandora->violation = 1;

	va_start(ap, fmt);
	report(current, fmt, ap);
	va_end(ap);

	switch (pandora->config->core.violation.decision) {
	case VIOLATION_DENY:
		return 0; /* Let the caller handle this */
	case VIOLATION_KILL:
		warning("killing process:%lu", (unsigned long)pid);
		pink_trace_kill(pid);
		return PINK_EASY_CFLAG_DROP;
	case VIOLATION_CONT:
		warning("resuming process:%lu", (unsigned long)pid);
		pink_trace_resume(pid, 0);
		return PINK_EASY_CFLAG_DROP;
	case VIOLATION_CONTALL:
		warning("resuming all processes");
		count = pink_easy_process_tree_walk(tree, cont_one, NULL);
		warning("resumed %u processes, exiting", count);
		break;
	case VIOLATION_KILLALL:
		warning("killing all processes");
		count = pink_easy_process_tree_walk(tree, kill_one, NULL);
		warning("killed %u processes, exiting", count);
		break;
	default:
		abort();
	}

	/* exit */
	if (pandora->config->core.violation.exit_code > 0)
		exit(pandora->config->core.violation.exit_code);
	else if (!pandora->config->core.violation.exit_code)
		exit(128 + pandora->config->core.violation.exit_code);
	exit(pandora->code);
}
