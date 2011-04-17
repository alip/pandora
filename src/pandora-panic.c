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
#include <string.h>

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
cont_one(pink_easy_process_t *proc, void *userdata)
{
	bool logok = *(bool *)userdata;
	pid_t pid = pink_easy_process_get_pid(proc);

	if (logok)
		warning("resuming process:%lu", (unsigned long)pid);
	else
		fprintf(stderr, "resuming process:%lu\n", (unsigned long)pid);

	if (!pink_easy_process_resume(proc, 0) && errno != ESRCH) {
		if (logok)
			warning("failed to resume process:%lu (errno:%d %s)",
				(unsigned long)pid, errno, strerror(errno));
		else
			fprintf(stderr, "failed to resume process:%lu (errno:%d %s)\n",
					(unsigned long)pid, errno, strerror(errno));
	}

	return true;
}

static bool
kill_one(pink_easy_process_t *proc, void *userdata)
{
	bool logok = *(bool *)userdata;
	pid_t pid = pink_easy_process_get_pid(proc);

	if (logok)
		warning("killing process:%lu", (unsigned long)pid);
	else
		fprintf(stderr, "killing process:%lu\n", (unsigned long)pid);

	if (pink_easy_process_kill(proc, SIGKILL) < 0 && errno != ESRCH) {
		if (logok)
			warning("failed to kill process:%lu (errno:%d %s)",
				(unsigned long)pid, errno, strerror(errno));
		else
			fprintf(stderr, "failed to kill process:%lu (errno:%d %s)\n",
					(unsigned long)pid, errno, strerror(errno));
	}

	return true;
}

void
abort_all(void)
{
	bool logok = false;
	unsigned count;
	pink_easy_process_list_t *list = pink_easy_context_get_process_list(pandora->ctx);

	switch (pandora->config.abort_decision) {
	case ABORT_CONTALL:
		count = pink_easy_process_list_walk(list, cont_one, &logok);
		fprintf(stderr, "resumed %u process%s\n", count, count > 1 ? "es" : "");
		break;
	case ABORT_KILLALL:
		count = pink_easy_process_list_walk(list, kill_one, &logok);
		fprintf(stderr, "killed %u process%s\n", count, count > 1 ? "es" : "");
		break;
	default:
		break;
	}
}

PINK_GCC_ATTR((format (printf, 2, 0)))
static void
report(pink_easy_process_t *current, const char *fmt, va_list ap)
{
	char *cmdline;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	warning("-- Access Violation! --");
	warning("process id:%lu (%s name:\"%s\")", (unsigned long)pid, pink_bitness_name(bit), data->comm);
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
	proc_data_t *data = pink_easy_process_get_userdata(current);

	data->deny = true;
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
	proc_data_t *data = pink_easy_process_get_userdata(current);

	/* Restore system call number */
	if (!pink_util_set_syscall(pid, bit, data->sno)) {
		if (errno == ESRCH)
			return PINK_EASY_CFLAG_DROP;
		warning("pink_util_set_syscall(%lu, %s, %s): errno:%d (%s)",
				(unsigned long)pid, pink_bitness_name(bit),
				pink_name_syscall(data->sno, bit),
				errno, strerror(errno));
	}

	/* Return the saved return value */
	if (!pink_util_set_return(pid, data->ret)) {
		if (errno == ESRCH)
			return PINK_EASY_CFLAG_DROP;
		warning("pink_util_set_return(%lu, %s, %s): errno:%d (%s)",
				(unsigned long)pid, pink_bitness_name(bit),
				pink_name_syscall(data->sno, bit),
				errno, strerror(errno));
	}

	return 0;
}

int
panic(pink_easy_process_t *current)
{
	bool logok = true;
	unsigned count;
	pink_easy_process_list_t *list = pink_easy_context_get_process_list(pandora->ctx);

	switch (pandora->config.panic_decision) {
	case PANIC_KILL:
		warning("panic! killing the guilty process");
		kill_one(current, &logok);
		return PINK_EASY_CFLAG_DROP;
	case PANIC_CONT:
		warning("panic! resuming the guilty process");
		cont_one(current, &logok);
		return PINK_EASY_CFLAG_DROP;
	case PANIC_CONTALL:
		warning("panic! resuming all processes");
		count = pink_easy_process_list_walk(list, cont_one, &logok);
		warning("resumed %u process%s, exiting", count, count > 1 ? "es" : "");
		break;
	case PANIC_KILLALL:
		warning("panic! killing all processes");
		count = pink_easy_process_list_walk(list, kill_one, &logok);
		warning("killed %u process%s, exiting", count, count > 1 ? "es" : "");
		break;
	default:
		abort();
	}

	/* exit */
	exit(pandora->config.panic_exit_code > 0 ? pandora->config.panic_exit_code : pandora->exit_code);
}

int
violation(pink_easy_process_t *current, const char *fmt, ...)
{
	bool logok = true;
	unsigned count;
	va_list ap;
	pink_easy_process_list_t *list = pink_easy_context_get_process_list(pandora->ctx);

	pandora->violation = true;

	va_start(ap, fmt);
	report(current, fmt, ap);
	va_end(ap);

	switch (pandora->config.violation_decision) {
	case VIOLATION_DENY:
		return 0; /* Let the caller handle this */
	case VIOLATION_KILL:
		warning("killing the guilty process");
		kill_one(current, &logok);
		return PINK_EASY_CFLAG_DROP;
	case VIOLATION_CONT:
		warning("resuming the guilty process");
		cont_one(current, &logok);
		return PINK_EASY_CFLAG_DROP;
	case VIOLATION_CONTALL:
		warning("resuming all processes");
		count = pink_easy_process_list_walk(list, cont_one, &logok);
		warning("resumed %u processes, exiting", count);
		break;
	case VIOLATION_KILLALL:
		warning("killing all processes");
		count = pink_easy_process_list_walk(list, kill_one, &logok);
		warning("killed %u processes, exiting", count);
		break;
	default:
		abort();
	}

	/* exit */
	if (pandora->config.violation_exit_code > 0)
		exit(pandora->config.violation_exit_code);
	else if (!pandora->config.violation_exit_code)
		exit(128 + pandora->config.violation_exit_code);
	exit(pandora->exit_code);
}
