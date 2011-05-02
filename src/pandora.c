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

/*
 * The function pandora_attach_all() is based in part upon strace which is:
 *
 * Copyright (c) 1991, 1992 Paul Kranenburg <pk@cs.few.eur.nl>
 * Copyright (c) 1993 Branko Lankester <branko@hacktic.nl>
 * Copyright (c) 1993, 1994, 1995, 1996 Rick Sladkey <jrs@world.std.com>
 * Copyright (c) 1996-1999 Wichert Akkerman <wichert@cistron.nl>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "pandora-defs.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/queue.h>

#include "macro.h"
#include "util.h"

pandora_t *pandora = NULL;

static void
about(void)
{
	printf(PACKAGE"-"VERSION GITHEAD"\n");
}

PINK_GCC_ATTR((noreturn))
static void
usage(FILE *outfp, int code)
{
	fprintf(outfp, "\
"PACKAGE"-"VERSION GITHEAD" -- Pandora's Box\n\
usage: "PACKAGE" [-hVv] [-c pathspec...] [-m magic...] {-p pid...}\n\
   or: "PACKAGE" [-hVv] [-c pathspec...] [-m magic...] [-E var=val...] {command [arg...]}\n\
-h          -- Show usage and exit\n\
-V          -- Show version and exit\n\
-v          -- Be verbose, may be repeated\n\
-c pathspec -- path spec to the configuration file, may be repeated\n\
-m magic    -- run a magic command during init, may be repeated\n\
-p pid      -- trace processes with process id, may be repeated\n\
-E var=val  -- put var=val in the environment for command, may be repeated\n\
-E var      -- remove var from the environment for command, may be repeated\n");
	exit(code);
}

static void
pandora_init(void)
{
	assert(!pandora);

	pandora = xmalloc(sizeof(pandora_t));
	pandora->eldest = -1;
	pandora->exit_code = 0;
	pandora->violation = false;
	pandora->ctx = NULL;
	config_init();
}

static void
pandora_destroy(void)
{
	struct snode *node;

	assert(pandora);

	/* Free the global configuration */
	free_sandbox(&pandora->config.child);

	SLIST_FLUSH(node, &pandora->config.exec_kill_if_match, up, free);
	SLIST_FLUSH(node, &pandora->config.exec_resume_if_match, up, free);

	SLIST_FLUSH(node, &pandora->config.filter_exec, up, free);
	SLIST_FLUSH(node, &pandora->config.filter_path, up, free);
	SLIST_FLUSH(node, &pandora->config.filter_sock, up, free_sock_match);

	pink_easy_context_destroy(pandora->ctx);

	free(pandora);
	pandora = NULL;

	systable_free();
	log_close();
}

static void
sig_cleanup(int signo)
{
	struct sigaction sa;

	fprintf(stderr, "\ncaught signal %d exiting\n", signo);

	abort_all();

	sigaction(signo, NULL, &sa);
	sa.sa_handler = SIG_DFL;
	sigaction(signo, &sa, NULL);
	raise(signo);
}

static bool
dump_one_process(pink_easy_process_t *current, void *userdata)
{
	pid_t pid = pink_easy_process_get_pid(current);
	pid_t ppid = pink_easy_process_get_ppid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	struct snode *node;

	fprintf(stderr, "-- Process ID: %lu\n", (unsigned long)pid);
	fprintf(stderr, "   Parent Process ID: %lu\n", ppid > 0 ? (unsigned long)ppid : 0UL);
	fprintf(stderr, "   Bitness: %s\n", pink_bitness_name(bit));
	fprintf(stderr, "   Attach: %s\n", pink_easy_process_is_attached(current) ? "true" : "false");
	fprintf(stderr, "   Clone: %s\n", pink_easy_process_is_clone(current) ? "true" : "false");
	fprintf(stderr, "   Comm: %s\n", data->comm);
	fprintf(stderr, "   Cwd: %s\n", data->cwd);
	fprintf(stderr, "   Syscall: {no:%lu name:%s}\n", data->sno, pink_name_syscall(data->sno, bit));

	if (!PTR_TO_UINT(userdata))
		return true;

	fprintf(stderr, "--> Sandbox: {exec:%s path:%s sock:%s}\n",
			data->config.sandbox_exec ? "true" : "false",
			data->config.sandbox_path ? "true" : "false",
			data->config.sandbox_sock ? "true" : "false");
	fprintf(stderr, "    Magic Lock: %s\n",
			data->config.magic_lock == LOCK_UNSET ? "unset" :
			data->config.magic_lock == LOCK_SET ? "set" : "pending");
	fprintf(stderr, "    Exec Whitelist:\n");
	SLIST_FOREACH(node, &data->config.whitelist_exec, up)
		fprintf(stderr, "      \"%s\"\n", (char *)node->data);
	fprintf(stderr, "    Path Whitelist:\n");
	SLIST_FOREACH(node, &data->config.whitelist_path, up)
		fprintf(stderr, "      \"%s\"\n", (char *)node->data);
	/* TODO:  SLIST_FOREACH(node, data->config.whitelist_sock, up) */

	return true;
}

static void
sig_user(int signo)
{
	bool cmpl;
	unsigned c;
	pink_easy_process_list_t *list;

	if (!pandora)
		return;

	cmpl = signo == SIGUSR2;
	list = pink_easy_context_get_process_list(pandora->ctx);

	fprintf(stderr, "\nReceived SIGUSR%s, dumping %sprocess tree\n",
			cmpl ? "2" : "1",
			cmpl ? "complete " : "");
	c = pink_easy_process_list_walk(list, dump_one_process, UINT_TO_PTR(cmpl));
	fprintf(stderr, "Tracing %u process%s\n", c, c > 1 ? "es" : "");
}

static unsigned
pandora_attach_all(pid_t pid)
{
	char *ptask;
	DIR *dir;

	if (!pandora->config.follow_fork)
		goto one;

	/* Read /proc/$pid/task and attach to all threads */
	xasprintf(&ptask, "/proc/%lu/task", (unsigned long)pid);
	dir = opendir(ptask);
	free(ptask);

	if (dir) {
		unsigned ntid = 0, nerr = 0;
		struct dirent *de;
		pid_t tid;

		while ((de = readdir(dir))) {
			if (de->d_fileno == 0)
				continue;
			if (parse_pid(de->d_name, &tid) < 0)
				continue;
			++ntid;
			if (pink_easy_attach(pandora->ctx, tid, tid != pid ? pid : -1) < 0) {
				warning("failed to attach to tid:%lu (errno:%d %s)",
						(unsigned long)tid,
						errno, strerror(errno));
				++nerr;
			}

		}
		closedir(dir);
		ntid -= nerr;
		return ntid;
	}

	warning("failed to open /proc/%lu/task (errno:%d %s)",
			(unsigned long)pid,
			errno, strerror(errno));
one:
	if (pink_easy_attach(pandora->ctx, pid, -1) < 0) {
		warning("failed to attach process:%lu (errno:%d %s)",
				(unsigned long)pid,
				errno, strerror(errno));
		return 0;
	}
	return 1;
}

int
main(int argc, char **argv)
{
	int opt, ptrace_options, ret;
	unsigned pid_count;
	pid_t pid;
	pid_t *pid_list;
	const char *env;
	struct sigaction sa;

	/* Initialize Pandora */
	pandora_init();

	/* Allocate pids array */
	pid_count = 0;
	pid_list = xmalloc(argc * sizeof(pid_t));

	while ((opt = getopt(argc, argv, "hVvc:m:p:E:")) != EOF) {
		switch (opt) {
		case 'h':
			usage(stdout, 0);
		case 'V':
			about();
			return 0;
		case 'v':
			++pandora->config.log_level;
			break;
		case 'c':
			config_reset();
			config_parse_spec(optarg);
			break;
		case 'm':
			ret = magic_cast_string(NULL, optarg, 0);
			if (ret < 0)
				die(1, "invalid magic: `%s': %s", optarg, magic_strerror(ret));
			break;
		case 'p':
			if ((ret = parse_pid(optarg, &pid)) < 0) {
				errno = -ret;
				die_errno(1, "invalid process id `%s'", optarg);
			}
			if (pid == getpid())
				die(1, "tracing self is not possible");

			pid_list[pid_count++] = pid;
			break;
		case 'E':
			if (putenv(optarg))
				die_errno(1, "putenv");
			break;
		default:
			usage(stderr, 1);
		}
	}

	if ((optind == argc) && !pid_count)
		usage(stderr, 1);

	if ((env = getenv(PANDORA_CONFIG_ENV))) {
		config_reset();
		config_parse_spec(env);
	}

	/* Initialize logging */
	log_init();

	/* Configuration is done */
	config_destroy();

	/* Initialize callbacks */
	callback_init();
	systable_init();
	sysinit();

	ptrace_options = PINK_TRACE_OPTION_SYSGOOD | PINK_TRACE_OPTION_EXEC | PINK_TRACE_OPTION_EXIT;
	if (pandora->config.follow_fork)
		ptrace_options |= (PINK_TRACE_OPTION_FORK | PINK_TRACE_OPTION_VFORK | PINK_TRACE_OPTION_CLONE);

	if (!(pandora->ctx = pink_easy_context_new(ptrace_options, &pandora->callback_table, NULL, NULL)))
		die_errno(-1, "pink_easy_context_new");

	if (!pid_count) {
		free(pid_list);

		if (pink_easy_execvp(pandora->ctx, argv[optind], &argv[optind]))
			die(1, "failed to execute child process");
	}
	else {
		unsigned npid = 0;
		for (unsigned i = 0; i < pid_count; i++)
			npid += pandora_attach_all(pid_list[i]);
		if (!npid)
			die(1, "failed to attach to any process");
		free(pid_list);
	}

	/* Handle signals */
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = 0;

	sa.sa_handler = SIG_IGN;
	sigaction(SIGTTOU, &sa, NULL);
	sigaction(SIGTTIN, &sa, NULL);

	sa.sa_handler = sig_cleanup;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGPIPE, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);

	sa.sa_handler = sig_user;
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);

	sa.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &sa, NULL);

	ret = pink_easy_loop(pandora->ctx);
	pandora_destroy();
	return ret;
}
