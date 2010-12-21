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
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>

#include "proc.h"

inline
static int
errno2retval(void)
{
	if (errno == EIO)
		return -EFAULT;
	return -errno;
}

#if !defined(SPARSE) && defined(__GNUC__) && __GNUC__ >= 3
__attribute__ ((format (printf, 2, 3)))
#endif
static void
report_violation(pink_easy_process_t *current, const char *fmt, ...)
{
	char *cmdline;
	va_list ap;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	warning("-- Access Violation! --");
	warning("process id:%lu bitness:\"%s\"", (unsigned long)pid, pink_bitness_name(bit));
	warning("cwd: `%s'", data->cwd);

	if (!proc_cmdline(pid, 128, &cmdline)) {
		warning("cmdline: `%s'", cmdline);
		free(cmdline);
	}

	va_start(ap, fmt);
	log_msg_va(1, fmt, ap);
	va_end(ap);
	log_nl(1);
}

static int
deny_syscall(const pink_easy_context_t *ctx, pink_easy_process_t *current)
{
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	data->deny = 1;
	data->ret = errno2retval();

	if (!pink_util_set_syscall(pid, bit, PINKTRACE_INVALID_SYSCALL)) {
		if (errno != ESRCH) {
			warning("pink_util_set_syscall(%d, %s, 0xbadca11): %d(%s)",
					pid, pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(ctx, current);
		}
		return PINK_EASY_CFLAG_DEAD;
	}

	return 0;
}

static int
restore_syscall(pink_easy_process_t *current)
{
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	data->deny = 0;

	/* Restore system call number */
	if (!pink_util_set_syscall(pid, bit, data->sno)) {
		if (errno == ESRCH)
			return PINK_EASY_CFLAG_DEAD;
		warning("pink_util_set_syscall(%d, %s, %s): errno:%d (%s)",
				pid, pink_bitness_name(bit),
				pink_name_syscall(data->sno, bit),
				errno, strerror(errno));
	}

	/* Return the saved return value */
	if (!pink_util_set_return(pid, data->ret)) {
		if (errno == ESRCH)
			return PINK_EASY_CFLAG_DEAD;
		warning("pink_util_set_return(%d, %s, %s): errno:%d (%s)",
				pid, pink_bitness_name(bit),
				pink_name_syscall(data->sno, bit),
				errno, strerror(errno));
	}

	return 0;
}

static int
update_cwd(const pink_easy_context_t *ctx, pink_easy_process_t *current)
{
	int r;
	long ret;
	char *cwd;
	pid_t pid = pink_easy_process_get_pid(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	data->chdir = 0;

	/* Check the return value */
	if (!pink_util_get_return(pid, &ret)) {
		if (errno != ESRCH) {
			warning("pink_util_get_return(%lu): %d(%s)",
					(unsigned long)pid,
					errno, strerror(errno));
			return panic(ctx, current);
		}
		return PINK_EASY_CFLAG_DEAD;
	}

	if (ret) {
		/* Unsuccessful chdir() */
		return 0;
	}

	if ((r = proc_cwd(pid, &cwd)) < 0) {
		warning("proc_cwd(%lu): %d(%s)",
				(unsigned long)pid,
				-r, strerror(-r));
		return panic(ctx, current);
	}

	free(data->cwd);
	data->cwd = cwd;
	return 0;
}

static short
sys_generic_check_path1(const pink_easy_context_t *ctx,
		pink_easy_process_t *current,
		const char *name,
		int create, int resolve)
{
	int ret;
	char *path, *abspath;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	ret = 0;
	path = abspath = NULL;

	errno = 0;
	path = pink_decode_string_persistent(pid, bit, 0);
	if (errno)
		return (errno = ESRCH) ? PINK_EASY_CFLAG_DEAD : deny_syscall(ctx, current);
	else if (!path) {
		errno = EFAULT;
		return deny_syscall(ctx, current);
	}

	ret = box_resolve_path(path, data->cwd, pid, create > 0, resolve, &abspath);
	if (ret < 0) {
		errno = -ret;
		ret = deny_syscall(ctx, current);
		goto fail;
	}

	if (!box_allow_path(abspath, data->config.allow.path)) {
		struct stat buf;

		if (create > 1 && !stat(abspath, &buf)) {
			/* The system call *must* create the path and it
			 * exists, deny with EEXIST and don't report a
			 * violation. Useful for cases like:
			 * mkdir -p /foo/bar/baz
			 */
			errno = EEXIST;
		}
		else {
			errno = EPERM;
			report_violation(current, "%s(\"%s\")", name, path);
		}
		ret = deny_syscall(ctx, current);
		goto fail;
	}

	free(path);
	free(abspath);
	return 0;

fail:
	if (path)
		free(path);
	if (abspath)
		free(abspath);
	return ret;
}

static short
sys_chmod(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data;

	data = pink_easy_process_get_data(current);
	if (!data->config.core.sandbox_path)
		return 0;

	return sys_generic_check_path1(ctx, current, name, 0, 1);
}

static short
sys_chown(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data;

	data = pink_easy_process_get_data(current);
	if (!data->config.core.sandbox_path)
		return 0;

	return sys_generic_check_path1(ctx, current, name, 0, 1);
}

static short
sys_open(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	pid_t pid;
	pink_bitness_t bit;
	long flags;
	proc_data_t *data;

	pid = pink_easy_process_get_pid(current);
	bit = pink_easy_process_get_bitness(current);
	data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	/* Check mode argument first */
	if (!pink_util_get_arg(pid, bit, 1, &flags))
		return (errno == ESRCH) ? PINK_EASY_CFLAG_DEAD : deny_syscall(ctx, current);
	if (!(flags & (O_WRONLY | O_RDWR)))
		return 0;

	return sys_generic_check_path1(ctx, current, name, flags & O_CREAT, 1);
}

static short
sys_creat(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	return sys_generic_check_path1(ctx, current, name, 1, 1);
}

static short
sys_lchown(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	return sys_generic_check_path1(ctx, current, name, 0, 0);
}

static short
sys_mkdir(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	return sys_generic_check_path1(ctx, current, name, 2, 1);
}

static short
sys_mknod(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	return sys_generic_check_path1(ctx, current, name, 2, 1);
}

static short
sys_rmdir(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	return sys_generic_check_path1(ctx, current, name, 0, 0);
}

static short
sys_truncate(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	return sys_generic_check_path1(ctx, current, name, 0, 1);
}

static short
sys_umount(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	return sys_generic_check_path1(ctx, current, name, 0, 1);
}

static short
sys_umount2(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	return sys_generic_check_path1(ctx, current, name, 0, 1);
}

static short
sys_utime(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	return sys_generic_check_path1(ctx, current, name, 0, 1);
}

static short
sys_utimes(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	return sys_generic_check_path1(ctx, current, name, 0, 1);
}

static short
sys_unlink(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	return sys_generic_check_path1(ctx, current, name, 0, 0);
}

static short
sys_chdir(PINK_UNUSED const pink_easy_context_t *ctx, pink_easy_process_t *current, PINK_UNUSED const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);
	data->chdir = 1;
	return 0;
}

static short
sys_stat(PINK_UNUSED const pink_easy_context_t *ctx, pink_easy_process_t *current, PINK_UNUSED const char *name)
{
	int ret;
	char *path;
	struct stat buf;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	if (data->config.core.magic_lock == LOCK_SET) {
		/* No magic allowed! */
		return 0;
	}

	errno = 0;
	path = pink_decode_string_persistent(pid, bit, 0);
	if (!path) {
		/* Don't bother denying the system call here.
		 * Because this should not be a fatal error.
		 */
		return (errno == ESRCH) ? PINK_EASY_CFLAG_DEAD : 0;
	}

	ret = magic_cast_string(current, path, 1);
	free(path);
	if (ret < 0) {
		switch (ret) {
		case MAGIC_ERROR_INVALID_KEY:
		case MAGIC_ERROR_INVALID_TYPE:
		case MAGIC_ERROR_INVALID_VALUE:
			errno = EINVAL;
			break;
		case MAGIC_ERROR_OOM:
			errno = ENOMEM;
			break;
		default:
			errno = 0;
			break;
		}
		return deny_syscall(ctx, current);
	}
	else if (ret > 0) {
		/* Encode stat buffer */
		memset(&buf, 0, sizeof(struct stat));
		buf.st_mode = S_IFCHR | (S_IRUSR | S_IWUSR) | (S_IRGRP | S_IWGRP) | (S_IROTH | S_IWOTH);
		buf.st_rdev = 259; /* /dev/null */
		buf.st_mtime = -842745600; /* ;) */
		pink_encode_simple(pid, bit, 1, &buf, sizeof(struct stat));
		errno = 0;
		return deny_syscall(ctx, current);
	}

	return 0;
}

void
sysinit(void)
{
	systable_add("chmod", sys_chmod);
	systable_add("chown", sys_chown);
	systable_add("chown32", sys_chown);
	systable_add("open", sys_open);
	systable_add("creat", sys_creat);
	systable_add("lchown", sys_lchown);
	systable_add("lchown32", sys_lchown);
	systable_add("mkdir", sys_mkdir);
	systable_add("mknod", sys_mknod);
	systable_add("rmdir", sys_rmdir);
	systable_add("truncate", sys_truncate);
	systable_add("truncate64", sys_truncate);
	systable_add("umount", sys_umount);
	systable_add("umount2", sys_umount2);
	systable_add("utime", sys_utime);
	systable_add("utimes", sys_utimes);
	systable_add("unlink", sys_unlink);

	/* chdir() and fchdir() require special attention */
	systable_add("chdir", sys_chdir);
	systable_add("fchdir", sys_chdir);

	/* The rest is magic! */
	systable_add("stat", sys_stat);
	systable_add("stat64", sys_stat);
	systable_add("lstat", sys_stat);
	systable_add("lstat64", sys_stat);
}

int
sysenter(const pink_easy_context_t *ctx, pink_easy_process_t *current)
{
	long no;
	pid_t pid;
	pink_bitness_t bit;
	proc_data_t *data;
	const sysentry_t *entry;

	pid = pink_easy_process_get_pid(current);
	bit = pink_easy_process_get_bitness(current);
	data = pink_easy_process_get_data(current);

	if (!pink_util_get_syscall(pid, bit, &no)) {
		if (errno != ESRCH) {
			warning("pink_util_get_syscall(%d, %s, &no): %d(%s)",
					pid, pink_bitness_name(bit),
					errno, strerror(errno));
			warning("panic! killing process:%d", pid);
			pink_trace_kill(pid);
		}
		return PINK_EASY_CFLAG_DEAD;
	}

	data->sno = no;
	entry = systable_lookup(no, bit);
	return entry ? entry->func(ctx, current, entry->name) : 0;
}

int sysexit(PINK_UNUSED const pink_easy_context_t *ctx, pink_easy_process_t *current)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (data->chdir) {
		/* Process is exiting a system call which may have changed the
		 * current working directory. */
		return update_cwd(ctx, current);
	}

	if (data->deny) {
		/* Process is exiting a denied system call! */
		return restore_syscall(current);
	}

	return 0;
}
