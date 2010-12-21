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
#include <assert.h>
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

inline
static int
open_check(long flags, int *create, int *resolve)
{
	int c, r;

	assert(create);
	assert(resolve);

	/* The flag combinations we care about:
	 * - O_RDONLY | O_CREAT (stupid, but creates the path)
	 * - O_WRONLY
	 * - O_RDWR
	 */
	if (!(flags & (O_RDONLY | O_CREAT)) && !(flags & (O_WRONLY | O_RDWR)))
		return 0;

	r = 1;
	c = flags & O_CREAT ? 1 : 0;
	if (flags & O_EXCL) {
		if (!c) {
			/* Quoting open(2):
			 * In general, the behavior of O_EXCL is undefined if
			 * it is used without O_CREAT.  There is one exception:
			 * on Linux 2.6 and later, O_EXCL can be used without
			 * O_CREAT if pathname refers to a block device. If
			 * the block device is in use by the system (e.g.,
			 * mounted),  open()  fails.
			 */
			/* void */;
		}
		else {
			/* Two things to mention here:
			 * - If O_EXCL is specified in conjunction with
			 *   O_CREAT, and pathname already exists, then open()
			 *   will fail.
			 * - When both O_CREAT and O_EXCL are specified,
			 *   symbolic links are not followed.
			 */
			++c, --r;
		}
	}

	*create = c;
	*resolve = r;
	return 1;
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

#define SYS_GENERIC_CHECK_PATH1(ctx, current, name, create, resolve) \
	sys_generic_check_path((ctx), (current), (name), NULL, 0, (create), (resolve))
#define SYS_GENERIC_CHECK_PATH2(ctx, current, name, create, resolve) \
	sys_generic_check_path((ctx), (current), (name), NULL, 1, (create), (resolve))
static short
sys_generic_check_path(const pink_easy_context_t *ctx,
		pink_easy_process_t *current,
		const char *name,
		const char *prefix,
		unsigned ind,
		int create, int resolve)
{
	short ret;
	int r;
	char *path, *abspath;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	ret = 0;
	path = abspath = NULL;

	errno = 0;
	path = pink_decode_string_persistent(pid, bit, ind);
	if (errno)
		return (errno = ESRCH) ? PINK_EASY_CFLAG_DEAD : deny_syscall(ctx, current);
	else if (!path) {
		errno = EFAULT;
		if (!config->core.ignore_safe_violations)
			goto report;
		ret = deny_syscall(ctx, current);
		goto end;
	}

	if ((r = box_resolve_path(path, prefix ? prefix : data->cwd, pid, create > 0, resolve, &abspath)) < 0) {
		errno = -r;
		if (!config->core.ignore_safe_violations)
			goto report;
		ret = deny_syscall(ctx, current);
		goto end;
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
			if (!config->core.ignore_safe_violations)
				goto report;
		}
		else {
			errno = EPERM;
report:
			switch (ind) {
			case 0:
				report_violation(current, "%s(\"%s\")", name, path);
				break;
			case 1:
				report_violation(current, "%s(?, \"%s\", prefix=\"%s\")",
						name, path, prefix ? prefix : "");
				break;
			case 2:
				report_violation(current, "%s(?, ?, \"%s\", prefix=\"%s\")",
						name, path, prefix ? prefix : "");
				break;
			case 3:
				report_violation(current, "%s(?, ?, ?, \"%s\", prefix=\"%s\")",
						name, path, prefix ? prefix : "");
				break;
			default:
				abort();
			}
			ret = violation(ctx, current);
			if (ret)
				goto end;
		}
		ret = deny_syscall(ctx, current);
	}

end:
	if (path)
		free(path);
	if (abspath)
		free(abspath);
	return ret;
}

#define SYS_GENERIC_CHECK_PATH_AT1(ctx, current, name, create, resolve) \
	sys_generic_check_path_at((ctx), (current), (name), 1, (create), (resolve))
#define SYS_GENERIC_CHECK_PATH_AT2(ctx, current, name, create, resolve) \
	sys_generic_check_path_at((ctx), (current), (name), 2, (create), (resolve))
#define SYS_GENERIC_CHECK_PATH_AT3(ctx, current, name, create, resolve) \
	sys_generic_check_path_at((ctx), (current), (name), 3, (create), (resolve))
static short
sys_generic_check_path_at(const pink_easy_context_t *ctx,
		pink_easy_process_t *current,
		const char *name,
		unsigned ind,
		int create, int resolve)
{
	short ret;
	int r;
	long dfd;
	char *prefix;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	/* Decode the dirfd argument */
	if (!pink_util_get_arg(pid, bit, ind - 1, &dfd))
		return (errno == ESRCH) ? PINK_EASY_CFLAG_DEAD : deny_syscall(ctx, current);

	prefix = NULL;
	if (dfd < 0) {
		errno = EBADF;
		return deny_syscall(ctx, current);
	}
	else if (dfd != AT_FDCWD) {
		if ((r = proc_fd(pid, dfd, &prefix)) < 0) {
			errno = r == -ENOENT ? EBADF : -r;
			return deny_syscall(ctx, current);
		}
	}

	ret = sys_generic_check_path(ctx, current, name, prefix ? prefix : data->cwd, ind, create, resolve);
	if (prefix)
		free(prefix);
	return ret;
}

static short
sys_chmod(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 1);
}

static short
sys_chown(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 1);
}

static short
sys_open(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	int c, r;
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	/* Check mode argument first */
	if (!pink_util_get_arg(pid, bit, 1, &flags))
		return (errno == ESRCH) ? PINK_EASY_CFLAG_DEAD : deny_syscall(ctx, current);

	if (!open_check(flags, &c, &r))
		return 0;

	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, c, r);
}

static short
sys_creat(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, 1, 1);
}

static short
sys_lchown(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 0);
}

static short
sys_mkdir(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, 2, 1);
}

static short
sys_mknod(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, 2, 1);
}

static short
sys_rmdir(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 1);
}

static short
sys_truncate(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 1);
}

static short
sys_umount(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 1);
}

static short
sys_umount2(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 1);
}

static short
sys_utime(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 1);
}

static short
sys_utimes(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 1);
}

static short
sys_unlink(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 0);
}

static short
sys_link(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	short ret;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	ret = SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 0);
	if (!ret && !data->deny)
		return SYS_GENERIC_CHECK_PATH2(ctx, current, name, 2, 0);
	return 0;
}

static short
sys_rename(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	short ret;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	ret = SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 0);
	if (!ret && !data->deny)
		return SYS_GENERIC_CHECK_PATH2(ctx, current, name, 1, 0);
	return 0;
}

static short
sys_symlink(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	short ret;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	ret = SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 0);
	if (!ret && !data->deny)
		return SYS_GENERIC_CHECK_PATH2(ctx, current, name, 2, 0);
	return 0;
}

static short
sys_mount(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH2(ctx, current, name, 0, 1);
}

static short
sys_openat(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	int c, r;
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	/* Check mode argument first */
	if (!pink_util_get_arg(pid, bit, 2, &flags))
		return (errno == ESRCH) ? PINK_EASY_CFLAG_DEAD : deny_syscall(ctx, current);

	if (!open_check(flags, &c, &r))
		return 0;

	return SYS_GENERIC_CHECK_PATH_AT1(ctx, current, name, c, r);
}

static short
sys_mkdirat(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH_AT1(ctx, current, name, 2, 1);
}

static short
sys_mknodat(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	return SYS_GENERIC_CHECK_PATH_AT1(ctx, current, name, 2, 1);
}

static short
sys_fchmodat(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	/* Check for AT_SYMLINK_NOFOLLOW */
	if (!pink_util_get_arg(pid, bit, 3, &flags))
		return (errno == ESRCH) ? PINK_EASY_CFLAG_DEAD : deny_syscall(ctx, current);

	return SYS_GENERIC_CHECK_PATH_AT1(ctx, current, name, 0, !(flags & AT_SYMLINK_NOFOLLOW));
}

static short
sys_fchownat(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	/* Check for AT_SYMLINK_FOLLOW */
	if (!pink_util_get_arg(pid, bit, 4, &flags))
		return (errno == ESRCH) ? PINK_EASY_CFLAG_DEAD : deny_syscall(ctx, current);

	return SYS_GENERIC_CHECK_PATH_AT1(ctx, current, name, 0, flags & AT_SYMLINK_FOLLOW);
}

static short
sys_unlinkat(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	/* If AT_REMOVEDIR flag is set in the third argument, unlinkat()
	 * behaves like rmdir(2), otherwise it behaves like unlink(2).
	 * The difference between the two system calls is, the former resolves
	 * symbolic links, whereas the latter doesn't.
	 */
	if (!pink_util_get_arg(pid, bit, 2, &flags))
		return (errno == ESRCH) ? PINK_EASY_CFLAG_DEAD : deny_syscall(ctx, current);

	return SYS_GENERIC_CHECK_PATH_AT1(ctx, current, name, 0, flags & AT_REMOVEDIR);
}

static short
sys_symlinkat(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	short ret;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	ret = SYS_GENERIC_CHECK_PATH1(ctx, current, name, 0, 0);
	if (!ret && !data->deny)
		return SYS_GENERIC_CHECK_PATH_AT2(ctx, current, name, 2, 0);
	return 0;
}

static short
sys_renameat(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	short ret;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	ret = SYS_GENERIC_CHECK_PATH_AT1(ctx, current, name, 0, 0);
	if (!ret && !data->deny)
		return SYS_GENERIC_CHECK_PATH_AT3(ctx, current, name, 1, 0);
	return 0;
}

static short
sys_linkat(const pink_easy_context_t *ctx, pink_easy_process_t *current, const char *name)
{
	short ret;
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox_path)
		return 0;

	/* Check for AT_SYMLINK_FOLLOW */
	if (!pink_util_get_arg(pid, bit, 4, &flags))
		return (errno == ESRCH) ? PINK_EASY_CFLAG_DEAD : deny_syscall(ctx, current);

	ret = SYS_GENERIC_CHECK_PATH_AT1(ctx, current, name, 0, flags & AT_SYMLINK_FOLLOW);
	if (!ret && !data->deny)
		return SYS_GENERIC_CHECK_PATH_AT3(ctx, current, name, 1, 0);
	return 0;
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
	/* Check first argument. */
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

	/* Check first argument and if necessary second argument as well. */
	systable_add("link", sys_link);
	systable_add("rename", sys_rename);
	systable_add("symlink", sys_symlink);

	/* Check second path */
	systable_add("mount", sys_mount);

	/* First argument is dirfd and second is the path */
	systable_add("openat", sys_openat);
	systable_add("mkdirat", sys_mkdirat);
	systable_add("mknodat", sys_mknodat);
	systable_add("fchmodat", sys_fchmodat);
	systable_add("fchownat", sys_fchownat);
	systable_add("unlinkat", sys_unlinkat);

	/* Check the first argument and if necessary second & third argument as well. */
	systable_add("symlinkat", sys_symlinkat);

	/* Check the first & second argument and if necessary third & fourth
	 * argument as well. */
	systable_add("renameat", sys_renameat);
	systable_add("linkat", sys_linkat);

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
