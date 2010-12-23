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
#include <string.h>

#include "proc.h"

inline
static int
open_check(long flags, sysinfo_t *info)
{
	assert(info);

	/* The flag combinations we care about:
	 * - O_RDONLY | O_CREAT
	 * - O_WRONLY
	 * - O_RDWR
	 */
	if (!(flags & (O_RDONLY | O_CREAT)) && !(flags & (O_WRONLY | O_RDWR)))
		return 0;

	info->resolv = 1;
	info->create = flags & O_CREAT ? 1 : 0;
	if (flags & O_EXCL) {
		if (!info->create) {
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
			++info->create, --info->resolv;
		}
	}

	return 1;
}

static int
update_cwd(pink_easy_process_t *current)
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
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (ret) {
		/* Unsuccessful chdir() */
		return 0;
	}

	if ((r = proc_cwd(pid, &cwd)) < 0) {
		warning("proc_cwd(%lu): %d(%s)",
				(unsigned long)pid,
				-r, strerror(-r));
		return panic(current);
	}

	free(data->cwd);
	data->cwd = cwd;
	return 0;
}

static int
sys_chmod(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_chown(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_open(pink_easy_process_t *current, const char *name)
{
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);
	sysinfo_t info;

	if (!data->config.core.sandbox.path)
		return 0;

	/* Check mode argument first */
	if (!pink_util_get_arg(pid, bit, 1, &flags)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 1): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	memset(&info, 0, sizeof(sysinfo_t));
	if (!open_check(flags, &info))
		return 0;

	return box_check_path(current, name, &info);
}

static int
sys_creat(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.create = 1;
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_lchown(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.create = 2;
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_mkdir(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.create = 2;
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_mknod(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.create = 2;
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_rmdir(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_truncate(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_umount(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_umount2(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_utime(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_utimes(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_unlink(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));

	return box_check_path(current, name, &info);
}

static int
sys_link(pink_easy_process_t *current, const char *name)
{
	int ret;
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));

	ret = box_check_path(current, name, &info);
	if (!ret && !data->deny) {
		info.index  = 1;
		info.create = 2;
		return box_check_path(current, name, &info);
	}

	return 0;
}

static int
sys_rename(pink_easy_process_t *current, const char *name)
{
	int ret;
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));

	ret = box_check_path(current, name, &info);
	if (!ret && !data->deny) {
		info.index  = 1;
		info.create = 1;
		return box_check_path(current, name, &info);
	}

	return 0;
}

static int
sys_symlink(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.index  = 1;
	info.create = 2;

	return box_check_path(current, name, &info);
}

static int
sys_mount(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.index  = 1;
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_openat(pink_easy_process_t *current, const char *name)
{
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);
	sysinfo_t info;

	if (!data->config.core.sandbox.path)
		return 0;

	/* Check mode argument first */
	if (!pink_util_get_arg(pid, bit, 2, &flags)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 2): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	memset(&info, 0, sizeof(sysinfo_t));
	info.at = 1;
	info.index = 1;
	if (!open_check(flags, &info))
		return 0;

	return box_check_path(current, name, &info);
}

static int
sys_mkdirat(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.at     = 1;
	info.index  = 1;
	info.create = 2;
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_mknodat(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.at     = 1;
	info.index  = 1;
	info.create = 2;
	info.resolv = 1;

	return box_check_path(current, name, &info);
}

static int
sys_fchmodat(pink_easy_process_t *current, const char *name)
{
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);
	sysinfo_t info;

	if (!data->config.core.sandbox.path)
		return 0;

	/* Check for AT_SYMLINK_NOFOLLOW */
	if (!pink_util_get_arg(pid, bit, 3, &flags)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 3): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	memset(&info, 0, sizeof(sysinfo_t));
	info.at     = 1;
	info.index  = 1;
	info.resolv = flags & AT_SYMLINK_NOFOLLOW ? 0 : 1;

	return box_check_path(current, name, &info);
}

static int
sys_fchownat(pink_easy_process_t *current, const char *name)
{
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);
	sysinfo_t info;

	if (!data->config.core.sandbox.path)
		return 0;

	/* Check for AT_SYMLINK_FOLLOW */
	if (!pink_util_get_arg(pid, bit, 4, &flags)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 4): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	memset(&info, 0, sizeof(sysinfo_t));
	info.at     = 1;
	info.index  = 1;
	info.resolv = flags & AT_SYMLINK_FOLLOW ? 1 : 0;

	return box_check_path(current, name, &info);
}

static int
sys_unlinkat(pink_easy_process_t *current, const char *name)
{
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);
	sysinfo_t info;

	if (!data->config.core.sandbox.path)
		return 0;

	/* If AT_REMOVEDIR flag is set in the third argument, unlinkat()
	 * behaves like rmdir(2), otherwise it behaves like unlink(2).
	 * The difference between the two system calls is, the former resolves
	 * symbolic links, whereas the latter doesn't.
	 */
	if (!pink_util_get_arg(pid, bit, 2, &flags)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 2): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	memset(&info, 0, sizeof(sysinfo_t));
	info.at     = 1;
	info.index  = 1;
	info.resolv = flags & AT_REMOVEDIR ? 1 : 0;

	return box_check_path(current, name, &info);
}

static int
sys_symlinkat(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.at     = 1;
	info.index  = 2;
	info.create = 2;

	return box_check_path(current, name, &info);
}

static int
sys_renameat(pink_easy_process_t *current, const char *name)
{
	int ret;
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.at     = 1;
	info.index  = 1;

	ret = box_check_path(current, name, &info);
	if (!ret && !data->deny) {
		info.index  = 3;
		info.create = 1;
		ret = box_check_path(current, name, &info);
	}

	return ret;
}

static int
sys_linkat(pink_easy_process_t *current, const char *name)
{
	int ret;
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);
	sysinfo_t info;

	if (!data->config.core.sandbox.path)
		return 0;

	/* Check for AT_SYMLINK_FOLLOW */
	if (!pink_util_get_arg(pid, bit, 4, &flags)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 4): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	memset(&info, 0, sizeof(sysinfo_t));
	info.at     = 1;
	info.index  = 1;
	info.resolv = flags & AT_SYMLINK_FOLLOW ? 1 : 0;

	ret = box_check_path(current, name, &info);
	if (!ret && !data->deny) {
		info.index  = 3;
		info.create = 1;
		ret = box_check_path(current, name, &info);
	}

	return ret;
}

static int
sys_execve(pink_easy_process_t *current, const char *name)
{
	int ret;
	char *abspath;
	proc_data_t *data = pink_easy_process_get_data(current);
	sysinfo_t info;

	/* Handling core.trace.kill_if_match and core.trace.resume_if_match:
	 *
	 * Resolve and save the path argument in data->exec_abspath.
	 * When we receive a PINK_EVENT_EXEC which means execve() was
	 * successful, we'll check for kill_if_match and resume_if_match lists
	 * and kill or resume the process as necessary.
	 */
	memset(&info, 0, sizeof(sysinfo_t));
	info.buf    = &abspath;
	info.resolv = 1;
	ret = box_check_path(current, name, &info);
	if (ret) {
		/* Resolving path failed! */
		return ret;
	}
	data->exec_abspath = abspath;

	if (!data->config.core.sandbox.exec)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.abspath = abspath;
	info.allow   = data->config.allow.exec;
	info.resolv  = 1;
	info.deny_errno = EACCES;

	ret = box_check_path(current, name, &info);
	return ret;
}

static int
sys_chdir(pink_easy_process_t *current, PINK_UNUSED const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);
	data->chdir = 1;
	return 0;
}

static int
sys_stat(pink_easy_process_t *current, PINK_UNUSED const char *name)
{
	int ret;
	char *path;
	struct stat buf;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	if (data->config.core.trace.magic_lock == LOCK_SET) {
		/* No magic allowed! */
		return 0;
	}

	errno = 0;
	path = pink_decode_string_persistent(pid, bit, 0);
	if (errno || !path) {
		/* Don't bother denying the system call here.
		 * Because this should not be a fatal error.
		 */
		return (errno == ESRCH) ? PINK_EASY_CFLAG_DROP : 0;
	}

	ret = magic_cast_string(current, path, 1);
	if (ret < 0) {
		warning("failed to cast magic \"%s\": %s", path, magic_strerror(ret));
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
		ret = deny(current);
	}
	else if (ret > 0) {
		/* Encode stat buffer */
		memset(&buf, 0, sizeof(struct stat));
		buf.st_mode = S_IFCHR | (S_IRUSR | S_IWUSR) | (S_IRGRP | S_IWGRP) | (S_IROTH | S_IWOTH);
		buf.st_rdev = 259; /* /dev/null */
		buf.st_mtime = -842745600; /* ;) */
		pink_encode_simple(pid, bit, 1, &buf, sizeof(struct stat));
		message("magic \"%s\" accepted", path);
		errno = 0;
		ret = deny(current);
	}

	free(path);
	return ret;
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

	/* "at" suffixed functions */
	systable_add("openat", sys_openat);
	systable_add("mkdirat", sys_mkdirat);
	systable_add("mknodat", sys_mknodat);
	systable_add("fchmodat", sys_fchmodat);
	systable_add("fchownat", sys_fchownat);
	systable_add("unlinkat", sys_unlinkat);
	systable_add("symlinkat", sys_symlinkat);
	systable_add("renameat", sys_renameat);
	systable_add("linkat", sys_linkat);

	/* execve() sandboxing */
	systable_add("execve", sys_execve);

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
sysenter(pink_easy_process_t *current)
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
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	data->sno = no;
	entry = systable_lookup(no, bit);
	return entry ? entry->func(current, entry->name) : 0;
}

int sysexit(pink_easy_process_t *current)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (data->chdir) {
		/* Process is exiting a system call which may have changed the
		 * current working directory. */
		return update_cwd(current);
	}

	if (data->deny) {
		/* Process is exiting a denied system call! */
		return restore(current);
	}

	return 0;
}
