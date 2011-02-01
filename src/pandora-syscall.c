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
#include <sys/stat.h>
#include <sys/mount.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

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
sysexit_chdir(pink_easy_process_t *current)
{
	int r;
	long ret;
	char *cwd;
	pid_t pid = pink_easy_process_get_pid(current);
	proc_data_t *data = pink_easy_process_get_data(current);

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
sysexit_bind(pink_easy_process_t *current)
{
	unsigned port;
	long fd, ret;
	sock_match_t *m;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

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
		/* Unsuccessful bind(), ignore */
		if (data->bind_abspath) {
			free(data->bind_abspath);
			data->bind_abspath = NULL;
		}
		if (data->bind_last) {
			free(data->bind_last);
			data->bind_last = NULL;
		}
		return 0;
	}

	m = xmalloc(sizeof(sock_match_t));
	m->family = data->bind_last->family;

	switch (m->family) {
	case AF_UNIX:
		if (data->bind_abspath) {
			/* Non-abstract UNIX socket */
			m->match.sa_un.abstract = 0;
			strncpy(m->match.sa_un.path, data->bind_abspath, PATH_MAX);
		}
		else {
			/* Abstract UNIX socket */
			m->match.sa_un.abstract = 1;
			strncpy(m->match.sa_un.path, data->bind_last->u.sa_un.sun_path, PATH_MAX);
		}
		m->match.sa_un.path[PATH_MAX - 1] = '\0';
		break;
	case AF_INET:
		port = ntohs(data->bind_last->u.sa_in.sin_port);
		m->match.sa_in.port[0] = m->match.sa_in.port[1] = port;
		m->match.sa_in.netmask = 32;
		memcpy(&m->match.sa_in.addr, &data->bind_last->u.sa_in.sin_addr, sizeof(struct in_addr));
		if (!port)
			goto zero;
		break;
#if PANDORA_HAVE_IPV6
	case AF_INET6:
		port = ntohs(data->bind_last->u.sa6.sin6_port);
		m->match.sa6.port[0] = m->match.sa6.port[1] = port;
		m->match.sa6.netmask = 64;
		memcpy(&m->match.sa6.addr, &data->bind_last->u.sa6.sin6_addr, sizeof(struct in6_addr));
		if (!port)
			goto zero;
		break;
#endif
	default:
		abort();
	}

	data->config.allow.sock.connect = slist_prepend(data->config.allow.sock.connect, m);
	if (!data->config.allow.sock.connect)
		die_errno(-1, "slist_prepend");

	if (data->bind_abspath) {
		free(data->bind_abspath);
		data->bind_abspath = NULL;
	}
	if (data->bind_last) {
		free(data->bind_last);
		data->bind_last = NULL;
	}

	return 0;
zero:
	if (data->bind_last) {
		free(data->bind_last);
		data->bind_last = NULL;
	}

	/* Save the file descriptor */
	if (!pink_decode_socket_fd(pid, bit, 0, &fd)) {
		if (errno != ESRCH) {
			warning("pink_decode_socket_fd(%lu, \"%s\", 0): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	ht_int64_node_t *node = hashtable_find(data->bind_zero, ++fd, 1);
	if (!node)
		die_errno(-1, "hashtable_find");
	node->data = m;

	return 0;
}

static int
sysexit_getsockname(pink_easy_process_t *current)
{
	unsigned port;
	long fd, ret;
	pink_socket_address_t psa;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

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
		/* Unsuccessful getsockname(), ignore */
		return 0;
	}

	if (!pink_decode_socket_address(pid, bit, 0, &fd, &psa)) {
		if (errno != ESRCH) {
			warning("pink_decode_socket_address(%lu, \"%s\", 0): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	ht_int64_node_t *node = hashtable_find(data->bind_zero, ++fd, 0);
	assert(node);
	sock_match_t *m = node->data;
	node->key = 0;
	node->data = NULL;

	switch (m->family) {
	case AF_INET:
		port = ntohs(psa.u.sa_in.sin_port);
		assert(port);
		m->match.sa_in.port[0] = m->match.sa_in.port[1] = port;
		break;
#if PANDORA_HAVE_IPV6
	case AF_INET6:
		port = ntohs(psa.u.sa6.sin6_port);
		assert(port);
		m->match.sa6.port[0] = m->match.sa6.port[1] = port;
		break;
#endif
	default:
		abort();
	}

	data->config.allow.sock.connect = slist_prepend(data->config.allow.sock.connect, m);
	if (!data->config.allow.sock.connect)
		die_errno(-1, "slist_prepend");

	return 0;
}

static int
sysexit_dup(pink_easy_process_t *current)
{
	long fd, ret;
	ht_int64_node_t *old_node, *new_node;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

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

	if (ret < 0) {
		/* dup() call failed, ignore */
		return 0;
	}

	if (!pink_util_get_arg(pid, bit, 0, &fd)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 0): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (!(old_node = hashtable_find(data->bind_zero, ++fd, 0))) {
		/* No such file descriptor in bind_zero */
		return 0;
	}

	if (!(new_node = hashtable_find(data->bind_zero, ++ret, 1)))
		die_errno(-1, "hashtable_find");

	new_node->data = sock_match_xdup(old_node->data);
	return 0;
}

static int
sysexit_fcntl(pink_easy_process_t *current)
{
	long cmd, fd, ret;
	ht_int64_node_t *old_node, *new_node;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

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

	if (ret < 0) {
		/* fcntl() call failed, ignore */
		return 0;
	}

	/* Check the command */
	if (!pink_util_get_arg(pid, bit, 1, &cmd)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 1): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (cmd != F_DUPFD)
		return 0;

	if (!pink_util_get_arg(pid, bit, 0, &fd)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 0): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (!(old_node = hashtable_find(data->bind_zero, ++fd, 0))) {
		/* No such file descriptor in bind_zero */
		return 0;
	}

	if (!(new_node = hashtable_find(data->bind_zero, ++ret, 1)))
		die_errno(-1, "hashtable_find");

	new_node->data = sock_match_xdup(old_node->data);
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
#ifdef UMOUNT_NOFOLLOW
	long flags;
	pid_t pid;
	pink_bitness_t bit;
#endif
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
#ifdef UMOUNT_NOFOLLOW
	/* Check for UMOUNT_NOFOLLOW */
	pid = pink_easy_process_get_pid(current);
	bit = pink_easy_process_get_bitness(current);
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
	info.resolv = flags & UMOUNT_NOFOLLOW ? 0 : 1;
#else
	info.resolv = 1;
#endif /* UMOUNT_NOFOLLOW */

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
sys_setxattr(pink_easy_process_t *current, const char *name)
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
sys_lsetxattr(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.path)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	return box_check_path(current, name, &info);
}

static int
sys_removexattr(pink_easy_process_t *current, const char *name)
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
sys_lremovexattr(pink_easy_process_t *current, const char *name)
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
sys_utimensat(pink_easy_process_t *current, const char *name)
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
sys_execve(pink_easy_process_t *current, const char *name)
{
	int r;
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
	if ((r = box_check_path(current, name, &info))) {
		/* Resolving path failed! */
		return r;
	}
	data->exec_abspath = abspath;

	if (!data->config.core.sandbox.exec)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.abspath = abspath;
	info.allow   = data->config.allow.exec;
	info.filter  = pandora->config->filter.exec;
	info.resolv  = 1;
	info.deny_errno = EACCES;

	return box_check_path(current, name, &info);
}

static int
sys_bind(pink_easy_process_t *current, const char *name)
{
	int r;
	char *unix_abspath;
	pink_socket_address_t *psa;
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.sock)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.allow  = data->config.allow.sock.bind;
	info.filter = pandora->config->filter.sock;
	info.index  = 1;
	info.create = 1;
	info.resolv = 1;
	info.deny_errno = EADDRNOTAVAIL;

	if (pandora->config->core.allow.successful_bind) {
		info.unix_abspath = &unix_abspath;
		info.addr = &psa;
	}

	r = box_check_sock(current, name, &info);

	if (pandora->config->core.allow.successful_bind && !r) {
		data->bind = 1;
		data->bind_abspath = unix_abspath;
		data->bind_last = psa;
	}

	return r;
}

static int
sys_connect(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.sock)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.allow  = data->config.allow.sock.connect;
	info.filter = pandora->config->filter.sock;
	info.index  = 1;
	info.create = 1;
	info.resolv = 1;
	info.deny_errno = ECONNREFUSED;

	return box_check_sock(current, name, &info);
}

static int
sys_sendto(pink_easy_process_t *current, const char *name)
{
	sysinfo_t info;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.sock)
		return 0;

	memset(&info, 0, sizeof(sysinfo_t));
	info.allow  = data->config.allow.sock.connect;
	info.filter = pandora->config->filter.sock;
	info.index  = 4;
	info.create = 1;
	info.resolv = 1;
	info.deny_errno = ECONNREFUSED;

	return box_check_sock(current, name, &info);
}

static int
sys_getsockname(pink_easy_process_t *current, PINK_UNUSED const char *name)
{
	long fd;
	pid_t pid;
	pink_bitness_t bit;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.sock || !data->bind_zero->size)
		return 0;

	pid = pink_easy_process_get_pid(current);
	bit = pink_easy_process_get_bitness(current);

	if (!pink_decode_socket_fd(pid, bit, 0, &fd)) {
		if (errno != ESRCH) {
			warning("pink_decode_socket_fd(%lu, \"%s\", 0): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	ht_int64_node_t *node = hashtable_find(data->bind_zero, ++fd, 0);
	if (node)
		data->getsockname = 1;

	return 0;
}

static int
sys_socketcall(pink_easy_process_t *current, PINK_UNUSED const char *name)
{
	long subcall;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!data->config.core.sandbox.sock)
		return 0;

	if (!pink_has_socketcall(bit))
		return 0;

	if (!pink_decode_socket_call(pid, bit, &subcall)) {
		if (errno != ESRCH) {
			warning("pink_decode_socketcall(%lu, \"%s\"): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (subcall == PINK_SOCKET_SUBCALL_BIND)
		return sys_bind(current, "bind");
	else if (subcall == PINK_SOCKET_SUBCALL_CONNECT)
		return sys_connect(current, "connect");
	else if (subcall == PINK_SOCKET_SUBCALL_SENDTO)
		return sys_sendto(current, "sendto");
	else if (subcall == PINK_SOCKET_SUBCALL_GETSOCKNAME)
		return sys_getsockname(current, "getsockname");
	else
		return 0;
}

static int
sys_dup(pink_easy_process_t *current, PINK_UNUSED const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!pandora->config->core.allow.successful_bind
			|| !data->config.core.sandbox.sock
			|| !data->bind_zero->size)
		return 0;

	data->dup = 1;
	return 0;
}

static int
sys_fcntl(pink_easy_process_t *current, PINK_UNUSED const char *name)
{
	proc_data_t *data = pink_easy_process_get_data(current);

	if (!pandora->config->core.allow.successful_bind
			|| !data->config.core.sandbox.sock
			|| !data->bind_zero->size)
		return 0;

	data->fcntl = 1;
	return 0;
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
		case MAGIC_ERROR_INVALID_QUERY:
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
		info("magic \"%s\" accepted", path);
		errno = (ret > 1) ? ENOENT : 0;
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
	systable_add("setxattr", sys_setxattr);
	systable_add("lsetxattr", sys_lsetxattr);
	systable_add("removexattr", sys_removexattr);
	systable_add("lremovexattr", sys_lremovexattr);

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
	systable_add("utimensat", sys_utimensat);

	/* execve() sandboxing */
	systable_add("execve", sys_execve);

	/* socket sandboxing */
	systable_add("bind", sys_bind);
	systable_add("connect", sys_connect);
	systable_add("sendto", sys_sendto);
	systable_add("getsockname", sys_getsockname);
	systable_add("socketcall", sys_socketcall);
	systable_add("dup", sys_dup);
	systable_add("dup2", sys_dup);
	systable_add("dup3", sys_dup);
	systable_add("fcntl", sys_fcntl);
	systable_add("fcntl64", sys_fcntl);

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
	const char *name;
	pid_t pid;
	pink_bitness_t bit;
	proc_data_t *data;
	const sysentry_t *entry;

	pid = pink_easy_process_get_pid(current);
	bit = pink_easy_process_get_bitness(current);
	data = pink_easy_process_get_data(current);

	if (!pink_util_get_syscall(pid, bit, &no)) {
		if (errno != ESRCH) {
			warning("pink_util_get_syscall(%d, %s): %d(%s)",
					pid, pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	data->sno = no;
	entry = systable_lookup(no, bit);
	if (entry)
		debug("process:%lu is entering system call \"%s\"",
				(unsigned long)pid,
				entry->name);
	else {
		name = pink_name_syscall(no, bit);
		trace("process:%lu is entering system call \"%s\"",
				(unsigned long)pid,
				name ? name : "???");
	}

	return entry ? entry->func(current, entry->name) : 0;
}

int
sysexit(pink_easy_process_t *current)
{
	int r = 0;
	proc_data_t *data = pink_easy_process_get_data(current);

	if (data->chdir) {
		/* Process is exiting a system call which may have changed the
		 * current working directory. */
		r = sysexit_chdir(current);
		data->chdir = 0;
	}
	else if (data->bind) {
		/* Process is exiting a bind() call which may be whitelisted
		 * for connect() */
		r = sysexit_bind(current);
		data->bind = 0;
	}
	else if (data->getsockname) {
		/* Process is exiting getsockname() call which may have
		 * revealed the real port of bind() to zero port.
		 */
		r = sysexit_getsockname(current);
		data->getsockname = 0;
	}
	else if (data->dup) {
		r = sysexit_dup(current);
		data->dup = 0;
	}
	else if (data->fcntl) {
		r = sysexit_fcntl(current);
		data->fcntl = 0;
	}
	else if (data->deny) {
		/* Process is exiting a denied system call! */
		r = restore(current);
		data->deny = 0;
	}

	return r;
}
