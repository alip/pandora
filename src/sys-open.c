/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2011 Ali Polatel <alip@exherbo.org>
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

#include <assert.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "hashtable.h"

inline
static int
open_check(long flags, int *create, int *resolv)
{
	int c, r;

	assert(create);
	assert(resolv);

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
	*resolv = r;

	/* `unsafe' flag combinations:
	 * - O_RDONLY | O_CREAT
	 * - O_WRONLY
	 * - O_RDWR
	 */
	return flags & (O_RDONLY | O_CREAT) || flags & (O_WRONLY | O_RDWR);
}

int
sys_open(pink_easy_process_t *current, const char *name)
{
	int create, resolv;
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	sys_info_t info;

	if (!pink_util_get_arg(pid, bit, 1, &flags)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 1) failed (errno:%d %s)",
					(unsigned long)pid, pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	memset(&info, 0, sizeof(sys_info_t));
	if (!open_check(flags, &create, &resolv))
		return 0;
	info.create = create;
	info.resolv = resolv;

	return box_check_path(current, name, &info);
}

int
sys_openat(pink_easy_process_t *current, const char *name)
{
	int create, resolv;
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	sys_info_t info;

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

	memset(&info, 0, sizeof(sys_info_t));
	if (!open_check(flags, &create, &resolv))
		return 0;
	info.at = 1;
	info.index = 1;
	info.create = create;
	info.resolv = resolv;

	return box_check_path(current, name, &info);
}
