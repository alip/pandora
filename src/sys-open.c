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
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

inline
static bool
open_wr_check(long flags, enum create_mode *create, bool *resolv)
{
	enum create_mode c;
	bool r;

	assert(create);
	assert(resolv);

	r = true;
	c = flags & O_CREAT ? MAY_CREATE : NO_CREATE;
	if (flags & O_EXCL) {
		if (c == NO_CREATE) {
			/* Quoting open(2):
			 * In general, the behavior of O_EXCL is undefined if
			 * it is used without O_CREAT.  There is one exception:
			 * on Linux 2.6 and later, O_EXCL can be used without
			 * O_CREAT if pathname refers to a block device. If
			 * the block device is in use by the system (e.g.,
			 * mounted), open() fails.
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
			c = MUST_CREATE;
			r = false;
		}
	}

	*create = c;
	*resolv = r;

	/* `unsafe' flag combinations:
	 * - O_RDONLY | O_CREAT
	 * - O_WRONLY
	 * - O_RDWR
	 */
	return !!(flags & (O_RDONLY | O_CREAT) || flags & (O_WRONLY | O_RDWR));
}

int
sys_open(pink_easy_process_t *current, const char *name)
{
	int r;
	bool resolv, wr;
	enum create_mode create;
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sys_info_t info;

	if (data->config.sandbox_read == SANDBOX_OFF && data->config.sandbox_write == SANDBOX_OFF)
		return 0;

	if (!pink_util_get_arg(pid, bit, 1, &flags)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 1) failed (errno:%d %s)",
					(unsigned long)pid, pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	wr = open_wr_check(flags, &create, &resolv);

	memset(&info, 0, sizeof(sys_info_t));
	info.create = create;
	info.resolv = resolv;

	r = 0;
	if (wr && data->config.sandbox_write != SANDBOX_OFF) {
		info.whitelisting = data->config.sandbox_write == SANDBOX_DENY;
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && data->config.sandbox_read != SANDBOX_OFF) {
		info.whitelisting = data->config.sandbox_read == SANDBOX_DENY;
		info.wblist = data->config.sandbox_read == SANDBOX_DENY ? &data->config.whitelist_read : &data->config.blacklist_read;
		info.filter = &pandora->config.filter_read;
		r = box_check_path(current, name, &info);
	}

	return r;
}

int
sys_openat(pink_easy_process_t *current, const char *name)
{
	int r;
	bool resolv, wr;
	enum create_mode create;
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sys_info_t info;

	if (data->config.sandbox_read == SANDBOX_OFF && data->config.sandbox_write == SANDBOX_OFF)
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

	wr = open_wr_check(flags, &create, &resolv);

	memset(&info, 0, sizeof(sys_info_t));
	info.at = true;
	info.index = 1;
	info.create = create;
	info.resolv = resolv;

	r = 0;
	if (wr && data->config.sandbox_write != SANDBOX_OFF) {
		info.whitelisting = data->config.sandbox_write == SANDBOX_DENY;
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && data->config.sandbox_read != SANDBOX_OFF) {
		info.whitelisting = data->config.sandbox_read == SANDBOX_DENY;
		info.wblist = data->config.sandbox_read == SANDBOX_DENY ? &data->config.whitelist_read : &data->config.blacklist_read;
		info.filter = &pandora->config.filter_read;
		r = box_check_path(current, name, &info);
	}

	return r;
}
