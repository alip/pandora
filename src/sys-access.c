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
#include <unistd.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int
sys_access(pink_easy_process_t *current, const char *name)
{
	int r;
	long mode;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sys_info_t info;

	if (data->config.sandbox_exec == SANDBOX_OFF
			&& data->config.sandbox_read == SANDBOX_OFF
			&& data->config.sandbox_write == SANDBOX_OFF)
		return 0;


	if (!pink_util_get_arg(pid, bit, 1, &mode)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 1) failed (errno:%d %s)",
					(unsigned long)pid, pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (!((mode & R_OK) && data->config.sandbox_read == SANDBOX_OFF)
		&& !((mode & W_OK) && data->config.sandbox_write == SANDBOX_OFF)
		&& !((mode & X_OK) && data->config.sandbox_exec == SANDBOX_OFF))
		return 0;

	memset(&info, 0, sizeof(sys_info_t));
	info.resolv = true;
	info.safe = true;
	info.deny_errno = EACCES;

	r = 0;
	if (data->config.sandbox_write != SANDBOX_OFF && mode & W_OK) {
		info.whitelisting = data->config.sandbox_write == SANDBOX_DENY;
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && data->config.sandbox_read != SANDBOX_OFF && mode & R_OK) {
		info.whitelisting = data->config.sandbox_read == SANDBOX_DENY;
		info.wblist = data->config.sandbox_read == SANDBOX_DENY ? &data->config.whitelist_read : &data->config.blacklist_read;
		info.filter = &pandora->config.filter_read;
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && data->config.sandbox_exec != SANDBOX_OFF && mode & X_OK) {
		info.whitelisting = data->config.sandbox_exec == SANDBOX_DENY;
		info.wblist = data->config.sandbox_exec == SANDBOX_DENY ? &data->config.whitelist_exec : &data->config.blacklist_exec;
		info.filter = &pandora->config.filter_exec;
		r = box_check_path(current, name, &info);
	}

	return r;
}

int
sys_faccessat(pink_easy_process_t *current, const char *name)
{
	int r;
	long mode, flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sys_info_t info;

	if (data->config.sandbox_exec == SANDBOX_OFF
			&& data->config.sandbox_read == SANDBOX_OFF
			&& data->config.sandbox_write == SANDBOX_OFF)
		return 0;

	/* Check mode argument first */
	if (!pink_util_get_arg(pid, bit, 2, &mode)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 2): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (!((mode & R_OK) && data->config.sandbox_read == SANDBOX_OFF)
		&& !((mode & W_OK) && data->config.sandbox_write == SANDBOX_OFF)
		&& !((mode & X_OK) && data->config.sandbox_exec == SANDBOX_OFF))
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

	memset(&info, 0, sizeof(sys_info_t));
	info.at     = true;
	info.index  = 1;
	info.resolv = !(flags & AT_SYMLINK_NOFOLLOW);
	info.safe   = true;
	info.deny_errno = EACCES;

	r = 0;
	if (data->config.sandbox_write != SANDBOX_OFF && mode & W_OK) {
		info.whitelisting = data->config.sandbox_write == SANDBOX_DENY;
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && data->config.sandbox_read != SANDBOX_OFF && mode & R_OK) {
		info.whitelisting = data->config.sandbox_read == SANDBOX_DENY;
		info.wblist = data->config.sandbox_read == SANDBOX_DENY ? &data->config.whitelist_read : &data->config.blacklist_read;
		info.filter = &pandora->config.filter_read;
		r = box_check_path(current, name, &info);
	}

	if (!r && !data->deny && data->config.sandbox_exec != SANDBOX_OFF && mode & X_OK) {
		info.whitelisting = data->config.sandbox_exec == SANDBOX_DENY;
		info.wblist = data->config.sandbox_exec == SANDBOX_DENY ? &data->config.whitelist_exec : &data->config.blacklist_exec;
		info.filter = &pandora->config.filter_exec;
		r = box_check_path(current, name, &info);
	}

	return r;
}
