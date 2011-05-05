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

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int
sys_chown(pink_easy_process_t *current, const char *name)
{
	sys_info_t info;
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (data->config.sandbox_write == SANDBOX_OFF)
		return 0;

	memset(&info, 0, sizeof(sys_info_t));
	info.resolv = true;
	info.whitelisting = data->config.sandbox_write == SANDBOX_DENY;

	return box_check_path(current, name, &info);
}

int
sys_lchown(pink_easy_process_t *current, const char *name)
{
	sys_info_t info;
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (data->config.sandbox_write == SANDBOX_OFF)
		return 0;

	memset(&info, 0, sizeof(sys_info_t));
	info.whitelisting = data->config.sandbox_write == SANDBOX_DENY;

	return box_check_path(current, name, &info);
}

int
sys_fchownat(pink_easy_process_t *current, const char *name)
{
	long flags;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);
	sys_info_t info;

	if (data->config.sandbox_write == SANDBOX_OFF)
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

	memset(&info, 0, sizeof(sys_info_t));
	info.at     = true;
	info.resolv = !!(flags & AT_SYMLINK_FOLLOW);
	info.index  = 1;
	info.whitelisting = data->config.sandbox_write == SANDBOX_DENY;

	return box_check_path(current, name, &info);
}
