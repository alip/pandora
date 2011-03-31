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
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <sys/mount.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int
sys_mount(pink_easy_process_t *current, const char *name)
{
	sys_info_t info;
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (!data->config.sandbox_path)
		return 0;

	memset(&info, 0, sizeof(sys_info_t));
	info.resolv = true;
	info.index  = 1;

	return box_check_path(current, name, &info);
}

int
sys_umount(pink_easy_process_t *current, const char *name)
{
	sys_info_t info;
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (!data->config.sandbox_path)
		return 0;

	memset(&info, 0, sizeof(sys_info_t));
	info.resolv = true;

	return box_check_path(current, name, &info);
}

int
sys_umount2(pink_easy_process_t *current, const char *name)
{
#ifdef UMOUNT_NOFOLLOW
	long flags;
	pid_t pid;
	pink_bitness_t bit;
#endif
	sys_info_t info;
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (!data->config.sandbox_path)
		return 0;

	memset(&info, 0, sizeof(sys_info_t));
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
	info.resolv = !(flags & UMOUNT_NOFOLLOW);
#else
	info.resolv = true;
#endif /* UMOUNT_NOFOLLOW */

	return box_check_path(current, name, &info);
}
