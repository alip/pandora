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

#include <assert.h>
#include <errno.h>
#include <fcntl.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "proc.h"

/* Decode the path at the given index and place it in buf.
 * Handles panic() itself.
 * Returns:
 * -1 : System call must be denied.
 * -2 : System call must be reported and denied.
 *  0 : Successful run
 * >0 : PINK_EASY_CFLAG* flags
 */
int
path_decode(pink_easy_process_t *current, unsigned ind, char **buf)
{
	char *path;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);

	assert(current);
	assert(buf);

	errno = 0;
	path = pink_decode_string_persistent(pid, bit, ind);
	if (errno) {
		if (errno != ESRCH) {
			warning("pink_decode_string_persistent(%lu, %s, %u): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					ind,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}
	else if (!path) {
		*buf = NULL;
		errno = EFAULT;
		return pandora->config->core.violation.ignore_safe ? -1 : -2;
	}

	*buf = path;
	return 0;
}

/*
 * Resolve the prefix of an at-suffixed function reading /proc/$pid/fd/$fd
 * Handles panic() itself.
 * Returns:
 * -1 : System call must be denied.
 * -2 : System call must be reported and denied.
 *  0 : Successful run
 * >0 : PINK_EASY_CFLAG* flags
 */
int
path_prefix(pink_easy_process_t *current, sysinfo_t *info)
{
	int r;
	long fd;
	char *prefix;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);

	assert(info);
	assert(info->at);

	if (!pink_util_get_arg(pid, bit, info->index - 1, &fd)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", %u): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					info->index - 1,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (fd != AT_FDCWD) {
		if ((r = proc_fd(pid, fd, &prefix)) < 0) {
			errno = r == -ENOENT ? EBADF : -r;
			if (errno == EBADF)
				return pandora->config->core.violation.ignore_safe ? -1 : -2;
			return -1;
		}
		info->prefix = prefix;
	}
	else
		info->prefix = NULL;

	return 0;
}

/* Resolves the path and places it in buf.
 * Returns:
 * -1 : System call must be denied.
 * -2 : System call must be reported and denied.
 *  0 : Successful run
 */
int
path_resolve(pink_easy_process_t *current, const sysinfo_t *info, const char *path, char **buf)
{
	int r;
	char *abspath;
	pid_t pid = pink_easy_process_get_pid(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	assert(current);
	assert(info);
	assert(buf);

	if ((r = box_resolve_path(path, info->prefix ? info->prefix : data->cwd, pid, info->create > 0, info->resolv, &abspath)) < 0) {
		errno = -r;
		if (!pandora->config->core.violation.ignore_safe)
			return -2;
		return -1;
	}

	*buf = abspath;
	return 0;
}
