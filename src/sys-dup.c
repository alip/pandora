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

#include <sys/types.h>
#include <errno.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "hashtable.h"

int
sys_dup(pink_easy_process_t *current, PINK_GCC_ATTR((unused)) const char *name)
{
	long fd;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (data->config.sandbox_sock == SANDBOX_OFF || !pandora->config.whitelist_successful_bind)
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

	data->args[0] = fd;
	return 0;
}

int
sysx_dup(pink_easy_process_t *current, const char *name)
{
	long ret;
	ht_int64_node_t *old_node, *new_node;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (data->config.sandbox_sock == SANDBOX_OFF || !pandora->config.whitelist_successful_bind || !data->args[0])
		return 0;

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
		debug("ignoring failed %s() call for process:%lu [%s name:\"%s\" cwd:\"%s\"]",
				name, (unsigned long)pid, pink_bitness_name(bit),
				data->comm, data->cwd);
		return 0;
	}

	if (!(old_node = hashtable_find(data->sockmap, data->args[0] + 1, 0))) {
		debug("process:%lu [%s name:\"%s\" cwd:\"%s\"] duplicated unknown fd:%ld to fd:%ld by %s() call",
				(unsigned long)pid, pink_bitness_name(bit),
				data->comm, data->cwd, data->args[0], ret, name);
		return 0;
	}

	if (!(new_node = hashtable_find(data->sockmap, ret + 1, 1)))
		die_errno(-1, "hashtable_find");

	new_node->data = sock_info_xdup(old_node->data);
	info("process:%lu [%s name:\"%s\" cwd:\"%s\"] duplicated fd:%lu to fd:%lu by %s() call",
			(unsigned long)pid, pink_bitness_name(bit),
			data->comm, data->cwd, data->args[0], ret, name);
	return 0;
}
