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
#include <assert.h>
#include <errno.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "hashtable.h"

int
sys_close(pink_easy_process_t *current, PINK_UNUSED const char *name)
{
	long fd;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (!pandora->config->whitelist_successful_bind || !data->config.sandbox_sock)
		return 0;

	if (!pink_util_get_arg(pid, bit, 0, &fd)) {
		if (errno != ESRCH) {
			warning("pink_util_get_arg(%lu, \"%s\", 0) failed (errno:%d %s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (hashtable_find(data->sockmap, fd + 1, 0))
		data->args[0] = fd;

	return 0;
}

int
sysx_close(pink_easy_process_t *current, PINK_UNUSED const char *name)
{
	long ret;
	ht_int64_node_t *node;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (!pandora->config->whitelist_successful_bind || !data->config.sandbox_sock || !data->args[0])
		return 0;

	if (!pink_util_get_return(pid, &ret)) {
		if (errno != ESRCH) {
			warning("pink_util_get_return(%lu) failed (errno:%d %s)",
					(unsigned long)pid,
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	if (ret < 0) {
		debug("ignoring failed %s() call for process:%lu [%s cwd:\"%s\"]",
				name, (unsigned long)pid, pink_bitness_name(bit),
				data->cwd);
		return 0;
	}

	node = hashtable_find(data->sockmap, data->args[0] + 1, 0);
	assert(node);

	node->key = 0;
	free_sock_info(node->data);
	node->data = NULL;
	info("process:%lu [%s cwd:\"%s\"] closed fd:%lu by %s() call",
			(unsigned long)pid, pink_bitness_name(bit), data->cwd,
			data->args[0], name);
	return 0;
}
