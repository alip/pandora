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
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/un.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "hashtable.h"

int
sys_bind(pink_easy_process_t *current, const char *name)
{
	int r;
	long fd;
	char *unix_abspath;
	pink_socket_address_t *psa;
	sys_info_t info;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (!data->config.sandbox_sock)
		return 0;

	memset(&info, 0, sizeof(sys_info_t));
	info.whitelist  = data->config.whitelist_sock_bind;
	info.filter = pandora->config->filter_sock;
	info.resolv = true;
	info.index  = 1;
	info.create = MAY_CREATE;
	info.deny_errno = EADDRNOTAVAIL;

	if (pandora->config->whitelist_successful_bind) {
		info.abspath = &unix_abspath;
		info.addr = &psa;
	}

	r = box_check_sock(current, name, &info);

	if (pandora->config->whitelist_successful_bind && !r) {
		/* Decode the file descriptor, for use in exit */
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
		data->args[0] = fd;

		switch (psa->family) {
		case AF_UNIX:
		case AF_INET:
#if PANDORA_HAVE_IPV6
		case AF_INET6:
#endif /* PANDORA_HAVE_IPV6 */
			data->savebind = xmalloc(sizeof(sock_info_t));
			data->savebind->path = unix_abspath;
			data->savebind->addr = psa;
			/* fall through */
		default:
			return r;
		}
	}

	if (pandora->config->whitelist_successful_bind) {
		if (unix_abspath)
			free(unix_abspath);
		if (psa)
			free(psa);
	}

	return r;
}

int
sysx_bind(pink_easy_process_t *current, const char *name)
{
	long ret;
	ht_int64_node_t *node;
	sock_match_t *m;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (!data->config.sandbox_sock || !pandora->config->whitelist_successful_bind || !data->savebind)
		return 0;

	/* Check the return value */
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
		free_sock_info(data->savebind);
		data->savebind = NULL;
		return 0;
	}

	/* Check for bind() with zero as port argument */
	if (data->savebind->addr->family == AF_INET && !data->savebind->addr->u.sa_in.sin_port)
		goto zero;
#if PANDORA_HAVE_IPV6
	if (data->savebind->addr->family == AF_INET6 && !data->savebind->addr->u.sa6.sin6_port)
		goto zero;
#endif

	sock_match_new_pink(data->savebind, &m);

	data->config.whitelist_sock_connect = slist_prepend(data->config.whitelist_sock_connect, m);
	if (!data->config.whitelist_sock_connect)
		die_errno(-1, "slist_prepend");
	return 0;
zero:
	node = hashtable_find(data->sockmap, data->args[0] + 1, 1);
	if (!node)
		die_errno(-1, "hashtable_find");
	node->data = data->savebind;
	data->savebind = NULL;
	return 0;
}
