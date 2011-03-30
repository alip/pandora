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
sys_getsockname(pink_easy_process_t *current, PINK_UNUSED const char *name)
{
	long fd;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (!data->config.core.sandbox.sock || !pandora->config->core.allow.successful_bind)
		return 0;

	if (!pink_decode_socket_fd(pid, bit, 0, &fd)) {
		if (errno != ESRCH) {
			warning("pink_decode_socket_fd(%lu, \"%s\", 0) failed (errno:%d %s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	ht_int64_node_t *node = hashtable_find(data->sockmap, fd + 1, 0);
	if (node)
		data->args[0] = fd;

	return 0;
}

int
sysx_getsockname(pink_easy_process_t *current, PINK_UNUSED const char *name)
{
	unsigned port;
	long ret;
	pink_socket_address_t psa;
	sock_match_t *m;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (!data->config.core.sandbox.sock || !data->args[0])
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

	if (ret) {
		debug("ignoring failed %s() call for process:%lu [%s cwd:\"%s\"]",
				name, (unsigned long)pid, pink_bitness_name(bit),
				data->cwd);
		return 0;
	}

	if (!pink_decode_socket_address(pid, bit, 0, NULL, &psa)) {
		if (errno != ESRCH) {
			warning("pink_decode_socket_address(%lu, \"%s\", 0): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	ht_int64_node_t *node = hashtable_find(data->sockmap, data->args[0] + 1, 0);
	assert(node);
	sock_info_t *info = node->data;
	sock_match_new_pink(info, &m);

	free_sock_info(info);
	node->key = 0;
	node->data = NULL;

	switch (m->family) {
	case AF_INET:
		port = ntohs(psa.u.sa_in.sin_port);
		/* assert(port); */
		m->match.sa_in.port[0] = m->match.sa_in.port[1] = port;
		break;
#if PANDORA_HAVE_IPV6
	case AF_INET6:
		port = ntohs(psa.u.sa6.sin6_port);
		/* assert(port); */
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
