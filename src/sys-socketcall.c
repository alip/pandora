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
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int
sys_socketcall(pink_easy_process_t *current, PINK_GCC_ATTR((unused)) const char *name)
{
	long subcall;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (!data->config.sandbox_sock || !pink_has_socketcall(bit))
		return 0;

	if (!pink_decode_socket_call(pid, bit, &subcall)) {
		if (errno != ESRCH) {
			warning("pink_decode_socketcall(%lu, \"%s\"): %d(%s)",
					(unsigned long)pid,
					pink_bitness_name(bit),
					errno, strerror(errno));
			return panic(current);
		}
		return PINK_EASY_CFLAG_DROP;
	}

	data->subcall = subcall;

	switch (subcall) {
	case PINK_SOCKET_SUBCALL_BIND:
		return sys_bind(current, "bind");
	case PINK_SOCKET_SUBCALL_CONNECT:
		return sys_connect(current, "connect");
	case PINK_SOCKET_SUBCALL_SENDTO:
		return sys_sendto(current, "sendto");
	case PINK_SOCKET_SUBCALL_GETSOCKNAME:
		return sys_getsockname(current, "getsockname");
	default:
		return 0;
	}
}

int
sysx_socketcall(pink_easy_process_t *current, PINK_GCC_ATTR((unused)) const char *name)
{
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (!data->config.sandbox_sock || !pink_has_socketcall(bit))
		return 0;

	switch (data->subcall) {
	case PINK_SOCKET_SUBCALL_BIND:
		return sysx_bind(current, "bind");
	case PINK_SOCKET_SUBCALL_GETSOCKNAME:
		return sysx_getsockname(current, "getsockname");
	default:
		return 0;
	}
}
