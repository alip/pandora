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
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

sock_info_t *
sock_info_xdup(sock_info_t *src)
{
	sock_info_t *dest;

	assert(src);

	dest = xmalloc(sizeof(sock_info_t));
	dest->path = src->path ? xstrdup(src->path) : NULL;

	dest->addr = xmalloc(sizeof(pink_socket_address_t));
	dest->addr->family = src->addr->family;
	dest->addr->length = src->addr->length;
	memcpy(&dest->addr->u._pad, src->addr->u._pad, sizeof(src->addr->u._pad));

	return dest;
}
