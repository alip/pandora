/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010 Ali Polatel <alip@exherbo.org>
 * Based in part upon courier which is:
 *   Copyright 1998-2009 Double Precision, Inc
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
#include <string.h>

#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "util.h"
#include "wildmatch.h"

int
sock_match_new(const char *src, sock_match_t **buf)
{
	int r;
	char *addr, *netmask, *range, *d, *p;
	sock_match_t *m;

	assert(buf);

	addr = NULL;
	m = xmalloc(sizeof(sock_match_t));

	if (!strncmp(src, "unix:", 5)) {
		m->family = AF_UNIX;
		m->match.sa_un.abstract = 0;
		if (*(src + 5) == 0) {
			r = -EINVAL;
			goto fail;
		}
		strncpy(m->match.sa_un.path, src + 5, PATH_MAX);
		m->match.sa_un.path[PATH_MAX - 1] = '\0';
	}
	else if (!strncmp(src, "unix-abstract:", 14)) {
		m->family = AF_UNIX;
		m->match.sa_un.abstract = 1;
		if (*(src + 14) == 0) {
			r = -EINVAL;
			goto fail;
		}
		strncpy(m->match.sa_un.path, src + 14, PATH_MAX);
		m->match.sa_un.path[PATH_MAX - 1] = '\0';
	}
	else if (!strncmp(src, "inet:", 5)) {
		m->family = AF_INET;
		addr = xstrdup(src + 5);

		/* Find out port */
		range = strrchr(addr, '@');
		if (!range || *(range + 1) == 0) {
			r = -EINVAL;
			goto fail;
		}
		addr[range - addr] = '\0';

		/* Delimiter '-' means we have a range of ports,
		 * otherwise it's a unique port.
		 */
		d = strchr(++range, '-');
		if (!d) {
			if ((r = parse_port(range, &m->match.sa_in.port[0])) < 0)
				goto fail;
			m->match.sa_in.port[1] = m->match.sa_in.port[0];
		}
		else {
			range[d - range] = '\0';
			if ((r = parse_port(range, &m->match.sa_in.port[0])) < 0)
				goto fail;
			if ((r = parse_port(++d, &m->match.sa_in.port[1])) < 0)
				goto fail;
		}

		/* Find out netmask */
		netmask = strrchr(addr, '/');
		if (!netmask) {
			/* Netmask not specified, figure it out. */
			m->match.sa_in.netmask = 8;
			p = addr;
			while (*p != 0) {
				if (*p++ == '.') {
					if (*p == 0)
						break;
					m->match.sa_in.netmask += 8;
				}
			}
		}
		else {
			if ((r = safe_atou(netmask + 1, &m->match.sa_in.netmask)) < 0)
				goto fail;
			addr[netmask - addr] = '\0';
		}

		errno = 0;
		if (inet_pton(AF_INET, addr, &m->match.sa_in.addr) != 1) {
			r = errno ? -errno : -EINVAL;
			goto fail;
		}
		free(addr);
	}
	else if (!strncmp(src, "inet6:", 6)) {
#if !PANDORA_HAVE_IPV6
		r = -EAFNOSUPPORT;
		goto fail;
#else
		m->family = AF_INET6;
		addr = xstrdup(src + 6);

		/* Find out port */
		range = strrchr(addr, '@');
		if (!range || *(range + 1) == 0) {
			r = -EINVAL;
			goto fail;
		}
		addr[range - addr] = '\0';

		/* Delimiter '-' means we have a range of ports,
		 * otherwise it's a unique port.
		 */
		d = strchr(++range, '-');
		if (!d) {
			if ((r = parse_port(range, &m->match.sa6.port[0])) < 0)
				goto fail;
			m->match.sa6.port[1] = m->match.sa6.port[0];
		}
		else {
			range[d - range] = '\0';
			if ((r = parse_port(range, &m->match.sa6.port[0])) < 0)
				goto fail;
			if ((r = parse_port(++d, &m->match.sa6.port[1])) < 0)
				goto fail;
		}

		/* Find out netmask */
		netmask = strrchr(addr, '/');
		if (!netmask) {
			/* Netmask not specified, figure it out. */
			m->match.sa6.netmask = 16;
			p = addr;
			while (*p != 0) {
				if (*p++ == ':') {
					/* ip:: ends the prefix right here,
					 * but ip::ip is a full IPv6 address.
					 */
					if (p[1] != '\0')
						m->match.sa6.netmask = sizeof(struct in6_addr) * 8;
					break;
				}
				if (*p == 0)
					break;
				m->match.sa6.netmask += 16;
			}
		}
		else {
			if ((r = safe_atou(netmask + 1, &m->match.sa6.netmask)) < 0)
				return r;
			addr[netmask - addr] = '\0';
		}

		errno = 0;
		if (inet_pton(AF_INET6, addr, &m->match.sa_in.addr) != 1) {
			r = errno ? -errno : -EINVAL;
			goto fail;
		}
		free(addr);
#endif
	}
	else {
		r = -EAFNOSUPPORT;
		goto fail;
	}

	m->str = xstrdup(src);
	*buf = m;
	return 0;

fail:
	if (addr)
		free(addr);
	free(m);
	return r;
}

int
sock_match(const sock_match_t *haystack, const pink_socket_address_t *needle)
{
	int n, mask;
	unsigned pmin, pmax, port;
	const unsigned char *b, *ptr;

	assert(haystack);
	assert(needle);

	if (needle->family != haystack->family)
		return 0;

	switch (needle->family) {
	case AF_UNIX:
		if (needle->u.sa_un.sun_path[0] == '\0' && needle->u.sa_un.sun_path[1] != '\0') {
			/* Abstract UNIX socket */
			return haystack->match.sa_un.abstract &&
				wildmatch(haystack->match.sa_un.path, needle->u.sa_un.sun_path + 1);
		}
		/* Non-abstract UNIX socket */
		return 0;
	case AF_INET:
		n = haystack->match.sa_in.netmask;
		ptr = (const unsigned char *)&needle->u.sa_in.sin_addr;
		b = (const unsigned char *)&haystack->match.sa_in.addr;
		pmin = haystack->match.sa_in.port[0];
		pmax = haystack->match.sa_in.port[1];
		port = needle->u.sa_in.sin_port;
		break;
#if PANDORA_HAVE_IPV6
	case AF_INET6:
		n = haystack->match.sa6.netmask;
		ptr = (const unsigned char *)&needle->u.sa6.sin6_addr;
		b = (const unsigned char *)&haystack->match.sa6.addr;
		pmin = haystack->match.sa6.port[0];
		pmax = haystack->match.sa6.port[1];
		port = needle->u.sa6.sin6_port;
		break;
#endif
	default:
		return 0;
	}

	while (n >= 8) {
		if (*ptr != *b)
			return 0;
		++ptr;
		++b;
		n -= 8;
	}

	if (n != 0) {
		mask = ((~0) << (8 - n)) & 255;
		if ((*ptr ^ *b) & mask)
			return 0;
	}

	return pmin <= port && port <= pmax;
}
