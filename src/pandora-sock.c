/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011 Ali Polatel <alip@exherbo.org>
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
#include <stdbool.h>
#include <string.h>

#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

#include "macro.h"
#include "util.h"
#include "wildmatch.h"

int
sock_match_expand(const char *src, char ***buf)
{
	const char *port;
	char **list;

	assert(buf);

	if (startswith(src, "LOOPBACK@")) {
		list = xmalloc(sizeof(char *));
		xasprintf(&list[0], "inet:127.0.0.0/8@%s", src + STRLEN_LITERAL("LOOPBACK@"));
		*buf = list;
		return 1;
	}
	else if (startswith(src, "LOOPBACK6@")) {
		list = xmalloc(sizeof(char *));
		xasprintf(&list[0], "inet6:::1@%s", src + STRLEN_LITERAL("LOOPBACK6@"));
		*buf = list;
		return 1;
	}
	else if (startswith(src, "LOCAL@")) {
		port = src + STRLEN_LITERAL("LOCAL@");
		list = xmalloc(4 * sizeof(char *));
		xasprintf(&list[0], "inet:127.0.0.0/8@%s", port);
		xasprintf(&list[1], "inet:10.0.0.0/8@%s", port);
		xasprintf(&list[2], "inet:172.16.0.0/12@%s", port);
		xasprintf(&list[3], "inet:192.168.0.0/16@%s", port);
		*buf = list;
		return 4;
	}
	else if (startswith(src, "LOCAL6@")) {
		port = src + STRLEN_LITERAL("LOCAL6@");
		list = xmalloc(4 * sizeof(char *));
		xasprintf(&list[0], "inet6:::1@%s", port);
		xasprintf(&list[1], "inet6:fe80::/7@%s", port);
		xasprintf(&list[2], "inet6:fc00::/7@%s", port);
		xasprintf(&list[3], "inet6:fec0::/7@%s", port);
		*buf = list;
		return 4;
	}

	list = xmalloc(sizeof(char *));
	list[0] = xstrdup(src);
	*buf = list;
	return 1;
}

int
sock_match_new(const char *src, sock_match_t **buf)
{
	int r;
	char *addr, *netmask, *range, *d, *p;
	sock_match_t *m;

	assert(buf);

	addr = NULL;
	m = xmalloc(sizeof(sock_match_t));

	if (startswith(src, "unix:")) {
		m->family = AF_UNIX;
		m->match.sa_un.abstract = false;
		if (*(src + STRLEN_LITERAL("unix:")) == 0) {
			r = -EINVAL;
			goto fail;
		}
		m->match.sa_un.path = xstrdup(src + STRLEN_LITERAL("unix:"));
	}
	else if (startswith(src, "unix-abstract:")) {
		m->family = AF_UNIX;
		m->match.sa_un.abstract = true;
		if (*(src + STRLEN_LITERAL("unix-abstract:")) == 0) {
			r = -EINVAL;
			goto fail;
		}
		m->match.sa_un.path = xstrdup(src + STRLEN_LITERAL("unix-abstract:"));
	}
	else if (startswith(src, "inet:")) {
		m->family = AF_INET;
		addr = xstrdup(src + STRLEN_LITERAL("inet:"));

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
	else if (startswith(src, "inet6:")) {
#if !PANDORA_HAVE_IPV6
		r = -EAFNOSUPPORT;
		goto fail;
#else
		m->family = AF_INET6;
		addr = xstrdup(src + STRLEN_LITERAL("inet6:"));

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
				goto fail;
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
sock_match_new_pink(const sock_info_t *src, sock_match_t **buf)
{
	sock_match_t *m;

	assert(src);
	assert(src->addr);
	assert(buf);

	m = xmalloc(sizeof(sock_match_t));
	m->family = src->addr->family;
	m->str = NULL;

	switch (m->family) {
	case AF_UNIX:
		if (src->addr->u.sa_un.sun_path[0] == '\0' && src->addr->u.sa_un.sun_path[1] != '\0') {
			/* Abstract UNIX socket */
			m->match.sa_un.abstract = true;
			m->match.sa_un.path = xstrdup(src->addr->u.sa_un.sun_path + 1);
		}
		else {
			/* Non-abstract UNIX socket */
			m->match.sa_un.abstract = false;
			m->match.sa_un.path = src->path ? xstrdup(src->path) : xstrdup(src->addr->u.sa_un.sun_path);
		}
		break;
	case AF_INET:
		m->match.sa_in.port[0] = m->match.sa_in.port[1] = ntohs(src->addr->u.sa_in.sin_port);
		m->match.sa_in.netmask = 32;
		memcpy(&m->match.sa_in.addr, &src->addr->u.sa_in.sin_addr, sizeof(struct in_addr));
		break;
#if PANDORA_HAVE_IPV6
	case AF_INET6:
		m->match.sa6.port[0] = m->match.sa6.port[1] = ntohs(src->addr->u.sa6.sin6_port);
		m->match.sa6.netmask = 64;
		memcpy(&m->match.sa6.addr, &src->addr->u.sa6.sin6_addr, sizeof(struct in6_addr));
		break;
#endif
	default:
		abort();
	}

	*buf = m;
	return 0;
}

sock_match_t *
sock_match_xdup(const sock_match_t *src)
{
	sock_match_t *m;

	m = xmalloc(sizeof(sock_match_t));

	m->family = src->family;
	m->str = xstrdup(src->str);
	switch (src->family) {
	case AF_UNIX:
		m->match.sa_un.abstract = src->match.sa_un.abstract;
		m->match.sa_un.path = xstrdup(src->match.sa_un.path);
		break;
	case AF_INET:
		m->match.sa_in.netmask = src->match.sa_in.netmask;
		m->match.sa_in.port[0] = src->match.sa_in.port[0];
		m->match.sa_in.port[1] = src->match.sa_in.port[1];
		memcpy(&m->match.sa_in.addr, &src->match.sa_in.addr, sizeof(struct in_addr));
		break;
#if PANDORA_HAVE_IPV6
	case AF_INET6:
		m->match.sa6.netmask = src->match.sa6.netmask;
		m->match.sa6.port[0] = src->match.sa6.port[0];
		m->match.sa6.port[1] = src->match.sa6.port[1];
		memcpy(&m->match.sa6.addr, &src->match.sa6.addr, sizeof(struct in6_addr));
		break;
#endif
	default:
		abort();
	}

	return m;
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
		/* Non-abstract UNIX socket
		 * This needs path resolving, expect the caller handled this.
		 */
		return 0;
	case AF_INET:
		n = haystack->match.sa_in.netmask;
		ptr = (const unsigned char *)&needle->u.sa_in.sin_addr;
		b = (const unsigned char *)&haystack->match.sa_in.addr;
		pmin = haystack->match.sa_in.port[0];
		pmax = haystack->match.sa_in.port[1];
		port = ntohs(needle->u.sa_in.sin_port);
		break;
#if PANDORA_HAVE_IPV6
	case AF_INET6:
		n = haystack->match.sa6.netmask;
		ptr = (const unsigned char *)&needle->u.sa6.sin6_addr;
		b = (const unsigned char *)&haystack->match.sa6.addr;
		pmin = haystack->match.sa6.port[0];
		pmax = haystack->match.sa6.port[1];
		port = ntohs(needle->u.sa6.sin6_port);
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
