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

#ifndef AF_H
#define AF_H 1

#include <sys/socket.h>

static const struct af_table {
	int family;
	const char *name;
} af_table[] = {
#ifdef AF_UNSPEC
	{AF_UNSPEC,	"AF_UNSPEC"},
#endif
#ifdef AF_LOCAL
	{AF_LOCAL,	"AF_LOCAL"},
#endif
#ifdef AF_UNIX
	{AF_UNIX,	"AF_UNIX"},
#endif
#ifdef AF_FILE
	{AF_FILE,	"AF_FILE"},
#endif
#ifdef AF_INET
	{AF_INET,	"AF_INET"},
#endif
#ifdef AF_AX25
	{AF_AX25,	"AF_AX25"},
#endif
#ifdef AF_IPX
	{AF_IPX,	"AF_IPX"},
#endif
#ifdef AF_APPLETALK
	{AF_APPLETALK,	"AF_APPLETALK"},
#endif
#ifdef AF_NETROM
	{AF_NETROM,	"AF_NETROM"},
#endif
#ifdef AF_BRIDGE
	{AF_BRIDGE,	"AF_BRIDGE"},
#endif
#ifdef AF_ATMPVC
	{AF_ATMPVC,	"AF_ATMPVC"},
#endif
#ifdef AF_X25
	{AF_X25,	"AF_X25"},
#endif
#ifdef AF_INET6
	{AF_INET6,	"AF_INET6"},
#endif
#ifdef AF_ROSE
	{AF_ROSE,	"AF_ROSE"},
#endif
#ifdef AF_DECnet
	{AF_DECnet,	"AF_DECnet"},
#endif
#ifdef AF_NETBEUI
	{AF_NETBEUI,	"AF_NETBEUI"},
#endif
#ifdef AF_SECURITY
	{AF_SECURITY,	"AF_SECURITY"},
#endif
#ifdef AF_KEY
	{AF_KEY,	"AF_KEY"},
#endif
#ifdef AF_NETLINK
	{AF_NETLINK,	"AF_NETLINK"},
#endif
#ifdef AF_ROUTE
	{AF_ROUTE,	"AF_ROUTE"},
#endif
#ifdef AF_PACKET
	{AF_PACKET,	"AF_PACKET"},
#endif
#ifdef AF_ASH
	{AF_ASH,	"AF_ASH"},
#endif
#ifdef AF_ECONET
	{AF_ECONET,	"AF_ECONET"},
#endif
#ifdef AF_ATMSVC
	{AF_ATMSVC,	"AF_ATMSVC"},
#endif
#ifdef AF_RDS
	{AF_RDS,	"AF_RDS"},
#endif
#ifdef AF_SNA
	{AF_SNA,	"AF_SNA"},
#endif
#ifdef AF_IRDA
	{AF_IRDA,	"AF_IRDA"},
#endif
#ifdef AF_PPPOX
	{AF_PPPOX,	"AF_PPPOX"},
#endif
#ifdef AF_WANPIPE
	{AF_WANPIPE,	"AF_WANPIPE"},
#endif
#ifdef AF_LLC
	{AF_LLC,	"AF_LLC"},
#endif
#ifdef AF_CAN
	{AF_CAN,	"AF_CAN"},
#endif
#ifdef AF_TIPC
	{AF_TIPC,	"AF_TIPC"},
#endif
#ifdef AF_BLUETOOTH
	{AF_BLUETOOTH,	"AF_BLUETOOTH"},
#endif
#ifdef AF_IUCV
	{AF_IUCV,	"AF_IUCV"},
#endif
#ifdef AF_RXRPC
	{AF_RXRPC,	"AF_RXRPC"},
#endif
#ifdef AF_ISDN
	{AF_ISDN,	"AF_ISDN"},
#endif
#ifdef AF_PHONET
	{AF_PHONET,	"AF_PHONET"},
#endif
#ifdef AF_IEEE802154
	{AF_IEEE802154,	"AF_IEEE802154"},
#endif
	{-1,		NULL},
};

inline
static const char *
af_lookup(int family)
{
	const struct af_table *af;

	for (af = af_table; af->name; af++)
		if (family == af->family)
			return af->name;

	return "AF_???";
}

#endif /* !AF_H */
