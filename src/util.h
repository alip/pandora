/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010 Ali Polatel <alip@exherbo.org>
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

#ifndef UTIL_H
#define UTIL_H 1

#include <sys/types.h>
#include <limits.h>
#include <stdbool.h>

bool startswith(const char *s, const char *prefix);

int safe_atoi(const char *s, int *ret_i);
int safe_atou(const char *s, unsigned *ret_u);
int safe_atollu(const char *s, long long unsigned *ret_llu);
#if __WORDSIZE == 32
static inline int safe_atolu(const char *s, unsigned long *ret_u) {
	return safe_atou(s, (unsigned *) ret_u);
}
#else
static inline int safe_atolu(const char *s, unsigned long *ret_u) {
	return safe_atollu(s, (unsigned long long *) ret_u);
}
#endif /* __WORDSIZE == 32 */

int parse_pid(const char *s, pid_t *ret_pid);
int parse_port(const char *s, unsigned *ret_port);

#endif /* !UTIL_H */
