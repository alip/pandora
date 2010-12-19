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

#ifndef FILE_H
#define FILE_H 1

#include <stddef.h>

typedef enum {
	CAN_EXISTING = 0,
	CAN_ALL_BUT_LAST,
} can_mode_t;

int path_is_absolute(const char *p);
char *path_make_absolute(const char *p, const char *prefix);
int basename_alloc(const char *path, char **buf);
int dirname_alloc(const char *path, char **buf);
int readlink_alloc(const char *path, char **buf);
int canonicalize_filename_mode(const char *name, can_mode_t mode, int resolve, char **path);

#endif /* !FILE_H */
