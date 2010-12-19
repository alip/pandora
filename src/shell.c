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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "shell.h"

char *
shell_expand(const char *p, ssize_t len)
{
	size_t i, mylen;
	char *cmd, *dest;
	FILE *sh;

	if (len < 0)
		mylen = strlen(p) + 1;
	else
		mylen = len + 1;

	if (asprintf(&cmd, "/bin/sh -c 'echo \"%s\"'", p) < 0)
		return NULL;

	sh = popen(cmd, "r");
	if (!sh) {
		free(cmd);
		return NULL;
	}
	free(cmd);

	i = 0;
	dest = NULL;
	while (!feof(sh)) {
		dest = realloc(dest, (++i + 1) * sizeof(char));
		if (!dest) {
			pclose(sh);
			return NULL;
		}
		dest[i - 1] = fgetc(sh);
	}
	pclose(sh);

	/* Remove the trailing newline and add a zero byte. */
	if (dest[i - 2] == '\n')
		dest[i - 2] = '\0';
	else
		dest[i - 1] = '\0';

	return dest;
}
