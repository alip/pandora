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

#include <errno.h>
#include <sys/types.h>
#include <stdio.h>

#include "file.h"
#include "proc.h"

/*
 * resolve /proc/$pid/cwd
 */
int
proc_cwd(pid_t pid, char **buf)
{
	int ret;
	char *cwd;
	char linkcwd[64];

	snprintf(linkcwd, 64, "/proc/%d/cwd", pid);

	/* Try readlink_alloc() first. */
	ret = readlink_alloc(linkcwd, &cwd);
	if (!ret) {
		*buf = cwd;
		return 0;
	}
	return ret;
}
