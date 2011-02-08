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
sys_execve(pink_easy_process_t *current, const char *name)
{
	int r;
	char *path, *abspath;
	pid_t pid = pink_easy_process_get_pid(current);
	pink_bitness_t bit = pink_easy_process_get_bitness(current);
	proc_data_t *data = pink_easy_process_get_data(current);

	path = abspath = NULL;

	r = path_decode(current, 0, &path);
	if (r < 0)
		return deny(current);
	else if (r /* > 0 */)
		return r;

	if ((r = box_resolve_path(path, data->cwd, pid, 0, 1, &abspath)) < 0) {
		info("resolving path:\"%s\" [%s() index:0] failed for process:%lu [%s cwd:\"%s\"] (errno:%d %s)",
				path, name,
				(unsigned long)pid, pink_bitness_name(bit), data->cwd,
				-r, strerror(-r));
		errno = -r;
		r = deny(current);
		if (pandora->config->core.violation.raise_fail)
			violation(current, "%s(\"%s\")", name, path);
		free(path);
		return r;
	}
	free(path);

	/* Handling trace.kill_if_match and trace.resume_if_match:
	 *
	 * Resolve and save the path argument in data->abspath.
	 * When we receive a PINK_EVENT_EXEC which means execve() was
	 * successful, we'll check for kill_if_match and resume_if_match lists
	 * and kill or resume the process as necessary.
	 */
	data->abspath = abspath;

	if (!data->config.core.sandbox.exec)
		return 0;

	if (box_match_path(abspath, data->config.allow.exec, NULL))
		return 0;

	errno = EACCES;
	r = deny(current);

	if (!box_match_path(abspath, pandora->config->filter.exec, NULL))
		violation(current, "%s(\"%s\")", name, abspath);

	free(abspath);
	data->abspath = NULL;

	return r;
}
