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

#include <stdbool.h>
#include <string.h>

#include <pinktrace/pink.h>
#include <pinktrace/easy/pink.h>

int
sys_rename(pink_easy_process_t *current, const char *name)
{
	int r;
	sys_info_t info;
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (data->config.sandbox_write == SANDBOX_OFF)
		return 0;

	memset(&info, 0, sizeof(sys_info_t));
	info.whitelisting = data->config.sandbox_write == SANDBOX_DENY;

	r = box_check_path(current, name, &info);
	if (!r && !data->deny) {
		info.create = MAY_CREATE;
		info.index  = 1;
		return box_check_path(current, name, &info);
	}

	return r;
}

int
sys_renameat(pink_easy_process_t *current, const char *name)
{
	int r;
	sys_info_t info;
	proc_data_t *data = pink_easy_process_get_userdata(current);

	if (data->config.sandbox_write == SANDBOX_OFF)
		return 0;

	memset(&info, 0, sizeof(sys_info_t));
	info.at     = true;
	info.index  = 1;
	info.whitelisting = data->config.sandbox_write == SANDBOX_DENY;

	r = box_check_path(current, name, &info);
	if (!r && !data->deny) {
		info.create = MAY_CREATE;
		info.index  = 3;
		return box_check_path(current, name, &info);
	}

	return r;
}
