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

#include "slist.h"

#include <stdlib.h>

slist_t *
slist_prepend(slist_t *slist, void *data)
{
	slist_t *node;

	node = malloc(sizeof(slist_t));
	if (!node)
		return NULL;

	node->data = data;
	node->next = slist;

	return node;
}

slist_t *
slist_remove_link(slist_t *slist, slist_t *slink)
{
	slist_t *prev, *temp;

	prev = NULL;
	temp = slist;

	while (temp) {
		if (temp == slink) {
			if (prev)
				prev->next = temp->next;
			if (slist == temp)
				slist = slist->next;

			temp->next = NULL;
			break;
		}
	
		prev = temp;
		temp = temp->next;
	}

	return slist;
}

void
slist_free(slist_t *slist, void (*freefunc) (void *data))
{
	slist_t *current;

	while (slist) {
		current = slist;
		if (freefunc)
			freefunc(current->data);
		slist = slist->next;
		free(current);
	}
}
