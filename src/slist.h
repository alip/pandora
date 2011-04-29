/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/*
 * Copyright (c) 2010, 2011 Ali Polatel <alip@exherbo.org>
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

#ifndef SLIST_H
#define SLIST_H 1

#include <sys/queue.h>

/* Generic singly-linked list based on sys/queue.h */
struct snode {
	void *data;
	SLIST_ENTRY(snode) up;
};
SLIST_HEAD(slist, snode);
typedef struct slist slist_t;

#define SLIST_FLUSH(var, head, field, freedata)				\
	do {								\
		while ((var = SLIST_FIRST(head))) {			\
			SLIST_REMOVE_HEAD(head, field);			\
			freedata(var->data);				\
			free(var);					\
		}							\
		SLIST_INIT(head);					\
	} while (0)

#endif /* !SLIST_H */
