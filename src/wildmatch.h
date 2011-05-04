/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/* wildmatch.h */

#ifndef WILDMATCH_H
#define WILDMATCH_H 1

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include "util.h"

int wildmatch(const char *pattern, const char *text);
int iwildmatch(const char *pattern, const char *text);
int wildmatch_array(const char *pattern, const char*const *texts, int where);
int litmatch_array(const char *string, const char*const *texts, int where);

static inline int
wildmatch_ext(char *pattern, const char *text)
{
	int i, r;

	if (!endswith(pattern, "/***"))
		return wildmatch(pattern, text);

	i = strrchr(pattern, '/') - pattern;

	/* First try to match bare directory */
	pattern[i] = '\0';
	if ((r = wildmatch(pattern, text)))
		return r;

	/* Next try with one star less */
	pattern[i] = '/';
	pattern[i + 3] = '\0';
	r = wildmatch(pattern, text);
	pattern[i + 3] = '*';
	return r;
}

#endif /* !WILDMATCH_H */
