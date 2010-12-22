/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

/* wildmatch.h */

#ifndef WILDMATCH_H
#define WILDMATCH_H 1

int wildmatch(const char *pattern, const char *text);
int iwildmatch(const char *pattern, const char *text);
int wildmatch_array(const char *pattern, const char*const *texts, int where);
int litmatch_array(const char *string, const char*const *texts, int where);

#endif /* !WILDMATCH_H */
