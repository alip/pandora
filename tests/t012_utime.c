/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <utime.h>

int
main(int argc, char **argv)
{
	struct utimbuf t;

	if (argc < 2)
		return 125;

	t.actime = 0;
	t.modtime = 0;

	if (utime(argv[1], &t) < 0) {
		if (getenv("PANDORA_TEST_SUCCESS")) {
			perror(__FILE__);
			return 1;
		}
		else if (getenv("PANDORA_TEST_EPERM") && errno == EPERM)
			return 0;
		perror(__FILE__);
		return 1;
	}

	return getenv("PANDORA_TEST_SUCCESS") ? 0 : 2;
}
