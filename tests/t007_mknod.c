/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	if (argc < 1)
		return 125;

	if (mknod(argv[1], S_IFIFO, 0) < 0) {
		if (getenv("PANDORA_TEST_SUCCESS")) {
			perror(__FILE__);
			return 1;
		}
		else if (getenv("PANDORA_TEST_EPERM") && errno == EPERM)
			return 0;
		else if (getenv("PANDORA_TEST_EEXIST") && errno == EEXIST)
			return 0;
		perror(__FILE__);
		return 1;
	}

	return getenv("PANDORA_TEST_SUCCESS") ? 0 : 2;
}
