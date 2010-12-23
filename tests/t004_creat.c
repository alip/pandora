/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	int fd;

	if (argc < 2)
		return 125;

	if ((fd = creat(argv[1], 0644)) < 0) {
		if (getenv("PANDORA_TEST_SUCCESS")) {
			perror(__FILE__);
			return 1;
		}
		if (getenv("PANDORA_TEST_EEXIST") && errno == EEXIST)
			return 0;
		if (getenv("PANDORA_TEST_EPERM") && errno == EPERM)
			return 0;
		perror(__FILE__);
		return 1;
	}

	if (argc > 2)
		write(fd, argv[2], strlen(argv[2]));
	close(fd);
	return getenv("PANDORA_TEST_SUCCESS") ? 0 : 2;
}
