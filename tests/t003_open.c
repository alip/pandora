/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	int fd, flags;

	if (argc < 2)
		return 125;

	flags = 0;
	if (!strcmp(argv[2], "rdonly")) {
		fd = open(argv[1], O_RDONLY);
		if (fd < 0) {
			perror(__FILE__);
			return 1;
		}
		return 0;
	}
	if (!strcmp(argv[2], "rdonly-creat"))
		flags |= O_RDONLY | O_CREAT;
	else if (!strcmp(argv[2], "rdonly-creat-excl"))
		flags |= O_RDONLY | O_CREAT | O_EXCL;
	else if (!strcmp(argv[2], "wronly"))
		flags |= O_WRONLY;
	else if (!strcmp(argv[2], "wronly-creat"))
		flags |= O_WRONLY | O_CREAT;
	else if (!strcmp(argv[2], "wronly-creat-excl"))
		flags |= O_WRONLY | O_CREAT | O_EXCL;
	else if (!strcmp(argv[2], "rdwr"))
		flags |= O_RDWR;
	else if (!strcmp(argv[2], "rdwr-creat"))
		flags |= O_RDWR | O_CREAT;
	else if (!strcmp(argv[2], "rdwr-creat-excl"))
		flags |= O_RDWR | O_CREAT | O_EXCL;
	else
		return 125;

	fd = open(argv[1], flags, 0644);
	if (fd < 0) {
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

	if (!(flags & O_CREAT) && argc > 2)
		write(fd, argv[3], strlen(argv[5]));
	close(fd);
	return getenv("PANDORA_TEST_SUCCESS") ? 0 : 2;
}
