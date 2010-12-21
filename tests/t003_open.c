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
	int fd, flags, existing, succ;
	const char *path;

	/* arguments:
	 * 1: path
	 * 2: flags in string
	 * 3: existing (0/1)
	 * 4: expect-success (0/1)
	 * 5: data to write to file
	 */

	if (argc < 4)
		return 125;
	path = argv[1];
	existing = atoi(argv[3]);
	succ = atoi(argv[4]);

	flags = 0;
	if (!strcmp(argv[2], "rdonly")) {
		fd = open(path, O_RDONLY);
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

	fd = open(path, flags, 0644);
	if (fd < 0) {
		if (succ) {
			perror(__FILE__);
			return 1;
		}
		if (existing) {
			if (errno == EEXIST)
				return 0;
		}
		else if (errno == EPERM)
			return 0;
		perror(__FILE__);
		return 1;
	}

	if (!(flags & O_CREAT) && argc > 5)
		write(fd, argv[5], strlen(argv[5]));
	close(fd);
	return succ ? 0 : 2;
}
