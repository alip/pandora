/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	int fd;
	const char *path;

	path = argv[1];
	if (!strcmp(argv[2], "rdonly"))
		return open(path, O_RDONLY) < 0 ? 1 : 0;
	else if (!strcmp(argv[2], "wronly"))
		fd = open(path, O_WRONLY);
	else if (!strcmp(argv[2], "rdwr"))
		fd = open(path, O_RDWR);
	else
		return 127;

	if (fd < 0) {
		if (errno == EPERM)
			return 0;
		perror("t003-open");
		return 1;
	}

	write(fd, argv[3], strlen(argv[3]));
	close(fd);
	return 2;
}
