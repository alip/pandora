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
	int fd, succ;
	const char *path;

	if (argc < 3)
		return 125;

	path = argv[1];
	succ = atoi(argv[2]);

	if ((fd = creat(path, 0644)) < 0) {
		if (succ) {
			perror(__FILE__);
			return 1;
		}
		if (errno == EPERM)
			return 0;
		perror(__FILE__);
		return 1;
	}

	if (argc > 3)
		write(fd, argv[3], strlen(argv[3]));
	close(fd);
	return succ ? 0 : 2;
}
