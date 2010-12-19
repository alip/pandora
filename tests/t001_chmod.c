/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

int
main(int argc, char **argv)
{
	if (chmod(argv[1], 0000) < 0) {
		if (errno == EPERM)
			return 0;
		perror("t0001-chmod");
		return 1;
	}
	return 2;
}
