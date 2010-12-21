/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

#include <errno.h>
#include <stdio.h>
#include <sys/stat.h>

int
main(int argc, char **argv)
{
	int succ;

	if (argc < 2)
		return 125;
	succ = argc > 2;

	if (chmod(argv[1], 0000) < 0) {
		if (succ) {
			perror(__FILE__);
			return 1;
		}

		if (errno == EPERM)
			return 0;
		perror(__FILE__);
		return 1;
	}

	return succ ? 0 : 2;
}
