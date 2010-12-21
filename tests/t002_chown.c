/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	int succ;

	if (argc < 2)
		return 125;
	succ = argc > 2;

	uid_t uid = geteuid();
	gid_t gid = getegid();

	if (chown(argv[1], uid, gid) < 0) {
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
