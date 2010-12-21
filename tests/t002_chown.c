/* vim: set cino= fo=croql sw=8 ts=8 sts=0 noet cin fdm=syntax : */

#include <sys/types.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

int
main(int argc, char **argv)
{
	uid_t uid = geteuid();
	gid_t gid = getegid();

	if (chown(argv[1], uid, gid) < 0) {
		if (errno == EPERM)
			return 0;
		perror("t002-chown");
		return 1;
	}
	return 2;
}
