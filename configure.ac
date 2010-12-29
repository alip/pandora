dnl vim: set sw=4 sts=4 ts=4 noet ft=config foldmethod=marker foldmarker={{{,}}} :

dnl {{{ Program, version
AC_PREREQ(2.59)
AC_INIT([pandora], [1], [alip@exherbo.org])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([dist-bzip2 no-dist-gzip std-options foreign])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl {{{ Git revision
if test -d "${GIT_DIR:-${ac_top_srcdir:-./}/.git}" ; then
	GITHEAD=`git describe 2>/dev/null`
	if test -z "${GITHEAD}" ; then
		GITHEAD=`git rev-parse HEAD`
	fi
	if test -n "`git diff-index -m --name-only HEAD`" ; then
		GITHEAD="${GITHEAD}-dirty"
	fi
	if test -n "${GITHEAD}" ; then
		GITHEAD="-${GITHEAD}"
	fi
else
	GITHEAD=
fi
AC_MSG_CHECKING([for git head])
AC_ARG_WITH([git-head],
	AS_HELP_STRING([--with-git-head], [Specify Git head]),
	GITHEAD=`eval echo $withval`,
	GITHEAD=`eval echo $GITHEAD`)
AC_MSG_RESULT([$GITHEAD])
AC_SUBST([GITHEAD])
dnl }}}

PANDORA_CFLAGS=
dnl }}}

dnl {{{ toolchain checks
AC_PROG_CC_C99
if test x"$ac_cv_prog_cc_c99" = x"no"; then
	AC_MSG_ERROR([pandora requires a C compiler that supports ISO C99!])
fi
AC_GNU_SOURCE
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_SED
dnl }}}

dnl {{{ check for sizes
AC_CHECK_SIZEOF([int])
AC_CHECK_SIZEOF([long])
AC_CHECK_SIZEOF([long long])
AC_CHECK_SIZEOF([short])
AC_CHECK_SIZEOF([int16_t])
AC_CHECK_SIZEOF([uint16_t])
AC_CHECK_SIZEOF([int32_t])
AC_CHECK_SIZEOF([uint32_t])
AC_CHECK_SIZEOF([int64_t])
AC_CHECK_SIZEOF([off_t])
AC_CHECK_SIZEOF([off64_t])
dnl }}}

dnl {{{ check functions
AC_CHECK_FUNCS([fchdir])
dnl }}}

dnl {{{ Check whether getcwd(NULL, 0) allocates memory for result
AC_CACHE_CHECK([whether getcwd(NULL, 0) allocates memory for result],
			   [ac_cv_func_getcwd_null],
			   [AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <stdlib.h>
#include <unistd.h>

int main(void) {
	if (0 != chdir("/"))
		return EXIT_FAILURE;
	else {
		char *f = getcwd(NULL, 0);
		if (NULL != f && '/' == f[0] && '\0' == f[1])
			return EXIT_SUCCESS;
		else
			return EXIT_FAILURE;
	}
}
]])],
[ac_cv_func_getcwd_null=yes],
[ac_cv_func_getcwd_null=no])])
if test x"$ac_cv_func_getcwd_null" = x"yes"; then
	AC_DEFINE([HAVE_GETCWD_NULL], 1, [Define for getcwd(NULL, 0) that allocates memory])
fi
dnl }}}

dnl {{{ Check for usable /proc
AC_CACHE_CHECK([whether /proc/\$pid/cwd is usable],
			   [ac_cv_proc_cwd_usable],
			   [AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <sys/types.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
	pid_t pid;

	pid = fork();
	if (0 > pid)
		exit(1);
	if (0 == pid) {
		pause();
		_exit(0);
	}
	else {
		char proc[32], path[PATH_MAX];
		char *cwd = NULL;
		ssize_t len;

		cwd = getcwd(cwd, PATH_MAX);
		if (NULL == cwd)
			goto fail;

		snprintf(proc, 32, "/proc/%i/cwd", pid);
		len = readlink(proc, path, PATH_MAX);
		if (0 > len)
			goto fail;
		else
			path[len] = '\0';
		if (0 != strncmp(cwd, path, PATH_MAX))
			goto fail;

		kill(pid, SIGKILL);
		exit(0);
fail:
		kill(pid, SIGKILL);
		exit(1);
	}
}
]])],
[ac_cv_proc_cwd_usable=yes],
[ac_cv_proc_cwd_usable=no])])
if test x"$ac_cv_proc_cwd_usable" = x"no"; then
	AC_MSG_ERROR([/proc fails to give current working directory information about process IDs])
fi

AC_CACHE_CHECK([whether /proc/\$pid/fd/\$dirfd is usable],
			   [ac_cv_proc_fd_usable],
			   [AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <sys/types.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>

int main(void) {
	pid_t pid;
	char buf[32];
	int pfd[2];

	if (-1 == pipe(pfd))
		exit(1);

	pid = fork();
	if (0 == pid) {
		DIR *d = opendir("/dev");
		int dfd = dirfd(d);

		close(pfd[0]);

		snprintf(buf, 32, "%i", dfd);
		write(pfd[1], buf, 32);

		close(pfd[1]);

		pause();
		_exit(0);
	}
	else {
		int dfd, n;
		char proc[64], path[PATH_MAX];

		close(pfd[1]);

		if (0 > read(pfd[0], buf, 32))
			goto fail;

		close(pfd[0]);

		dfd = atoi(buf);
		snprintf(proc, 64, "/proc/%i/fd/%i", pid, dfd);
		n = readlink(proc, path, PATH_MAX);
		if (0 > n)
			goto fail;
		path[n] = '\0';

		if (0 != strncmp(path, "/dev", 5))
			goto fail;

		kill(pid, SIGKILL);
		exit(0);
fail:
		kill(pid, SIGKILL);
		exit(1);
	}
}
]])],
[ac_cv_proc_fd_usable=yes],
[ac_cv_proc_fd_usable=no])])
if test x"$ac_cv_proc_fd_usable" = x"no"; then
	AC_MSG_ERROR([/proc fails to give directory file descriptor information about pids])
fi

AC_CACHE_CHECK([whether /proc/self resolves to /proc/\$pid],
			   [ac_cv_have_proc_self],
			   [AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PROC_SELF "/proc/self"

int main(void) {
	char buf[64], proc_pid[64];
	pid_t pid;

	if (0 > readlink(PROC_SELF, buf, 64)) {
		perror("readlink");
		return EXIT_FAILURE;
	}

	pid = getpid();
	snprintf(proc_pid, 64, "%i", pid);
	return (0 == strncmp(buf, proc_pid, 64)) ? EXIT_SUCCESS : EXIT_FAILURE;
}
]])],
[ac_cv_have_proc_self=yes],
[ac_cv_have_proc_self=no])])
if test x"$ac_cv_have_proc_self" = x"yes"; then
	AC_DEFINE([HAVE_PROC_SELF], 1, [Define for /proc/self])
fi
dnl }}}

dnl {{{ Check for large file support
AC_SYS_LARGEFILE
dnl }}}

dnl {{{ Check for libraries
PINKTRACE_REQUIRED=0.0.5

PKG_PROG_PKG_CONFIG([0.20.0])
PKG_CHECK_MODULES([pinktrace], [pinktrace >= $PINKTRACE_REQUIRED],,
				  AC_MSG_ERROR([pandora requires pinktrace-$PINKTRACE_REQUIRED or newer]))
PKG_CHECK_MODULES([pinktrace_easy], [pinktrace_easy >= $PINKTRACE_REQUIRED],,
				  AC_MSG_ERROR([pandora requires pinktrace_easy-$PINKTRACE_REQUIRED]))
dnl }}}

dnl {{{ Check for supported OS of pinktrace
AC_MSG_CHECKING([for supported OS of pinktrace])
old_CPPFLAGS="${CPPFLAGS}"
CPPFLAGS="${CPPFLAGS} ${pkg_cv_pinktrace_CFLAGS}"
AC_PREPROC_IFELSE([AC_LANG_SOURCE([
#include <pinktrace/pink.h>
#ifndef PINKTRACE_LINUX
#error nope
#endif
])],
	[AC_MSG_RESULT([ok])],
	[AC_MSG_ERROR([pandora only supports Linux])])
CPPFLAGS="${old_CPPFLAGS}"
dnl }}}

dnl {{{ Check for supported bitness count of pinktrace
AC_MSG_CHECKING([for supported bitness count of pinktrace])
old_CPPFLAGS="${CPPFLAGS}"
CPPFLAGS="${CPPFLAGS} ${pkg_cv_pinktrace_CFLAGS}"
AC_PREPROC_IFELSE([AC_LANG_SOURCE([
#include <pinktrace/pink.h>
#if PINKTRACE_BITNESS_COUNT_SUPPORTED < 2
#error nope
#endif
])],
	[pinktrace_bitness_count_supported=2],
	[pinktrace_bitness_count_supported=1])
CPPFLAGS="${old_CPPFLAGS}"
AC_MSG_RESULT([$pinktrace_bitness_count_supported])
AM_CONDITIONAL(BITNESS_TWO, test x"$pinktrace_bitness_count_supported" = x"2")
dnl }}}

dnl {{{ Check for IPV6 support
AC_ARG_ENABLE([ipv6],
			  [AS_HELP_STRING([--enable-ipv6],
							  [enable IPV6 support])],
			  WANT_IPV6="$enableval",
			  WANT_IPV6="no")
if test x"$WANT_IPV6" = x"yes" ; then
	AC_MSG_CHECKING([whether pinktrace was compiled with IPV6 support])
	old_CPPFLAGS="${CPPFLAGS}"
	CPPFLAGS="${CPPFLAGS} ${pkg_cv_pinktrace_CFLAGS}"
	AC_PREPROC_IFELSE([AC_LANG_SOURCE([
#include <pinktrace/pink.h>
#if PINKTRACE_HAVE_IPV6 == 0
#error nope
#endif
	])],
		[pinktrace_have_ipv6=yes],
		[pinktrace_have_ipv6=no])
	CPPFLAGS="${old_CPPFLAGS}"
	AC_MSG_RESULT([$pinktrace_have_ipv6])
	if test x"$pinktrace_have_ipv6" = x"no" ; then
		AC_MSG_ERROR([--enable-ipv6 requires pinktrace IPV6 support])
	fi
	AC_DEFINE([PANDORA_HAVE_IPV6], 1, [Define for IPV6 support])
else
	AC_DEFINE([PANDORA_HAVE_IPV6], 0, [Define for IPV6 support])
fi
AM_CONDITIONAL(WANT_IPV6, test x"$WANT_IPV6" = x"yes")
dnl }}}

dnl {{{ Extra CFLAGS
WANTED_CFLAGS="-pedantic -Wall -W -Wextra -Wbad-function-cast -Wcast-align -Wcast-qual -Wfloat-equal -Wformat=2 -Wformat-security -Wformat-nonliteral -Winit-self -Winline -Wlogical-op -Wmissing-prototypes -Wmissing-declarations -Wmissing-format-attribute -Wmissing-noreturn -Wpointer-arith -Wredundant-decls -Wshadow -Wswitch-default -Wunused -Wvla"
for flag in $WANTED_CFLAGS ; do
	AX_CHECK_COMPILER_FLAGS([$flag], [PANDORA_CFLAGS="$PANDORA_CFLAGS $flag"],)
done
AC_SUBST([PANDORA_CFLAGS])
dnl }}}

dnl {{{ Output
AM_CONFIG_HEADER(config.h)
AC_OUTPUT(
	Makefile
	src/Makefile
	tests/Makefile
	data/Makefile
	)
dnl }}}
