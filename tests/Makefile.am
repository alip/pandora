CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov \
	    *.log

DEFS+= \
       -DDATADIR=\"$(datadir)\" \
       -DGITHEAD=\"$(GITHEAD)\"

AM_CFLAGS= \
	   $(pinktrace_CFLAGS) \
	   $(pinktrace_easy_CFLAGS) \
	   @PANDORA_CFLAGS@

test-lib.sh: test-lib.sh.in
	$(AM_V_GEN)
	$(AM_V_at)$(SED) -e "s:@TOP_BUILDDIR@:$(abs_top_builddir):g" $< > $@
CLEANFILES+= test-lib.sh

noinst_DATA= wildtest.txt
wildtest_SOURCES= \
		  wildtest.c
wildtest_CFLAGS= \
		 -DWILD_TEST_ITERATIONS \
		 --include=$(top_srcdir)/src/wildmatch.c \
		 $(DEFS) \
		 $(AM_CFLAGS)

TESTS= \
       t000-basic.sh \
       t001-chmod.sh \
       t002-chown.sh \
       t003-open.sh \
       t004-creat.sh \
       t005-lchown.sh \
       t006-mkdir.sh \
       t007-mknod.sh \
       t008-rmdir.sh \
       t009-truncate.sh \
       t010-umount.sh \
       t011-umount2.sh \
       t012-utime.sh \
       t013-utimes.sh \
       t014-unlink.sh \
       t015-link.sh \
       t016-rename.sh \
       t017-symlink.sh \
       t018-mount.sh \
       t019-openat.sh \
       t020-mknodat.sh \
       t021-mkdirat.sh \
       t022-fchmodat.sh \
       t023-fchownat.sh \
       t024-unlinkat.sh \
       t027-linkat.sh
EXTRA_DIST= $(TESTS)

check_PROGRAMS= \
		wildtest \
		test-lib.sh \
		t001_chmod \
		t002_chown \
		t003_open \
		t004_creat \
		t005_lchown \
		t006_mkdir \
		t007_mknod
