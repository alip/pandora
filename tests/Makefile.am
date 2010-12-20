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
	$(AM_V_at)$(SED) -e "s:@TOP_BUILDDIR@:$(top_builddir):g" $< > $@
CLEANFILES+= test-lib.sh

TESTS= \
       t001-chmod.sh \
       t002-chown.sh
EXTRA_DIST= $(TESTS)

check_PROGRAMS= \
		test-lib.sh \
		t001_chmod \
		t002_chown
