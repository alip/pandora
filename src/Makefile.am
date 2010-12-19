CLEANFILES= \
	    gmon.out \
	    *.gcda \
	    *.gcno \
	    *.gcov
EXTRA_DIST=

DEFS+= \
       -DDATADIR=\"$(datadir)\" \
       -DGITHEAD=\"$(GITHEAD)\"
AM_CFLAGS= \
	   $(pinktrace_CFLAGS) \
	   $(pinktrace_easy_CFLAGS) \
	   @PANDORA_CFLAGS@

bin_PROGRAMS= pandora
noinst_HEADERS= \
		JSON_parser.h \
		file.h \
		number.h \
		proc.h \
		shell.h \
		slist.h \
		pandora-defs.h
pandora_SOURCES= \
		 JSON_parser.c \
		 file.c \
		 number.c \
		 proc.c \
		 shell.c \
		 slist.c \
		 pandora.c \
		 pandora-box.c \
		 pandora-callback.c \
		 pandora-config.c \
		 pandora-log.c \
		 pandora-syscall.c \
		 pandora-systable.c \
		 pandora-util.c
pandora_LDADD= \
	       $(pinktrace_LIBS) \
	       $(pinktrace_easy_LIBS)
