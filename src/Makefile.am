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
		proc.h \
		shell.h \
		slist.h \
		util.h \
		pandora-defs.h
pandora_SOURCES= \
		 JSON_parser.c \
		 file.c \
		 proc.c \
		 shell.c \
		 slist.c \
		 util.c \
		 pandora.c \
		 pandora-box.c \
		 pandora-callback.c \
		 pandora-config.c \
		 pandora-log.c \
		 pandora-magic.c \
		 pandora-syscall.c \
		 pandora-systable.c \
		 pandora-util.c
pandora_LDADD= \
	       $(pinktrace_LIBS) \
	       $(pinktrace_easy_LIBS)

SPARSE=sparse
SPARSE_CPPFLAGS= $(DEFAULT_INCLUDES) \
		 -Wbitwise -Wcast-to-as -Wdefault-bitfield-sign \
		 -Wparen-string -Wptr-subtraction-blows \
		 -Wreturn-void -Wshadow -Wtypesign -Wundef \
		 -I$(shell $(CC) -print-file-name=include) \
		 -I$(shell $(CC) -print-file-name=include-fixed)
# Fix this flag for your architecture!
SPARSE_CPPFLAGS+= -D__x86_64__=1

sparse-check:
	for src in $(pandora_SOURCES); \
	do \
		$(SPARSE) $(DEFS) $(AM_CFLAGS) $(SPARSE_CPPFLAGS) $$src || exit 1; \
	done
.PHONY: sparse-check
