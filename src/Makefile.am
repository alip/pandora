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
		addrfamily.h \
		byteorder.h \
		file.h \
		hashtable.h \
		macro.h \
		proc.h \
		slist.h \
		util.h \
		wildmatch.h \
		pandora-defs.h
pandora_SOURCES= \
		 JSON_parser.c \
		 file.c \
		 hashtable.c \
		 proc.c \
		 util.c \
		 wildmatch.c \
		 pandora.c \
		 pandora-box.c \
		 pandora-callback.c \
		 pandora-config.c \
		 pandora-log.c \
		 pandora-magic.c \
		 pandora-panic.c \
		 pandora-path.c \
		 pandora-sock.c \
		 pandora-sockinfo.c \
		 pandora-syscall.c \
		 pandora-systable.c \
		 pandora-util.c \
		 sys-access.c \
		 sys-chdir.c \
		 sys-execve.c \
		 sys-stat.c \
		 sys-dup.c \
		 sys-fcntl.c \
		 sys-chmod.c \
		 sys-chown.c \
		 sys-open.c \
		 sys-creat.c \
		 sys-close.c \
		 sys-mkdir.c \
		 sys-mknod.c \
		 sys-rmdir.c \
		 sys-truncate.c \
		 sys-mount.c \
		 sys-utime.c \
		 sys-unlink.c \
		 sys-setxattr.c \
		 sys-removexattr.c \
		 sys-link.c \
		 sys-rename.c \
		 sys-symlink.c \
		 sys-socketcall.c \
		 sys-bind.c \
		 sys-connect.c \
		 sys-getsockname.c
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
