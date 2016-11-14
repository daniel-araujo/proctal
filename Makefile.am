proctal_cflags = -std=c11 -Wfatal-errors -Wall -Wextra -Wpointer-arith \
	-Wmissing-prototypes -Wno-switch $(proctal_xopen_flags) \
	-Wno-unused-parameter $(proctal_posix_flags)
proctal_lib_headers_dir = $(srcdir)/src/lib

EXTRA_DIST = src/cli/args.yuck src/cli/args.yucc
CLEANFILES = src/cli/args.yucc

bin_PROGRAMS = proctal
lib_LIBRARIES = libproctal.a
lib_LTLIBRARIES = libproctal.la
include_HEADERS = src/lib/proctal.h
dist_man_MANS = src/cli/proctal.1

# Cli tool.
proctal_SOURCES = \
	src/cli/main.c \
	src/cli/cmd/watch.c \
	src/cli/cmd/freeze.c \
	src/cli/cmd/read.c \
	src/cli/cmd/write.c \
	src/cli/cmd/search.c \
	src/cli/cmd/val.h \
	src/cli/cmd/val.c \
	src/cli/parser.h \
	src/cli/parser.c \
	src/cli/cmd.h
proctal_LDADD = libproctal.la
proctal_CFLAGS = -I$(srcdir)/src/cli -Isrc/cli -I$(proctal_lib_headers_dir) $(proctal_cflags)

# Static library.
libproctal_a_SOURCES = \
	src/lib/proctal.h \
	src/lib/proctal.c \
	src/lib/global.h \
	src/lib/global.c \
	src/lib/error.c \
	src/lib/watch.c \
	src/lib/freeze.c \
	src/lib/write.c \
	src/lib/read.c \
	src/lib/addr.c \
	src/lib/linux.h \
	src/lib/linux.c \
	src/lib/internal.h
libproctal_a_CFLAGS = -I$(srcdir)src/lib -I/src/lib -I$(proctal_lib_headers_dir) $(proctal_cflags)

# Shared library.
libproctal_la_SOURCES = $(libproctal_a_SOURCES)
libproctal_la_CFLAGS = $(libproctal_a_CFLAGS)
libproctal_la_LDFLAGS = -version-info $(PROCTAL_LIBRARY_VERSION)

# The following rules specify additional dependencies for object files.
#
# Always keep in mind that, according to sections 9.4.1 and 27.8 of the
# documentation, automake does not support a convenient method for specifying
# dependencies for automatically generated object files of *_SOURCES c files
# and that you should be wary of renamed objects when *_CFLAGS is defined.
src/cli/proctal-main.$(OBJEXT): src/cli/args.yucc

# Expands M4 macros.
src/cli/args.yuck: $(srcdir)/src/cli/args.yuck.m4
	m4 $^ > $@

# Generates argument parsing code.
src/cli/args.yucc: src/cli/args.yuck
	$(YUCK) gen --no-auto-flags --no-auto-actions $^ -o $@

# Generates man page.
src/cli/proctal.1: src/cli/args.yuck
	$(YUCK) genman $^ -o $@
