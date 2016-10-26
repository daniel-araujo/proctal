EXTRA_DIST = src/args.yuck src/args.yucc
CLEANFILES = src/args.yucc

bin_PROGRAMS = proctal
lib_LIBRARIES = libproctal.a
lib_LTLIBRARIES = libproctal.la
include_HEADERS = src/proctal.h
dist_man_MANS = src/proctal.1

# Cli tool.
proctal_SOURCES = \
	src/main.c \
	src/command.h \
	src/command.c
proctal_LDADD = libproctal.la
proctal_CFLAGS = -Isrc -Wall -fmax-errors=10

# Static library.
libproctal_a_SOURCES = \
	src/proctal.h \
	src/write.c \
	src/read.c \
	src/search.c \
	src/linux.h \
	src/linux.c \
	src/alloc.h \
	src/alloc.c
libproctal_a_CFLAGS = # Forcing renamed objects.

# Shared library.
libproctal_la_SOURCES = $(libproctal_a_SOURCES)
libproctal_la_LDFLAGS = -version-info $(PROCTAL_LIBRARY_VERSION)

# The following rules specify additional dependencies for object files.
#
# Always keep in mind that, according to sections 9.4.1 and 27.8 of the
# documentation, automake does not support a convenient method for specifying
# dependencies for automatically generated object files of *_SOURCES c files
# and that you should be wary of renamed objects when *_CFLAGS is defined.
src/proctal-main.$(OBJEXT): src/args.yucc

# Generates argument parsing code.
src/args.yucc: Makefile $(srcdir)/src/args.yuck
	$(YUCK) gen --no-auto-flags --no-auto-actions $(srcdir)/src/args.yuck -o $@

# Generates man page.
src/proctal.1: Makefile $(srcdir)/src/args.yuck
	$(YUCK) genman $(srcdir)/src/args.yuck -o $@
