bin_PROGRAMS = proctal
lib_LTLIBRARIES = libproctal.la
include_HEADERS = src/lib/include/proctal.h
dist_man_MANS = src/cli/proctal.1
check_PROGRAMS = tests/invalid-patterns tests/valid-patterns tests/parse-valid-ascii
dist_check_SCRIPTS = tests/invalid-type-arguments.py

TESTS = $(check_PROGRAMS) $(dist_check_SCRIPTS)

EXTRA_DIST = src/cli/args.yuck.m4 src/cli/args.yuck src/cli/args.yucc
CLEANFILES = src/cli/args.yuck src/cli/args.yucc

proctal_cflags = -std=c11 -Wfatal-errors -Wall -Wextra -Wpointer-arith \
	-Wmissing-prototypes -Wno-switch $(proctal_xopen_flags) \
	-Wno-unused-parameter -Wno-unused-function $(proctal_posix_flags) \
	-Wno-maybe-uninitialized
proctal_src_lib_include = $(srcdir)/src/lib/include

# Cli tool.
proctal_SOURCES = \
	src/cli/main.c \
	src/cli/cmd/alloc.c \
	src/cli/cmd/dealloc.c \
	src/cli/cmd/execute.c \
	src/cli/cmd/watch.c \
	src/cli/cmd/freeze.c \
	src/cli/cmd/read.c \
	src/cli/cmd/write.c \
	src/cli/cmd/search.c \
	src/cli/cmd/pattern.c \
	src/cli/cmd/measure.c \
	src/cli/val/integer.h \
	src/cli/val/integer.c \
	src/cli/val/ieee754.h \
	src/cli/val/ieee754.c \
	src/cli/val/address.h \
	src/cli/val/address.c \
	src/cli/val/byte.h \
	src/cli/val/byte.c \
	src/cli/val/text.h \
	src/cli/val/text.c \
	src/cli/val/instruction.h \
	src/cli/val/instruction.c \
	src/cli/val.h \
	src/cli/val.c \
	src/cli/val-list.h \
	src/cli/val-list.c \
	src/cli/scanner.h \
	src/cli/scanner.c \
	src/cli/parser.h \
	src/cli/parser.c \
	src/cli/printer.h \
	src/cli/printer.c \
	src/cli/pattern.h \
	src/cli/pattern.c \
	src/cli/cmd.h
proctal_LDADD = libproctal.la $(proctal_capstone_libs) $(proctal_keystone_libs)
proctal_CFLAGS = -I$(srcdir)/src/cli -Isrc/cli -I$(proctal_src_lib_include) $(proctal_cflags)

# C library.
libproctal_la_SOURCES = \
	src/lib/impl/impl.h \
	src/lib/impl/linux.c \
	src/lib/proctal.h \
	src/lib/proctal.c \
	src/lib/error.c \
	src/lib/watch.c \
	src/lib/freeze.c \
	src/lib/write.c \
	src/lib/read.c \
	src/lib/address.c \
	src/lib/region.c \
	src/lib/alloc.c \
	src/lib/execute.c \
	src/lib/linux/address.c \
	src/lib/linux/address.h \
	src/lib/linux/region.c \
	src/lib/linux/region.h \
	src/lib/linux/alloc.c \
	src/lib/linux/alloc.h \
	src/lib/linux/execute.c \
	src/lib/linux/execute.h \
	src/lib/linux/mem.c \
	src/lib/linux/mem.h \
	src/lib/linux/proc.c \
	src/lib/linux/proc.h \
	src/lib/linux/ptrace.c \
	src/lib/linux/ptrace.h \
	src/lib/linux/proctal.c \
	src/lib/linux/proctal.h \
	src/lib/linux/watch.c \
	src/lib/linux/watch.h \
	src/lib/x86/dr.c \
	src/lib/x86/dr.h
libproctal_la_CFLAGS = -I$(srcdir)/src/lib -Isrc/lib $(proctal_cflags)
libproctal_la_LDFLAGS = -version-info $(PROCTAL_LIBRARY_VERSION)

# Tests.
tests_invalid_patterns_CFLAGS = -I$(srcdir)/src $(proctal_cflags)
tests_invalid_patterns_LDFLAGS = src/cli/proctal-pattern.o src/cli/proctal-parser.o

tests_valid_patterns_CFLAGS = -I$(srcdir)/src $(proctal_cflags)
tests_valid_patterns_LDFLAGS = src/cli/proctal-pattern.o src/cli/proctal-parser.o

tests_parse_valid_ascii_CFLAGS = -I$(srcdir)/src $(proctal_cflags)
tests_parse_valid_ascii_LDFLAGS = src/cli/val/proctal-text.o

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
