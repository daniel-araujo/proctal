bin_PROGRAMS =
dist_man_MANS =
EXTRA_DIST =
CLEANFILES =
check_PROGRAMS =
dist_check_SCRIPTS =
lib_LTLIBRARIES =
include_HEADERS =
noinst_LIBRARIES =

proctal_cflags_src_include = -iquote$(srcdir)/src -iquotesrc
proctal_cflags_src_lib_include = -I$(srcdir)/src/lib/include -Isrc/lib/include
proctal_cflags = $(proctal_cflags_src_include) -std=c11 -Wfatal-errors -Wall \
	-Wextra -Wpointer-arith \
	-Wno-switch $(proctal_xopen_flags) -Wno-unused-parameter \
	-Wno-unused-function $(proctal_posix_flags) -Wno-maybe-uninitialized

# Cli tool.
bin_PROGRAMS += proctal
dist_man_MANS += src/cli/proctal.1
EXTRA_DIST += src/cli/args.yuck.m4 src/cli/args.yuck src/cli/args.yucc \
	src/cli/parser-name.c.php
CLEANFILES += src/cli/args.yuck src/cli/args.yucc src/cli/parser-name.c
proctal_SOURCES = \
	src/cli/cmd/alloc.c \
	src/cli/cmd/alloc.h \
	src/cli/cmd/dealloc.c \
	src/cli/cmd/dealloc.h \
	src/cli/cmd/execute.c \
	src/cli/cmd/execute.h \
	src/cli/cmd/watch.c \
	src/cli/cmd/watch.h \
	src/cli/cmd/freeze.c \
	src/cli/cmd/freeze.h \
	src/cli/cmd/read.c \
	src/cli/cmd/read.h \
	src/cli/cmd/write.c \
	src/cli/cmd/write.h \
	src/cli/cmd/search.c \
	src/cli/cmd/search.h \
	src/cli/cmd/pattern.c \
	src/cli/cmd/pattern.h \
	src/cli/cmd/measure.c \
	src/cli/cmd/measure.h \
	src/cli/cmd/dump.c \
	src/cli/cmd/dump.h \
	src/cli/val/integer.h \
	src/cli/val/integer.c \
	src/cli/val/integer-sign-unsigned.c \
	src/cli/val/integer-sign-2scmpl.c \
	src/cli/val/ieee754.h \
	src/cli/val/ieee754.c \
	src/cli/val/address.h \
	src/cli/val/address.c \
	src/cli/val/byte.h \
	src/cli/val/byte.c \
	src/cli/val/text.h \
	src/cli/val/text.c \
	src/cli/val/text-charset-ascii.c \
	src/cli/val/instruction.h \
	src/cli/val/instruction.c \
	src/cli/val/native.h \
	src/cli/val.h \
	src/cli/val.c \
	src/cli/val-list.h \
	src/cli/val-list.c \
	src/cli/scanner.h \
	src/cli/scanner.c \
	src/cli/parser.h \
	src/cli/parser.c \
	src/cli/parser-name.c \
	src/cli/printer.h \
	src/cli/printer.c \
	src/cli/pattern.h \
	src/cli/pattern.c \
	src/cli/main.c
proctal_LDADD = libproctal.la libswbuf.a libchunk.a $(proctal_capstone_libs) $(proctal_keystone_libs)
proctal_CFLAGS = $(proctal_cflags)

check_PROGRAMS += tests/cli/invalid-patterns
tests_cli_invalid_patterns_SOURCES = src/cli/tests/invalid-patterns.c
tests_cli_invalid_patterns_CFLAGS = $(proctal_cflags)
tests_cli_invalid_patterns_LDFLAGS = src/cli/proctal-pattern.o src/cli/proctal-parser.o

check_PROGRAMS += tests/cli/valid-patterns
tests_cli_valid_patterns_SOURCES = src/cli/tests/valid-patterns.c
tests_cli_valid_patterns_CFLAGS = $(proctal_cflags)
tests_cli_valid_patterns_LDFLAGS = src/cli/proctal-pattern.o src/cli/proctal-parser.o

check_PROGRAMS += tests/cli/val/parse-valid-ascii
tests_cli_val_parse_valid_ascii_SOURCES = src/cli/val/tests/parse-valid-ascii.c
tests_cli_val_parse_valid_ascii_CFLAGS = $(proctal_cflags)
tests_cli_val_parse_valid_ascii_LDFLAGS = src/cli/val/proctal-text.o \
	src/cli/val/proctal-text-charset-ascii.o

check_PROGRAMS += tests/cli/val/parse-bin-valid-ascii
tests_cli_val_parse_bin_valid_ascii_SOURCES = src/cli/val/tests/parse-bin-valid-ascii.c
tests_cli_val_parse_bin_valid_ascii_CFLAGS = $(proctal_cflags)
tests_cli_val_parse_bin_valid_ascii_LDFLAGS = src/cli/val/proctal-text.o \
	src/cli/val/proctal-text-charset-ascii.o

check_PROGRAMS += tests/cli/val/parse-invalid-ascii
tests_cli_val_parse_invalid_ascii_SOURCES = src/cli/val/tests/parse-invalid-ascii.c
tests_cli_val_parse_invalid_ascii_CFLAGS = $(proctal_cflags)
tests_cli_val_parse_invalid_ascii_LDFLAGS = src/cli/val/proctal-text.o \
	src/cli/val/proctal-text-charset-ascii.o

check_PROGRAMS += tests/cli/val/parse-bin-invalid-ascii
tests_cli_val_parse_bin_invalid_ascii_SOURCES = src/cli/val/tests/parse-bin-invalid-ascii.c
tests_cli_val_parse_bin_invalid_ascii_CFLAGS = $(proctal_cflags)
tests_cli_val_parse_bin_invalid_ascii_LDFLAGS = src/cli/val/proctal-text.o \
	src/cli/val/proctal-text-charset-ascii.o

check_PROGRAMS += tests/cli/val/integer-add
tests_cli_val_integer_add_SOURCES = src/cli/val/tests/integer-add.c
tests_cli_val_integer_add_CFLAGS = $(proctal_cflags)
tests_cli_val_integer_add_LDFLAGS = src/cli/val/proctal-integer.o \
	src/cli/val/proctal-integer-sign-unsigned.o \
	src/cli/val/proctal-integer-sign-2scmpl.o

check_PROGRAMS += tests/cli/val/integer-sub
tests_cli_val_integer_sub_SOURCES = src/cli/val/tests/integer-sub.c
tests_cli_val_integer_sub_CFLAGS = $(proctal_cflags)
tests_cli_val_integer_sub_LDFLAGS = src/cli/val/proctal-integer.o \
	src/cli/val/proctal-integer-sign-unsigned.o \
	src/cli/val/proctal-integer-sign-2scmpl.o

check_PROGRAMS += tests/cli/val/integer-cmp
tests_cli_val_integer_cmp_SOURCES = src/cli/val/tests/integer-cmp.c
tests_cli_val_integer_cmp_CFLAGS = $(proctal_cflags)
tests_cli_val_integer_cmp_LDFLAGS = src/cli/val/proctal-integer.o \
	src/cli/val/proctal-integer-sign-unsigned.o \
	src/cli/val/proctal-integer-sign-2scmpl.o

dist_check_SCRIPTS += src/cli/tests/invalid-type-arguments.py

# Always keep in mind that, according to sections 9.4.1 and 27.8 of the
# documentation, automake does not support a convenient method for specifying
# dependencies for automatically generated object files of *_SOURCES c files
# and that you should be wary of renamed objects when *_CFLAGS is defined.
src/cli/proctal-main.$(OBJEXT): src/cli/args.yucc

# Expands M4 macros.
src/cli/args.yuck: $(srcdir)/src/cli/args.yuck.m4
	m4 $^ > $@

# PHP script that generates C code.
src/cli/parser-name.c: $(srcdir)/src/cli/parser-name.c.php
	$(PHP) $^ > $@

# Generates argument parsing code.
src/cli/args.yucc: src/cli/args.yuck
	$(YUCK) gen --no-auto-flags --no-auto-actions $^ -o $@

# Generates man page.
src/cli/proctal.1: src/cli/args.yuck
	$(YUCK) genman $^ -o $@


# C library.
lib_LTLIBRARIES += libproctal.la
include_HEADERS += src/lib/include/proctal.h
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
libproctal_la_CFLAGS = $(proctal_cflags)
libproctal_la_LDFLAGS = -version-info $(PROCTAL_LIBRARY_VERSION)


# Swbuf module.
noinst_LIBRARIES += libswbuf.a
libswbuf_a_SOURCES = \
	src/swbuf/swbuf.h \
	src/swbuf/swbuf.c
libswbuf_a_CFLAGS = $(proctal_cflags)

check_PROGRAMS += tests/swbuf/init-fail-alloc
tests_swbuf_init_fail_alloc_SOURCES = src/swbuf/tests/init-fail-alloc.c
tests_swbuf_init_fail_alloc_CFLAGS = $(proctal_cflags)
tests_swbuf_init_fail_alloc_LDADD = libswbuf.a

check_PROGRAMS += tests/swbuf/init-succeed-alloc
tests_swbuf_init_succeed_alloc_SOURCES = src/swbuf/tests/init-succeed-alloc.c
tests_swbuf_init_succeed_alloc_CFLAGS = $(proctal_cflags)
tests_swbuf_init_succeed_alloc_LDADD = libswbuf.a

check_PROGRAMS += tests/swbuf/swap
tests_swbuf_swap_SOURCES = src/swbuf/tests/swap.c
tests_swbuf_swap_CFLAGS = $(proctal_cflags)
tests_swbuf_swap_LDADD = libswbuf.a

check_PROGRAMS += tests/swbuf/address-offset
tests_swbuf_address_offset_SOURCES = src/swbuf/tests/address-offset.c
tests_swbuf_address_offset_CFLAGS = $(proctal_cflags)
tests_swbuf_address_offset_LDADD = libswbuf.a

check_PROGRAMS += tests/swbuf/size
tests_swbuf_size_SOURCES = src/swbuf/tests/size.c
tests_swbuf_size_CFLAGS = $(proctal_cflags)
tests_swbuf_size_LDADD = libswbuf.a


# Chunk module.
noinst_LIBRARIES += libchunk.a
libchunk_a_SOURCES = \
	src/chunk/chunk.h \
	src/chunk/chunk.c
libchunk_a_CFLAGS = $(proctal_cflags)

check_PROGRAMS += tests/chunk/leftover
tests_chunk_leftover_SOURCES = src/chunk/tests/leftover.c
tests_chunk_leftover_CFLAGS = $(proctal_cflags)
tests_chunk_leftover_LDADD = libchunk.a

check_PROGRAMS += tests/chunk/evenly
tests_chunk_evenly_SOURCES = src/chunk/tests/evenly.c
tests_chunk_evenly_CFLAGS = $(proctal_cflags)
tests_chunk_evenly_LDADD = libchunk.a

check_PROGRAMS += tests/chunk/finished
tests_chunk_finished_SOURCES = src/chunk/tests/finished.c
tests_chunk_finished_CFLAGS = $(proctal_cflags)
tests_chunk_finished_LDADD = libchunk.a


# Magic module.
EXTRA_DIST += src/magic/magic.h

check_PROGRAMS += tests/magic/array-size
tests_magic_array_size_SOURCES = src/magic/tests/array-size.c
tests_magic_array_size_CFLAGS = $(proctal_cflags)

check_PROGRAMS += tests/magic/compare
tests_magic_compare_SOURCES = src/magic/tests/compare.c
tests_magic_compare_CFLAGS = $(proctal_cflags)

check_PROGRAMS += tests/magic/deref
tests_magic_deref_SOURCES = src/magic/tests/deref.c
tests_magic_deref_CFLAGS = $(proctal_cflags)


TESTS = $(check_PROGRAMS) $(dist_check_SCRIPTS)
