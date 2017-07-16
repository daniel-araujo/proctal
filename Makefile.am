bin_PROGRAMS =
dist_man_MANS =
EXTRA_DIST = README.md
CLEANFILES =
check_PROGRAMS =
dist_check_SCRIPTS =
lib_LTLIBRARIES =
include_HEADERS =
noinst_LIBRARIES =
TESTS =


# Cli tool.
bin_PROGRAMS += proctal
dist_man_MANS += src/cli/proctal.1
EXTRA_DIST += src/cli/yuck/args.yuck.m4 src/cli/yuck/args.yuck src/cli/yuck/args.yucc
CLEANFILES += src/cli/yuck/args.yuck src/cli/yuck/args.yucc
EXTRA_DIST += src/cli/parser-name.c.php
CLEANFILES += src/cli/parser-name.c
proctal_SOURCES = \
	src/cli/cmd/allocate.c \
	src/cli/cmd/allocate.h \
	src/cli/cmd/deallocate.c \
	src/cli/cmd/deallocate.h \
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
	src/cli/scanner.h \
	src/cli/scanner.c \
	src/cli/printer.h \
	src/cli/printer.c \
	src/cli/pattern.h \
	src/cli/pattern.c \
	src/cli/yuck/main.h \
	src/cli/yuck/main.c \
	src/cli/main.c
proctal_LDADD = libproctal.la libswbuf.a libchunk.a libclival.a libcliparser.a libcliassembler.a $(proctal_darr_ldflags) $(proctal_capstone_ldflags) $(proctal_keystone_ldflags)
proctal_CFLAGS = $(proctal_cflags)
EXTRA_proctal_DEPENDENCIES = \
	darr/libdarr.a

noinst_LIBRARIES += libclival.a
libclival_a_SOURCES = \
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
	src/cli/val/filter.h \
	src/cli/val/filter.c \
	src/cli/val.h \
	src/cli/val.c \
	src/cli/val-list.h \
	src/cli/val-list.c
libclival_a_CFLAGS = $(proctal_cflags)

noinst_LIBRARIES += libcliparser.a
libcliparser_a_SOURCES = \
	src/cli/parser.h \
	src/cli/parser.c \
	src/cli/parser-name.c
libcliparser_a_CFLAGS = $(proctal_cflags)

noinst_LIBRARIES += libcliassembler.a
libcliassembler_a_SOURCES = \
	src/cli/assembler.h \
	src/cli/assembler.c
libcliassembler_a_CFLAGS = $(proctal_cflags)

TESTS += tests/cli/invalid-patterns
check_PROGRAMS += tests/cli/invalid-patterns
tests_cli_invalid_patterns_SOURCES = src/cli/tests/invalid-patterns.c
tests_cli_invalid_patterns_CFLAGS = $(proctal_cflags)
tests_cli_invalid_patterns_LDFLAGS = src/cli/proctal-pattern.o libcliparser.a

TESTS += tests/cli/valid-patterns
check_PROGRAMS += tests/cli/valid-patterns
tests_cli_valid_patterns_SOURCES = src/cli/tests/valid-patterns.c
tests_cli_valid_patterns_CFLAGS = $(proctal_cflags)
tests_cli_valid_patterns_LDFLAGS = src/cli/proctal-pattern.o libcliparser.a

TESTS += tests/cli/val/parse-valid-ascii
check_PROGRAMS += tests/cli/val/parse-valid-ascii
tests_cli_val_parse_valid_ascii_SOURCES = src/cli/val/tests/parse-valid-ascii.c
tests_cli_val_parse_valid_ascii_CFLAGS = $(proctal_cflags)
tests_cli_val_parse_valid_ascii_LDADD = libclival.a libcliassembler.a libcliparser.a $(proctal_capstone_ldflags) $(proctal_keystone_ldflags)

TESTS += tests/cli/val/parse-bin-valid-ascii
check_PROGRAMS += tests/cli/val/parse-bin-valid-ascii
tests_cli_val_parse_bin_valid_ascii_SOURCES = src/cli/val/tests/parse-bin-valid-ascii.c
tests_cli_val_parse_bin_valid_ascii_CFLAGS = $(proctal_cflags)
tests_cli_val_parse_bin_valid_ascii_LDADD = libclival.a libcliassembler.a libcliparser.a $(proctal_capstone_ldflags) $(proctal_keystone_ldflags)

TESTS += tests/cli/val/parse-invalid-ascii
check_PROGRAMS += tests/cli/val/parse-invalid-ascii
tests_cli_val_parse_invalid_ascii_SOURCES = src/cli/val/tests/parse-invalid-ascii.c
tests_cli_val_parse_invalid_ascii_CFLAGS = $(proctal_cflags)
tests_cli_val_parse_invalid_ascii_LDADD = libclival.a libcliassembler.a libcliparser.a $(proctal_capstone_ldflags) $(proctal_keystone_ldflags)

TESTS += tests/cli/val/parse-bin-invalid-ascii
check_PROGRAMS += tests/cli/val/parse-bin-invalid-ascii
tests_cli_val_parse_bin_invalid_ascii_SOURCES = src/cli/val/tests/parse-bin-invalid-ascii.c
tests_cli_val_parse_bin_invalid_ascii_CFLAGS = $(proctal_cflags)
tests_cli_val_parse_bin_invalid_ascii_LDADD = libclival.a libcliassembler.a libcliparser.a $(proctal_capstone_ldflags) $(proctal_keystone_ldflags)

TESTS += tests/cli/val/add
check_PROGRAMS += tests/cli/val/add
tests_cli_val_add_SOURCES = src/cli/val/tests/add.c
tests_cli_val_add_CFLAGS = $(proctal_cflags)
tests_cli_val_add_LDADD = libotrap.a libclival.a libcliassembler.a libcliparser.a $(proctal_capstone_ldflags) $(proctal_keystone_ldflags)

TESTS += tests/cli/val/sub
check_PROGRAMS += tests/cli/val/sub
tests_cli_val_sub_SOURCES = src/cli/val/tests/sub.c
tests_cli_val_sub_CFLAGS = $(proctal_cflags)
tests_cli_val_sub_LDADD =  libotrap.a libclival.a libcliassembler.a libcliparser.a $(proctal_capstone_ldflags) $(proctal_keystone_ldflags)

TESTS += tests/cli/val/cmp
check_PROGRAMS += tests/cli/val/cmp
tests_cli_val_cmp_SOURCES = src/cli/val/tests/cmp.c
tests_cli_val_cmp_CFLAGS = $(proctal_cflags)
tests_cli_val_cmp_LDADD = libotrap.a libclival.a libcliassembler.a libcliparser.a $(proctal_capstone_ldflags) $(proctal_keystone_ldflags)

TESTS += tests/cli/val/print
check_PROGRAMS += tests/cli/val/print
tests_cli_val_print_SOURCES = src/cli/val/tests/print.c
tests_cli_val_print_CFLAGS = $(proctal_cflags)
tests_cli_val_print_LDADD = libotrap.a libclival.a libcliassembler.a libcliparser.a $(proctal_capstone_ldflags) $(proctal_keystone_ldflags)

TESTS += tests/cli/val/parse
check_PROGRAMS += tests/cli/val/parse
tests_cli_val_parse_SOURCES = src/cli/val/tests/parse.c
tests_cli_val_parse_CFLAGS = $(proctal_cflags)
tests_cli_val_parse_LDADD = libotrap.a libclival.a libcliassembler.a libcliparser.a $(proctal_capstone_ldflags) $(proctal_keystone_ldflags)

TESTS += tests/cli/val/filter-compare
check_PROGRAMS += tests/cli/val/filter-compare
tests_cli_val_filter_compare_SOURCES = src/cli/val/tests/filter-compare.c
tests_cli_val_filter_compare_CFLAGS = $(proctal_cflags)
tests_cli_val_filter_compare_LDADD = libclival.a libcliassembler.a libcliparser.a $(proctal_capstone_ldflags) $(proctal_keystone_ldflags)

TESTS += tests/cli/val/filter-compare-prev
check_PROGRAMS += tests/cli/val/filter-compare-prev
tests_cli_val_filter_compare_prev_SOURCES = src/cli/val/tests/filter-compare-prev.c
tests_cli_val_filter_compare_prev_CFLAGS = $(proctal_cflags)
tests_cli_val_filter_compare_prev_LDADD = libclival.a libcliassembler.a libcliparser.a $(proctal_capstone_ldflags) $(proctal_keystone_ldflags)

TESTS += src/cli/tests/invalid-type-arguments.py
dist_check_SCRIPTS += src/cli/tests/invalid-type-arguments.py

TESTS += src/cli/tests/freeze-multiple-threads.py
dist_check_SCRIPTS += src/cli/tests/freeze-multiple-threads.py

TESTS += src/cli/tests/watch-multiple-threads.py
dist_check_SCRIPTS += src/cli/tests/watch-multiple-threads.py

check_PROGRAMS += tests/cli/program/spit-back-mt
tests_cli_program_spit_back_mt_SOURCES = src/cli/tests/program/spit-back-mt.c
tests_cli_program_spit_back_mt_CFLAGS = $(proctal_cflags)
tests_cli_program_spit_back_mt_LDADD = -lpthread

check_PROGRAMS += tests/cli/program/read-mem-mt
tests_cli_program_read_mem_mt_SOURCES = src/cli/tests/program/read-mem-mt.c
tests_cli_program_read_mem_mt_CFLAGS = $(proctal_cflags)
tests_cli_program_read_mem_mt_LDADD = -lpthread

# Always keep in mind that, according to sections 9.4.1 and 27.8 of the
# documentation, automake does not support a convenient method for specifying
# dependencies for automatically generated object files of *_SOURCES c files
# and that you should be wary of renamed objects when *_CFLAGS is defined.
src/cli/yuck/proctal-main.$(OBJEXT): src/cli/yuck/args.yucc

# Expands M4 macros.
src/cli/yuck/args.yuck: $(srcdir)/src/cli/yuck/args.yuck.m4
	m4 $^ > $@

# PHP script that generates C code.
src/cli/parser-name.c: $(srcdir)/src/cli/parser-name.c.php
	$(PHP) $^ > $@

# Generates argument parsing code.
src/cli/yuck/args.yucc: src/cli/yuck/args.yuck
	$(YUCK) gen --no-auto-flags --no-auto-actions $^ -o $@

# Generates man page.
src/cli/proctal.1: src/cli/yuck/args.yuck
	$(YUCK) genman $^ -o $@


# C library.
lib_LTLIBRARIES += libproctal.la
include_HEADERS += src/api/include/proctal.h
libproctal_la_SOURCES = \
	src/api/impl/impl.h \
	src/api/impl/linux.c \
	src/api/proctal.h \
	src/api/error.c \
	src/api/watch.c \
	src/api/freeze.c \
	src/api/write.c \
	src/api/read.c \
	src/api/address.c \
	src/api/region.c \
	src/api/allocate.c \
	src/api/execute.c \
	src/api/malloc.c \
	src/api/global.c \
	src/api/proc.c \
	src/api/init.c \
	src/api/linux/address.c \
	src/api/linux/address.h \
	src/api/linux/region.c \
	src/api/linux/region.h \
	src/api/linux/allocate.c \
	src/api/linux/allocate.h \
	src/api/linux/execute.c \
	src/api/linux/execute.h \
	src/api/linux/mem.c \
	src/api/linux/mem.h \
	src/api/linux/proc.c \
	src/api/linux/proc.h \
	src/api/linux/ptrace.c \
	src/api/linux/ptrace.h \
	src/api/linux/proctal.c \
	src/api/linux/proctal.h \
	src/api/linux/watch.c \
	src/api/linux/watch.h \
	src/api/x86/dr.c \
	src/api/x86/dr.h
libproctal_la_CFLAGS = $(proctal_cflags)
libproctal_la_LDFLAGS = -version-info $(PROCTAL_LIBRARY_VERSION)


# Swbuf module.
noinst_LIBRARIES += libswbuf.a
libswbuf_a_SOURCES = \
	src/swbuf/swbuf.h \
	src/swbuf/swbuf.c
libswbuf_a_CFLAGS = $(proctal_cflags)

TESTS += tests/swbuf/init-fail-alloc
check_PROGRAMS += tests/swbuf/init-fail-alloc
tests_swbuf_init_fail_alloc_SOURCES = src/swbuf/tests/init-fail-alloc.c
tests_swbuf_init_fail_alloc_CFLAGS = $(proctal_cflags)
tests_swbuf_init_fail_alloc_LDADD = libswbuf.a

TESTS += tests/swbuf/init-succeed-alloc
check_PROGRAMS += tests/swbuf/init-succeed-alloc
tests_swbuf_init_succeed_alloc_SOURCES = src/swbuf/tests/init-succeed-alloc.c
tests_swbuf_init_succeed_alloc_CFLAGS = $(proctal_cflags)
tests_swbuf_init_succeed_alloc_LDADD = libswbuf.a

TESTS += tests/swbuf/swap
check_PROGRAMS += tests/swbuf/swap
tests_swbuf_swap_SOURCES = src/swbuf/tests/swap.c
tests_swbuf_swap_CFLAGS = $(proctal_cflags)
tests_swbuf_swap_LDADD = libswbuf.a

TESTS += tests/swbuf/address-offset
check_PROGRAMS += tests/swbuf/address-offset
tests_swbuf_address_offset_SOURCES = src/swbuf/tests/address-offset.c
tests_swbuf_address_offset_CFLAGS = $(proctal_cflags)
tests_swbuf_address_offset_LDADD = libswbuf.a

TESTS += tests/swbuf/size
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

TESTS += tests/chunk/leftover
check_PROGRAMS += tests/chunk/leftover
tests_chunk_leftover_SOURCES = src/chunk/tests/leftover.c
tests_chunk_leftover_CFLAGS = $(proctal_cflags)
tests_chunk_leftover_LDADD = libchunk.a

TESTS += tests/chunk/evenly
check_PROGRAMS += tests/chunk/evenly
tests_chunk_evenly_SOURCES = src/chunk/tests/evenly.c
tests_chunk_evenly_CFLAGS = $(proctal_cflags)
tests_chunk_evenly_LDADD = libchunk.a

TESTS += tests/chunk/finished
check_PROGRAMS += tests/chunk/finished
tests_chunk_finished_SOURCES = src/chunk/tests/finished.c
tests_chunk_finished_CFLAGS = $(proctal_cflags)
tests_chunk_finished_LDADD = libchunk.a


# Magic module.
EXTRA_DIST += src/magic/magic.h

TESTS += tests/magic/array-size
check_PROGRAMS += tests/magic/array-size
tests_magic_array_size_SOURCES = src/magic/tests/array-size.c
tests_magic_array_size_CFLAGS = $(proctal_cflags)

TESTS += tests/magic/compare
check_PROGRAMS += tests/magic/compare
tests_magic_compare_SOURCES = src/magic/tests/compare.c
tests_magic_compare_CFLAGS = $(proctal_cflags)

TESTS += tests/magic/deref
check_PROGRAMS += tests/magic/deref
tests_magic_deref_SOURCES = src/magic/tests/deref.c
tests_magic_deref_CFLAGS = $(proctal_cflags)


# Otrap module.
noinst_LIBRARIES += libotrap.a
libotrap_a_SOURCES = \
	src/otrap/otrap.h \
	src/otrap/otrap.c
libotrap_a_CFLAGS = $(proctal_cflags)

TESTS += tests/otrap/read
check_PROGRAMS += tests/otrap/read
tests_otrap_read_SOURCES = src/otrap/tests/read.c
tests_otrap_read_CFLAGS = $(proctal_cflags)
tests_otrap_read_LDADD = libotrap.a

TESTS += tests/otrap/read-twice
check_PROGRAMS += tests/otrap/read-twice
tests_otrap_read_twice_SOURCES = src/otrap/tests/read-twice.c
tests_otrap_read_twice_CFLAGS = $(proctal_cflags)
tests_otrap_read_twice_LDADD = libotrap.a

TESTS += tests/otrap/read-too-much
check_PROGRAMS += tests/otrap/read-too-much
tests_otrap_read_too_much_SOURCES = src/otrap/tests/read-too-much.c
tests_otrap_read_too_much_CFLAGS = $(proctal_cflags)
tests_otrap_read_too_much_LDADD = libotrap.a

TESTS += tests/otrap/read-nothing
check_PROGRAMS += tests/otrap/read-nothing
tests_otrap_read_nothing_SOURCES = src/otrap/tests/read-nothing.c
tests_otrap_read_nothing_CFLAGS = $(proctal_cflags)
tests_otrap_read_nothing_LDADD = libotrap.a

TESTS += tests/otrap/skip
check_PROGRAMS += tests/otrap/skip
tests_otrap_skip_SOURCES = src/otrap/tests/skip.c
tests_otrap_skip_CFLAGS = $(proctal_cflags)
tests_otrap_skip_LDADD = libotrap.a

TESTS += tests/otrap/skip-twice
check_PROGRAMS += tests/otrap/skip-twice
tests_otrap_skip_twice_SOURCES = src/otrap/tests/skip-twice.c
tests_otrap_skip_twice_CFLAGS = $(proctal_cflags)
tests_otrap_skip_twice_LDADD = libotrap.a

TESTS += tests/otrap/skip-too-much
check_PROGRAMS += tests/otrap/skip-too-much
tests_otrap_skip_too_much_SOURCES = src/otrap/tests/skip-too-much.c
tests_otrap_skip_too_much_CFLAGS = $(proctal_cflags)
tests_otrap_skip_too_much_LDADD = libotrap.a

TESTS += tests/otrap/skip-nothing
check_PROGRAMS += tests/otrap/skip-nothing
tests_otrap_skip_nothing_SOURCES = src/otrap/tests/skip-nothing.c
tests_otrap_skip_nothing_CFLAGS = $(proctal_cflags)
tests_otrap_skip_nothing_LDADD = libotrap.a


# Darr.
CLEANFILES += darr/libdarr.a

darr/libdarr.a:
	cd darr && autoreconf -i && ./configure && make
