MAKEFLAGS = --no-print-directory

bin_PROGRAMS =
dist_man_MANS =
EXTRA_DIST = README.rst COPYING CONTRIBUTING
CLEANFILES =
check_PROGRAMS =
dist_check_SCRIPTS =
lib_LTLIBRARIES =
include_HEADERS =
noinst_LIBRARIES =
TESTS =

clean-local: darr-clean acur-clean

dist-hook: darr-dist-hook acur-dist-hook


# CLI
###############################################################################
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
proctal_LDADD = libproctal.la libswbuf.a libchunk.a libpq.a libclival.a libcliparser.a libcliassembler.a $(PROCTAL_LDFLAGS)
proctal_CFLAGS = $(PROCTAL_CFLAGS)
EXTRA_proctal_DEPENDENCIES = \
	darr/libdarr.a \
	acur/libacur.a

noinst_LIBRARIES += libclival.a
libclival_a_SOURCES = \
	src/cli/val/integer.h \
	src/cli/val/integer.c \
	src/cli/val/integer-sign-unsigned.c \
	src/cli/val/integer-sign-signed.c \
	src/cli/val/integer-endianness.c \
	src/cli/val/ieee754.h \
	src/cli/val/ieee754.c \
	src/cli/val/address.h \
	src/cli/val/address.c \
	src/cli/val/byte.h \
	src/cli/val/byte.c \
	src/cli/val/text.h \
	src/cli/val/text.c \
	src/cli/val/text-encoding-ascii.c \
	src/cli/val/assembler.h \
	src/cli/val/assembler.c \
	src/cli/val/filter.h \
	src/cli/val/filter.c \
	src/cli/val/x86.h \
	src/cli/val/x86.c \
	src/cli/val/arm.h \
	src/cli/val/arm.c \
	src/cli/val/aarch64.h \
	src/cli/val/aarch64.c \
	src/cli/val.h \
	src/cli/val.c
libclival_a_CFLAGS = $(PROCTAL_CFLAGS)

noinst_LIBRARIES += libcliparser.a
libcliparser_a_SOURCES = \
	src/cli/parser.h \
	src/cli/parser.c \
	src/cli/parser-name.c
libcliparser_a_CFLAGS = $(PROCTAL_CFLAGS)

noinst_LIBRARIES += libcliassembler.a
libcliassembler_a_SOURCES = \
	src/cli/assembler.h \
	src/cli/assembler/internal.h \
	src/cli/assembler/implementation.h \
	src/cli/assembler/internal.c \
	src/cli/assembler/interface.c

if PROCTAL_CAPSTONE

libcliassembler_a_SOURCES += \
	src/cli/assembler/implementation/capstone-keystone/with-capstone.c

else

libcliassembler_a_SOURCES += \
	src/cli/assembler/implementation/capstone-keystone/without-capstone.c

endif

if PROCTAL_KEYSTONE

libcliassembler_a_SOURCES += \
	src/cli/assembler/implementation/capstone-keystone/with-keystone.c

else

libcliassembler_a_SOURCES += \
	src/cli/assembler/implementation/capstone-keystone/without-keystone.c

endif

libcliassembler_a_CFLAGS = $(PROCTAL_CFLAGS)

TESTS += tests/cli/invalid-patterns
check_PROGRAMS += tests/cli/invalid-patterns
tests_cli_invalid_patterns_SOURCES = src/cli/tests/invalid-patterns.c
tests_cli_invalid_patterns_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_invalid_patterns_LDFLAGS = src/cli/proctal-pattern.o libcliparser.a

TESTS += tests/cli/valid-patterns
check_PROGRAMS += tests/cli/valid-patterns
tests_cli_valid_patterns_SOURCES = src/cli/tests/valid-patterns.c
tests_cli_valid_patterns_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_valid_patterns_LDFLAGS = src/cli/proctal-pattern.o libcliparser.a

TESTS += tests/cli/val/parse-valid-ascii
check_PROGRAMS += tests/cli/val/parse-valid-ascii
tests_cli_val_parse_valid_ascii_SOURCES = src/cli/val/tests/parse-valid-ascii.c
tests_cli_val_parse_valid_ascii_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_val_parse_valid_ascii_LDADD = libclival.a libcliassembler.a libcliparser.a $(PROCTAL_LDFLAGS)

TESTS += tests/cli/val/parse-bin-valid-ascii
check_PROGRAMS += tests/cli/val/parse-bin-valid-ascii
tests_cli_val_parse_bin_valid_ascii_SOURCES = src/cli/val/tests/parse-bin-valid-ascii.c
tests_cli_val_parse_bin_valid_ascii_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_val_parse_bin_valid_ascii_LDADD = libclival.a libcliassembler.a libcliparser.a $(PROCTAL_LDFLAGS)

TESTS += tests/cli/val/parse-invalid-ascii
check_PROGRAMS += tests/cli/val/parse-invalid-ascii
tests_cli_val_parse_invalid_ascii_SOURCES = src/cli/val/tests/parse-invalid-ascii.c
tests_cli_val_parse_invalid_ascii_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_val_parse_invalid_ascii_LDADD = libclival.a libcliassembler.a libcliparser.a $(PROCTAL_LDFLAGS)

TESTS += tests/cli/val/parse-bin-invalid-ascii
check_PROGRAMS += tests/cli/val/parse-bin-invalid-ascii
tests_cli_val_parse_bin_invalid_ascii_SOURCES = src/cli/val/tests/parse-bin-invalid-ascii.c
tests_cli_val_parse_bin_invalid_ascii_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_val_parse_bin_invalid_ascii_LDADD = libclival.a libcliassembler.a libcliparser.a $(PROCTAL_LDFLAGS)

TESTS += tests/cli/val/add
check_PROGRAMS += tests/cli/val/add
tests_cli_val_add_SOURCES = src/cli/val/tests/add.c
tests_cli_val_add_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_val_add_LDADD = libotrap.a libclival.a libcliassembler.a libcliparser.a $(PROCTAL_LDFLAGS)

TESTS += tests/cli/val/sub
check_PROGRAMS += tests/cli/val/sub
tests_cli_val_sub_SOURCES = src/cli/val/tests/sub.c
tests_cli_val_sub_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_val_sub_LDADD =  libotrap.a libclival.a libcliassembler.a libcliparser.a $(PROCTAL_LDFLAGS)

TESTS += tests/cli/val/cmp
check_PROGRAMS += tests/cli/val/cmp
tests_cli_val_cmp_SOURCES = src/cli/val/tests/cmp.c
tests_cli_val_cmp_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_val_cmp_LDADD = libotrap.a libclival.a libcliassembler.a libcliparser.a $(PROCTAL_LDFLAGS)

TESTS += tests/cli/val/print
check_PROGRAMS += tests/cli/val/print
tests_cli_val_print_SOURCES = src/cli/val/tests/print.c
tests_cli_val_print_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_val_print_LDADD = libotrap.a libclival.a libcliassembler.a libcliparser.a $(PROCTAL_LDFLAGS)

TESTS += tests/cli/val/parse
check_PROGRAMS += tests/cli/val/parse
tests_cli_val_parse_SOURCES = src/cli/val/tests/parse.c
tests_cli_val_parse_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_val_parse_LDADD = libotrap.a libclival.a libcliassembler.a libcliparser.a $(PROCTAL_LDFLAGS)

TESTS += tests/cli/val/filter-compare
check_PROGRAMS += tests/cli/val/filter-compare
tests_cli_val_filter_compare_SOURCES = src/cli/val/tests/filter-compare.c
tests_cli_val_filter_compare_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_val_filter_compare_LDADD = libclival.a libcliassembler.a libcliparser.a $(PROCTAL_LDFLAGS)

TESTS += tests/cli/val/filter-compare-prev
check_PROGRAMS += tests/cli/val/filter-compare-prev
tests_cli_val_filter_compare_prev_SOURCES = src/cli/val/tests/filter-compare-prev.c
tests_cli_val_filter_compare_prev_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_val_filter_compare_prev_LDADD = libclival.a libcliassembler.a libcliparser.a $(PROCTAL_LDFLAGS)

TESTS += tests/cli/val/integer-endianness
check_PROGRAMS += tests/cli/val/integer-endianness
tests_cli_val_integer_endianness_SOURCES = src/cli/val/tests/integer-endianness.c
tests_cli_val_integer_endianness_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_val_integer_endianness_LDADD = libclival.a libcliassembler.a libcliparser.a libotrap.a $(PROCTAL_LDFLAGS)

TESTS += src/cli/tests/invalid-type-arguments.py
dist_check_SCRIPTS += src/cli/tests/invalid-type-arguments.py

TESTS += src/cli/tests/freeze-multiple-threads.py
dist_check_SCRIPTS += src/cli/tests/freeze-multiple-threads.py

TESTS += src/cli/tests/watch-multiple-threads.py
dist_check_SCRIPTS += src/cli/tests/watch-multiple-threads.py

TESTS += src/cli/tests/search-boundaries.py
dist_check_SCRIPTS += src/cli/tests/search-boundaries.py

TESTS += src/cli/tests/execute-code.py
dist_check_SCRIPTS += src/cli/tests/execute-code.py

TESTS += src/cli/tests/allocate-permissions.py
dist_check_SCRIPTS += src/cli/tests/allocate-permissions.py

TESTS += src/cli/tests/allocate-permissions-default.py
dist_check_SCRIPTS += src/cli/tests/allocate-permissions-default.py

TESTS += src/cli/tests/deallocate.py
dist_check_SCRIPTS += src/cli/tests/deallocate.py

TESTS += src/cli/tests/search-permissions-default.py
dist_check_SCRIPTS += src/cli/tests/search-permissions-default.py

TESTS += src/cli/tests/dump-range.py
dist_check_SCRIPTS += src/cli/tests/dump-range.py

TESTS += src/cli/tests/search-range.py
dist_check_SCRIPTS += src/cli/tests/search-range.py

TESTS += src/cli/tests/search-review-range.py
dist_check_SCRIPTS += src/cli/tests/search-review-range.py

TESTS += src/cli/tests/pattern-range.py
dist_check_SCRIPTS += src/cli/tests/pattern-range.py

TESTS += src/cli/tests/watch-range.py
dist_check_SCRIPTS += src/cli/tests/watch-range.py

TESTS += src/cli/tests/watch-unique.py
dist_check_SCRIPTS += src/cli/tests/watch-unique.py

TESTS += src/cli/tests/watch-uncaught-trap-bug.py
dist_check_SCRIPTS += src/cli/tests/watch-uncaught-trap-bug.py

check_PROGRAMS += tests/cli/program/spit-back-mt
tests_cli_program_spit_back_mt_SOURCES = src/cli/tests/program/spit-back-mt.c
tests_cli_program_spit_back_mt_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_program_spit_back_mt_LDADD = -lpthread

check_PROGRAMS += tests/cli/program/read-mem-mt
tests_cli_program_read_mem_mt_SOURCES = src/cli/tests/program/read-mem-mt.c
tests_cli_program_read_mem_mt_CFLAGS = $(PROCTAL_CFLAGS)
tests_cli_program_read_mem_mt_LDADD = -lpthread

check_PROGRAMS += tests/cli/program/read-mem
tests_cli_program_read_mem_SOURCES = src/cli/tests/program/read-mem.c
tests_cli_program_read_mem_CFLAGS = $(PROCTAL_CFLAGS)

check_PROGRAMS += tests/cli/program/sleeper
tests_cli_program_sleeper_SOURCES = src/cli/tests/program/sleeper.c
tests_cli_program_sleeper_CFLAGS = $(PROCTAL_CFLAGS)

# Always keep in mind that, according to sections 9.4.1 and 27.8 of the
# documentation, automake does not support a convenient method for specifying
# dependencies for automatically generated object files of *_SOURCES c files
# and that you should be wary of renamed objects when *_CFLAGS is defined.
src/cli/yuck/proctal-main.$(OBJEXT): src/cli/yuck/args.yucc

# Expands M4 macros.
src/cli/yuck/args.yuck: $(srcdir)/src/cli/yuck/args.yuck.m4
	$(AM_V_GEN)m4 $^ > $@

# PHP scripts that generate C code.
%.c: %.c.php
	$(AM_V_GEN)$(PHP) $^ > $@

# Generates argument parsing code.
src/cli/yuck/args.yucc: src/cli/yuck/args.yuck
	$(AM_V_GEN)$(YUCK) gen --no-auto-flags --no-auto-actions $^ -o $@

# Generates man page.
src/cli/proctal.1: src/cli/yuck/args.yuck
	$(AM_V_GEN)$(YUCK) genman $^ -o $@


# API
###############################################################################
CLEANFILES += \
	src/api/darr/darr.h \
	src/api/darr/darr.c \
	src/api/acur/acur.h \
	src/api/acur/acur.c
lib_LTLIBRARIES += libproctal.la
include_HEADERS += src/api/include/proctal.h
libproctal_la_SOURCES = \
	src/api/darr/darr.h \
	src/api/darr/darr.c \
	src/api/darr/memory-support.h \
	src/api/darr/memory-support.c \
	src/api/acur/acur.h \
	src/api/acur/acur.c \
	src/api/implementation.h \
	src/api/proctal.h \
	src/api/version.c \
	src/api/error.c \
	src/api/error-message.c \
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
	src/api/init.c

if PROCTAL_PLATFORM_LINUX

libproctal_la_SOURCES += \
	src/api/linux/implementation.c \
	src/api/linux/address.c \
	src/api/linux/address.h \
	src/api/linux/region.c \
	src/api/linux/region.h \
	src/api/linux/allocate.c \
	src/api/linux/allocate.h \
	src/api/linux/execute.h \
	src/api/linux/execute/implementation.h \
	src/api/linux/execute/interface.c \
	src/api/linux/mem.c \
	src/api/linux/mem.h \
	src/api/linux/proc-maps.c \
	src/api/linux/proc.c \
	src/api/linux/proc.h \
	src/api/linux/ptrace.h \
	src/api/linux/ptrace/error-checking.c \
	src/api/linux/ptrace/implementation.h \
	src/api/linux/ptrace/interface.c \
	src/api/linux/ptrace/internal.h \
	src/api/linux/proctal.c \
	src/api/linux/proctal.h \
	src/api/linux/watch/interface.c \
	src/api/linux/watch/implementation.h \
	src/api/linux/watch.h

TESTS += tests/api/linux/proc-path-size
check_PROGRAMS += tests/api/linux/proc-path-size
tests_api_linux_proc_path_size_SOURCES = src/api/linux/tests/proc-path-size.c
tests_api_linux_proc_path_size_CFLAGS = $(PROCTAL_CFLAGS)
tests_api_linux_proc_path_size_LDADD = libproctal.la

TESTS += tests/api/linux/proc-maps/correct-properties
check_PROGRAMS += tests/api/linux/proc-maps/correct-properties
tests_api_linux_proc_maps_correct_properties_SOURCES = src/api/linux/tests/proc-maps/correct-properties.c
tests_api_linux_proc_maps_correct_properties_CFLAGS = $(PROCTAL_CFLAGS)
tests_api_linux_proc_maps_correct_properties_LDADD = libproctal.la

TESTS += tests/api/linux/proc-maps/check
check_PROGRAMS += tests/api/linux/proc-maps/check
tests_api_linux_proc_maps_check_SOURCES = src/api/linux/tests/proc-maps/check.c
tests_api_linux_proc_maps_check_CFLAGS = $(PROCTAL_CFLAGS)
tests_api_linux_proc_maps_check_LDADD = libproctal.la

if PROCTAL_CPU_ARCHITECTURE_X86_64

libproctal_la_SOURCES += \
	src/api/linux/ptrace/x86_64/instruction-pointer.c \
	src/api/linux/ptrace/x86_64/register.c \
	src/api/linux/ptrace/user-register.c

libproctal_la_SOURCES += \
	src/api/linux/execute/x86_64/no-op-code.c \
	src/api/linux/execute/x86_64/syscall.c \
	src/api/linux/execute/x86_64/trap-code.c \
	src/api/linux/execute/x86_64/savestate.c \
	src/api/linux/execute/x86_64/stackframe.c \
	src/api/linux/execute/hijack-main.c

libproctal_la_SOURCES += \
	src/api/linux/watch/x86_64/breakpoint.c

else

libproctal_la_SOURCES += \
	src/api/linux/ptrace/unimplemented.c

libproctal_la_SOURCES += \
	src/api/linux/execute/unimplemented.c

libproctal_la_SOURCES += \
	src/api/linux/watch/unimplemented.c

endif

else
if PROCTAL_PLATFORM_WINDOWS

libproctal_la_SOURCES += \
	src/api/windows/proctal.h \
	src/api/windows/proctal.c \
	src/api/windows/memory.h \
	src/api/windows/memory.c \
	src/api/windows/implementation.c

else

libproctal_la_SOURCES += \
	src/api/unimplemented.c

endif
endif

if PROCTAL_CPU_ARCHITECTURE_X86_64

libproctal_la_SOURCES += \
	src/api/x86_64/dr.c \
	src/api/x86_64/dr.h

endif

libproctal_la_CFLAGS = $(PROCTAL_CFLAGS)
libproctal_la_LDFLAGS = -version-info $(PROCTAL_LIBTOOL_VERSION)

src/api/darr/darr.h: $(srcdir)/darr/src/darr.h
	$(AM_V_GEN)$(SED) 's/darr_/proctal_darr_/g' $^ > $@
	$(AM_V_GEN)$(SED) -i 's/struct darr/struct proctal_darr/g' $@

src/api/darr/darr.c: $(srcdir)/darr/src/darr.c src/api/darr/darr.h
	$(AM_V_GEN)$(SED) 's/darr_/proctal_darr_/g' $^ > $@
	$(AM_V_GEN)$(SED) -i 's/struct darr/struct proctal_darr/g' $@

src/api/acur/acur.h: $(srcdir)/acur/src/acur.h
	$(AM_V_GEN)$(SED) 's/acur_/proctal_acur_/g' $^ > $@
	$(AM_V_GEN)$(SED) -i 's/struct acur/struct proctal_acur/g' $@

src/api/acur/acur.c: $(srcdir)/acur/src/acur.c src/api/acur/acur.h
	$(AM_V_GEN)$(SED) 's/acur_/proctal_acur_/g' $^ > $@
	$(AM_V_GEN)$(SED) -i 's/struct acur/struct proctal_acur/g' $@

TESTS += tests/api/darr/realloc/null-argument
check_PROGRAMS += tests/api/darr/realloc/null-argument
tests_api_darr_realloc_null_argument_SOURCES = src/api/darr/tests/realloc/null-argument.c
tests_api_darr_realloc_null_argument_CFLAGS = $(PROCTAL_CFLAGS)
tests_api_darr_realloc_null_argument_LDADD = libproctal.la tests/api/darr/realloc/libblocksize.a

TESTS += tests/api/darr/realloc/decrease-size-new-block
check_PROGRAMS += tests/api/darr/realloc/decrease-size-new-block
tests_api_darr_realloc_decrease_size_new_block_SOURCES = src/api/darr/tests/realloc/decrease-size-new-block.c
tests_api_darr_realloc_decrease_size_new_block_CFLAGS = $(PROCTAL_CFLAGS)
tests_api_darr_realloc_decrease_size_new_block_LDADD = libproctal.la tests/api/darr/realloc/libblocksize.a

TESTS += tests/api/darr/realloc/decrease-size-same-block
check_PROGRAMS += tests/api/darr/realloc/decrease-size-same-block
tests_api_darr_realloc_decrease_size_same_block_SOURCES = src/api/darr/tests/realloc/decrease-size-same-block.c
tests_api_darr_realloc_decrease_size_same_block_CFLAGS = $(PROCTAL_CFLAGS)
tests_api_darr_realloc_decrease_size_same_block_LDADD = libproctal.la tests/api/darr/realloc/libblocksize.a

TESTS += tests/api/darr/realloc/increase-size-new-block
check_PROGRAMS += tests/api/darr/realloc/increase-size-new-block
tests_api_darr_realloc_increase_size_new_block_SOURCES = src/api/darr/tests/realloc/increase-size-new-block.c
tests_api_darr_realloc_increase_size_new_block_CFLAGS = $(PROCTAL_CFLAGS)
tests_api_darr_realloc_increase_size_new_block_LDADD = libproctal.la tests/api/darr/realloc/libblocksize.a

# Realloc test utilities
noinst_LIBRARIES += tests/api/darr/realloc/libblocksize.a
tests_api_darr_realloc_libblocksize_a_SOURCES = \
	src/api/darr/tests/realloc/util/block-size.h \
	src/api/darr/tests/realloc/util/block-size.c
tests_api_darr_realloc_libblocksize_a_CFLAGS = $(PROCTAL_CFLAGS)


# Swbuf
###############################################################################
noinst_LIBRARIES += libswbuf.a
libswbuf_a_SOURCES = \
	src/swbuf/swbuf.h \
	src/swbuf/swbuf.c
libswbuf_a_CFLAGS = $(PROCTAL_CFLAGS)

TESTS += tests/swbuf/init-fail-alloc
check_PROGRAMS += tests/swbuf/init-fail-alloc
tests_swbuf_init_fail_alloc_SOURCES = src/swbuf/tests/init-fail-alloc.c
tests_swbuf_init_fail_alloc_CFLAGS = $(PROCTAL_CFLAGS)
tests_swbuf_init_fail_alloc_LDADD = libswbuf.a

TESTS += tests/swbuf/init-succeed-alloc
check_PROGRAMS += tests/swbuf/init-succeed-alloc
tests_swbuf_init_succeed_alloc_SOURCES = src/swbuf/tests/init-succeed-alloc.c
tests_swbuf_init_succeed_alloc_CFLAGS = $(PROCTAL_CFLAGS)
tests_swbuf_init_succeed_alloc_LDADD = libswbuf.a

TESTS += tests/swbuf/swap
check_PROGRAMS += tests/swbuf/swap
tests_swbuf_swap_SOURCES = src/swbuf/tests/swap.c
tests_swbuf_swap_CFLAGS = $(PROCTAL_CFLAGS)
tests_swbuf_swap_LDADD = libswbuf.a

TESTS += tests/swbuf/address-offset
check_PROGRAMS += tests/swbuf/address-offset
tests_swbuf_address_offset_SOURCES = src/swbuf/tests/address-offset.c
tests_swbuf_address_offset_CFLAGS = $(PROCTAL_CFLAGS)
tests_swbuf_address_offset_LDADD = libswbuf.a

TESTS += tests/swbuf/size
check_PROGRAMS += tests/swbuf/size
tests_swbuf_size_SOURCES = src/swbuf/tests/size.c
tests_swbuf_size_CFLAGS = $(PROCTAL_CFLAGS)
tests_swbuf_size_LDADD = libswbuf.a


# Chunk
###############################################################################
noinst_LIBRARIES += libchunk.a
libchunk_a_SOURCES = \
	src/chunk/chunk.h \
	src/chunk/chunk.c
libchunk_a_CFLAGS = $(PROCTAL_CFLAGS)

TESTS += tests/chunk/leftover
check_PROGRAMS += tests/chunk/leftover
tests_chunk_leftover_SOURCES = src/chunk/tests/leftover.c
tests_chunk_leftover_CFLAGS = $(PROCTAL_CFLAGS)
tests_chunk_leftover_LDADD = libchunk.a

TESTS += tests/chunk/evenly
check_PROGRAMS += tests/chunk/evenly
tests_chunk_evenly_SOURCES = src/chunk/tests/evenly.c
tests_chunk_evenly_CFLAGS = $(PROCTAL_CFLAGS)
tests_chunk_evenly_LDADD = libchunk.a

TESTS += tests/chunk/finished
check_PROGRAMS += tests/chunk/finished
tests_chunk_finished_SOURCES = src/chunk/tests/finished.c
tests_chunk_finished_CFLAGS = $(PROCTAL_CFLAGS)
tests_chunk_finished_LDADD = libchunk.a


# Magic
###############################################################################
EXTRA_DIST += src/magic/magic.h

TESTS += tests/magic/array-size
check_PROGRAMS += tests/magic/array-size
tests_magic_array_size_SOURCES = src/magic/tests/array-size.c
tests_magic_array_size_CFLAGS = $(PROCTAL_CFLAGS)

TESTS += tests/magic/compare
check_PROGRAMS += tests/magic/compare
tests_magic_compare_SOURCES = src/magic/tests/compare.c
tests_magic_compare_CFLAGS = $(PROCTAL_CFLAGS)

TESTS += tests/magic/deref
check_PROGRAMS += tests/magic/deref
tests_magic_deref_SOURCES = src/magic/tests/deref.c
tests_magic_deref_CFLAGS = $(PROCTAL_CFLAGS)


# Otrap
###############################################################################
noinst_LIBRARIES += libotrap.a
libotrap_a_SOURCES = \
	src/otrap/otrap.h \
	src/otrap/otrap.c
libotrap_a_CFLAGS = $(PROCTAL_CFLAGS)

TESTS += tests/otrap/read
check_PROGRAMS += tests/otrap/read
tests_otrap_read_SOURCES = src/otrap/tests/read.c
tests_otrap_read_CFLAGS = $(PROCTAL_CFLAGS)
tests_otrap_read_LDADD = libotrap.a

TESTS += tests/otrap/read-twice
check_PROGRAMS += tests/otrap/read-twice
tests_otrap_read_twice_SOURCES = src/otrap/tests/read-twice.c
tests_otrap_read_twice_CFLAGS = $(PROCTAL_CFLAGS)
tests_otrap_read_twice_LDADD = libotrap.a

TESTS += tests/otrap/read-too-much
check_PROGRAMS += tests/otrap/read-too-much
tests_otrap_read_too_much_SOURCES = src/otrap/tests/read-too-much.c
tests_otrap_read_too_much_CFLAGS = $(PROCTAL_CFLAGS)
tests_otrap_read_too_much_LDADD = libotrap.a

TESTS += tests/otrap/read-nothing
check_PROGRAMS += tests/otrap/read-nothing
tests_otrap_read_nothing_SOURCES = src/otrap/tests/read-nothing.c
tests_otrap_read_nothing_CFLAGS = $(PROCTAL_CFLAGS)
tests_otrap_read_nothing_LDADD = libotrap.a

TESTS += tests/otrap/skip
check_PROGRAMS += tests/otrap/skip
tests_otrap_skip_SOURCES = src/otrap/tests/skip.c
tests_otrap_skip_CFLAGS = $(PROCTAL_CFLAGS)
tests_otrap_skip_LDADD = libotrap.a

TESTS += tests/otrap/skip-twice
check_PROGRAMS += tests/otrap/skip-twice
tests_otrap_skip_twice_SOURCES = src/otrap/tests/skip-twice.c
tests_otrap_skip_twice_CFLAGS = $(PROCTAL_CFLAGS)
tests_otrap_skip_twice_LDADD = libotrap.a

TESTS += tests/otrap/skip-too-much
check_PROGRAMS += tests/otrap/skip-too-much
tests_otrap_skip_too_much_SOURCES = src/otrap/tests/skip-too-much.c
tests_otrap_skip_too_much_CFLAGS = $(PROCTAL_CFLAGS)
tests_otrap_skip_too_much_LDADD = libotrap.a

TESTS += tests/otrap/skip-nothing
check_PROGRAMS += tests/otrap/skip-nothing
tests_otrap_skip_nothing_SOURCES = src/otrap/tests/skip-nothing.c
tests_otrap_skip_nothing_CFLAGS = $(PROCTAL_CFLAGS)
tests_otrap_skip_nothing_LDADD = libotrap.a


# Pq
###############################################################################
noinst_LIBRARIES += libpq.a
libpq_a_SOURCES = \
	src/pq/pq.h \
	src/pq/implementation.h \
	src/pq/quit-state.h \
	src/pq/quit-state.c \
	src/pq/interface.c
libpq_a_CFLAGS = $(PROCTAL_CFLAGS)

if PROCTAL_PLATFORM_LINUX

libpq_a_SOURCES += src/pq/posix/implementation.c

else
if PROCTAL_PLATFORM_WINDOWS

libpq_a_SOURCES += src/pq/windows-posix/implementation.c

else

libpq_a_SOURCES += src/pq/unimplemented.c

endif
endif


# Darr
###############################################################################
.PHONY: darr-dist-hook darr-clean darr/libdarr.a

darr-clean:
	$(MAKE) -C darr clean

darr/libdarr.a:
	$(AM_V_GEN)$(MAKE) $(AM_V_lt) -C darr libdarr.a

darr-dist-hook:
	cp -r $(srcdir)/darr $(distdir)
	rm -rf $(distdir)/darr/autom4te.cache
	rm -rf $(distdir)/darr/.git


# Acur
###############################################################################
.PHONY: acur-dist-hook acur-clean acur/libacur.a

acur-clean:
	$(MAKE) -C acur clean

acur/libacur.a:
	$(AM_V_GEN)$(MAKE) $(AM_V_lt) -C acur libacur.a

acur-dist-hook:
	cp -r $(srcdir)/acur $(distdir)
	rm -rf $(distdir)/acur/autom4te.cache
	rm -rf $(distdir)/acur/.git
