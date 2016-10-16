bin_PROGRAMS = proctal
proctal_SOURCES = src/proctal.h src/main.c src/write.c src/read.c src/command.c src/process.c src/stream.c
proctal_CPPFLAGS = -Isrc -Wall -fmax-errors=10
EXTRA_DIST = src/args.yuck src/args.yucc
CLEANFILES = src/args.yucc

# The following rules specify additional dependencies for object files.
#
# Always keep in mind that, according to sections 9.4.1 and 27.8 of the
# documentation, automake does not support a convenient method for specifying
# dependencies for automatically generated object files of *_SOURCES c files
# and that you should be wary of renamed objects when *_CPPFLAGS is defined.
src/proctal-main.$(OBJEXT): src/args.yucc

# Generates argument parsing code.
src/args.yucc: Makefile $(srcdir)/src/args.yuck
	$(YUCK) gen --no-auto-flags --no-auto-actions $(srcdir)/src/args.yuck -o $@
