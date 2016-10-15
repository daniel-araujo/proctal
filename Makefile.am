bin_PROGRAMS = proctal
proctal_SOURCES = src/cmdline.c src/cmdline.h src/main.c src/write.c src/read.c
proctal_CPPFLAGS = -Isrc
EXTRA_DIST = src/args.ggo

CLEANFILES = src/cmdline.c src/cmdline.h

src/main.c: src/cmdline.h

src/cmdline.h src/cmdline.c: $(srcdir)/src/args.ggo
	$(GENGETOPT) --input=$^ --output-dir=$(builddir)/src
