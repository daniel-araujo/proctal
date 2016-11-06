AC_PREREQ([2.69])
AC_INIT([proctal], [0.0.0])
AM_INIT_AUTOMAKE([foreign subdir-objects])
LT_PREREQ([2.4])
LT_INIT([dlopen])

AC_SUBST(PROCTAL_LIBRARY_VERSION, [0:0:0])

AC_CONFIG_SRCDIR([src/lib/proctal.h])
AC_CONFIG_HEADERS([config.h:config.h.in])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC
AC_HEADER_STDC
AC_TYPE_SIZE_T

PROCTAL_FIND_PROG([YUCK], [yuck])

PROCTAL_CHECK_HEADER([HAVE_SYS_PTRACE_H], [sys/ptrace.h], [required])

PROCTAL_CHECK_HEADER([HAVE_UNISTD_H], [unistd.h], [required])

PROCTAL_CHECK_FUNC([HAVE_USLEEP], [usleep], [required])

if test -n "$HAVE_USLEEP"; then
	proctal_xopen_flags="-D_XOPEN_SOURCE=500"
fi

AC_SUBST(proctal_xopen_flags)

AC_OUTPUT
