AC_PREREQ([2.69])
AC_INIT([proctal], [0.0.0])
AM_INIT_AUTOMAKE([foreign subdir-objects])
LT_PREREQ([2.4])
LT_INIT([dlopen])

AC_SUBST(PROCTAL_LIBRARY_VERSION, [0:0:0])

AC_CONFIG_SRCDIR([src/lib/include/proctal.h])
AC_CONFIG_HEADERS([config.h:config.h.in])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC
AC_HEADER_STDC
AC_TYPE_SIZE_T

PROCTAL_FIND_PROG([YUCK], [yuck])

PROCTAL_CHECK_HEADER([HAVE_SYS_PTRACE_H], [sys/ptrace.h], [required])

PROCTAL_CHECK_FUNC([HAVE_PTRACE], [ptrace], [required])

PROCTAL_CHECK_HEADER([HAVE_UNISTD_H], [unistd.h], [required])

PROCTAL_CHECK_FUNC([HAVE_USLEEP], [usleep], [required])

PROCTAL_CHECK_HEADER([HAVE_CAPSTONE_H], [capstone/capstone.h], [required])
PROCTAL_CHECK_LIB([HAVE_LIBCAPSTONE], [capstone], [cs_version],, [required])

PROCTAL_CHECK_HEADER([HAVE_KEYSTONE_H], [keystone/keystone.h], [required])
PROCTAL_CHECK_LIB([HAVE_LIBKEYSTONE], [keystone], [ks_version],, [required])

if test -n "$HAVE_USLEEP"; then
	proctal_xopen_flags="-D_XOPEN_SOURCE=500"
fi

if test -n "$HAVE_LIBCAPSTONE"; then
	proctal_capstone_libs="-lcapstone"
fi

if test -n "$HAVE_LIBKEYSTONE"; then
	proctal_keystone_libs="-lkeystone"
fi

proctal_posix_flags="-D_POSIX_C_SOURCE=200112L"

AC_SUBST(proctal_xopen_flags)
AC_SUBST(proctal_posix_flags)
AC_SUBST(proctal_capstone_libs)
AC_SUBST(proctal_keystone_libs)

AC_OUTPUT
