AC_PREREQ([2.69])
AC_INIT([proctal], [0.0.0], [bugs@proctal.io])
AC_CONFIG_AUX_DIR([.])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])
LT_PREREQ([2.4])
LT_INIT([dlopen])

PROCTAL_RUN_CONFIGURE([$srcdir/darr], [darr])
PROCTAL_RUN_CONFIGURE([$srcdir/acur], [acur])

AC_SUBST(PROCTAL_LIBRARY_VERSION, [0:0:0])

AC_CONFIG_SRCDIR([src/api/include/proctal.h])
AC_CONFIG_HEADERS([config.h:config.h.in])
AC_CONFIG_FILES([Makefile])

AC_PROG_CC
AC_PROG_SED

AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT8_T
AC_TYPE_INT16_T
AC_TYPE_UINT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_INT64_T
AC_TYPE_UINT64_T
AC_TYPE_LONG_DOUBLE
AC_TYPE_LONG_LONG_INT
AC_TYPE_UNSIGNED_LONG_LONG_INT
AC_TYPE_UINTPTR_T

PROCTAL_ARFLAGS_FIX

PROCTAL_INTEGER_ENDIANNESS
PROCTAL_CPU_ARCHITECTURE

PROCTAL_FIND_PROG([YUCK], [yuck])
PROCTAL_FIND_PROG([PHP], [php])

PROCTAL_FIND_LIB([PROCTAL_CAPSTONE], [capstone], [cs_version])
PROCTAL_FIND_LIB([PROCTAL_KEYSTONE], [keystone], [ks_version])

PROCTAL_CHECK_HEADER([HAVE_SYS_PTRACE_H], [sys/ptrace.h], [required])

PROCTAL_CHECK_FUNC([HAVE_PTRACE], [ptrace], [required])

PROCTAL_CHECK_HEADER([HAVE_UNISTD_H], [unistd.h], [required])

PROCTAL_CHECK_FUNC([HAVE_USLEEP], [usleep], [required])

if test -n "$HAVE_USLEEP"; then
	proctal_xopen_cflags="-D_XOPEN_SOURCE=500"
fi

if test -n "$PROCTAL_CAPSTONE"; then
	proctal_capstone_ldflags="-lcapstone"
fi

if test -n "$PROCTAL_KEYSTONE"; then
	proctal_keystone_ldflags="-lkeystone"
fi

proctal_posix_cflags="-D_POSIX_C_SOURCE=200112L"

proctal_darr_cflags=-I$srcdir/darr/src
proctal_darr_ldflags=darr/libdarr.a

proctal_acur_cflags=-I$srcdir/acur/src
proctal_acur_ldflags=acur/libacur.a

proctal_cflags="-iquote${srcdir}/src -iquotesrc -std=c11 -Wfatal-errors -Wall"
proctal_cflags="$proctal_cflags -Wextra -Wpointer-arith $proctal_xopen_cflags"
proctal_cflags="$proctal_cflags -Wno-unused-parameter -Wno-unused-function"
proctal_cflags="$proctal_cflags $proctal_posix_cflags -Wno-maybe-uninitialized"
proctal_cflags="$proctal_cflags $proctal_darr_cflags -Wno-unused-label"
proctal_cflags="$proctal_cflags $proctal_acur_cflags -include config.h"

AC_SUBST([proctal_capstone_ldflags])
AC_SUBST([proctal_keystone_ldflags])
AC_SUBST([proctal_darr_ldflags])
AC_SUBST([proctal_cflags])

AC_OUTPUT
