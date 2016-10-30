AC_PREREQ([2.69])
AC_INIT([proctal], [0.0.0])
AM_INIT_AUTOMAKE([foreign subdir-objects])
LT_PREREQ([2.4])
LT_INIT([dlopen])

AC_SUBST(PROCTAL_LIBRARY_VERSION, [0:0:0])

AC_CONFIG_SRCDIR([src/lib/proctal.h])
AC_CONFIG_HEADERS([config.h:config.h.in])
AC_CONFIG_FILES([Makefile])

# Checks for programs.
AC_PROG_CC
PROCTAL_FIND_PROG([YUCK], [yuck], [required])

# Checks for libraries.

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADER([sys/ptrace.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.

AC_OUTPUT
