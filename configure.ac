AC_PREREQ([2.69])
AC_INIT([proctal], [1.0.0])
AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_SRCDIR([src/proctal.h])
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

# Checks for library functions.

AC_OUTPUT
