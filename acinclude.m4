dnl PROCTAL_FIND_PROG(VAR, PROG, [OPTIONS])
dnl 
dnl Checks if PROG exists in the PATH variable. If PROG is found, an absolute
dnl path to PROG will be assigned to VAR, otherwise VAR is left untouched.
AC_DEFUN([PROCTAL_FIND_PROG], [
	AC_PATH_PROG([$1], [$2])

	if test -n "$3" && test "$3" = "required" && test -z "$$1"; then
		AC_MSG_ERROR(["$2 not found in PATH. Cannot continue without it"])
	fi
])
