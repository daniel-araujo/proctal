dnl PROCTAL_FIND_PROG(VAR, PROG, [OPTIONS])
dnl
dnl Adds a --with-PROG option that allows the user to define the value of VAR
dnl and passes it to AC_ARG_VAR.
dnl
dnl If --with-PROG is not provided it will check if PROG exists in the PATH
dnl variable. If PROG is found, an absolute path to PROG will be assigned to
dnl VAR.
dnl
dnl If PROG is not found anywhere, VAR will be set to PROG literally.
dnl
dnl VAR will not be assigned a value if it had already been assigned a
dnl non-empty value.
AC_DEFUN([PROCTAL_FIND_PROG], [
	AC_ARG_VAR([$1], [$2 command])

	PROCTAL_ARG_WITH_PROG([$1], [$2], [Absolute path to $2. If not set, $2 will be searched in directories defined by the PATH environment variable.])

	PROCTAL_PATH_PROG([$1], [$2], [$3])

	PROCTAL_ASSIGN_VAR([$1], [$2])
])

dnl PROCTAL_PATH_PROG(VAR, PROG, [OPTIONS])
dnl
dnl Checks if PROG exists in the PATH variable. If PROG is found, an absolute
dnl path to PROG will be assigned to VAR.
dnl
dnl VAR will be passed to AC_SUBST.
dnl
dnl This macro will do nothing if VAR had already been assigned a value.
AC_DEFUN([PROCTAL_PATH_PROG], [
	if test -z "$$1"; then
		dnl Reusing AC_PATH_PROG check message and passing VAR to
		dnl AC_SUBST.
		AC_PATH_PROG([$1], [$2])

		if test -n "$3" && test "$3" = "required" && test -z "$$1"; then
			AC_MSG_ERROR(["$2 not found in PATH. Cannot continue without it"])
		fi

		if test -z "$$1"; then
			AC_MSG_WARN(["$2 not found in PATH. Some files may fail to compile without it"])
		fi
	fi
])

dnl PROCTAL_ARG_WITH_PROG(VAR, NAME, DESCRIPTION)
dnl
dnl Assigns the value given to the --with-NAME option to VAR if it had not
dnl already been assigned a value.
dnl
dnl VAR will be passed to AC_SUBST.
dnl
dnl This macro will do nothing if VAR had already been assigned a value.
AC_DEFUN([PROCTAL_ARG_WITH_PROG], [
	if test -z "$$1"; then
		AC_SUBST([$1])

		AC_ARG_WITH([$2], [AS_HELP_STRING([--with-$2=PATH], [$3])], [
			if test -n "$withval"; then
				PROCTAL_ASSIGN_VAR([$1], [$withval])
			fi
		])
	fi
])

dnl PROCTAL_CHECK_HEADER(VAR, HEADER, [OPTIONS])
dnl
dnl Checks if HEADER exists in the header file include path. If HEADER is
dnl found, VAR will be assigned 1 if it hasn't already been assigned a value,
dnl otherwise VAR is left untouched.
AC_DEFUN([PROCTAL_CHECK_HEADER], [
	dnl Reusing AC_CHECK_HEADER check message.
	AC_CHECK_HEADER([$2], [
		PROCTAL_ASSIGN_VAR([$1], [1])
	])

	if test -n "$3" && test "$3" = "required" && test -z "$$1"; then
		AC_MSG_ERROR(["Header file $2 not found in include path. Cannot continue without it"])
	fi

	if test -z "$$1"; then
		AC_MSG_WARN(["Header file $2 not found in include path. Some files may fail to compile without it"])
	fi
])

dnl PROCTAL_CHECK_FUNC(VAR, FUNC, [OPTIONS])
dnl
dnl Checks if FUNC exists in the list of linked files. If FUNC is found, VAR
dnl will be assigned 1 if it hasn't already been assigned a value, otherwise
dnl VAR is left untouched.
AC_DEFUN([PROCTAL_CHECK_FUNC], [
	dnl Reusing AC_CHECK_FUNC check message.
	AC_CHECK_FUNC([$2], [
		PROCTAL_ASSIGN_VAR([$1], [1])
	])

	if test -n "$3" && test "$3" = "required" && test -z "$$1"; then
		AC_MSG_ERROR(["Function $2 not found in linked files. Cannot continue without it"])
	fi

	if test -z "$$1"; then
		AC_MSG_WARN(["Function $2 not found in linked files. Some files may fail to compile without it"])
	fi
])

dnl PROCTAL_CHECK_LIB(VAR, LIB, FUNC, [DEPENDENCIES], [OPTIONS])
dnl
dnl Checks if FUNC exists when linking to LIB. If the check is successful, VAR
dnl will be assigned 1 if it hasn't already been assigned a value, otherwise
dnl VAR is left untouched. DEPENDENCIES are an additional set of libraries to
dnl link with for the test.
AC_DEFUN([PROCTAL_CHECK_LIB], [
	dnl Reusing AC_CHECK_LIB check message.
	AC_CHECK_LIB([$2], [$3], [
		PROCTAL_ASSIGN_VAR([$1], [1])
	],, [$4])

	if test -n "$5" && test "$5" = "required" && test -z "$$1"; then
		AC_MSG_ERROR(["Failed to link to library $2. Cannot continue without it"])
	fi

	if test -z "$$1"; then
		AC_MSG_WARN(["Failed to link to library $2. Some files may fail to compile without it"])
	fi
])

dnl PROCTAL_ASSIGN_VAR(VAR, VAL)
dnl
dnl Assigns VAL to VAR if VAR hasn't already been assigned a value previously.
dnl Passes VAR to AC_SUBST.
AC_DEFUN([PROCTAL_ASSIGN_VAR], [
	if test -z "$$1"; then
		$1=$2
	fi
	AC_SUBST([$1])
])

dnl PROCTAL_INSTALL_GIT_REPOSITORY(DST, SRC, COMMIT)
dnl
dnl Fetches git repository SRC and places it in git repository DST and checks
dnl out commit COMMIT.
AC_DEFUN([PROCTAL_INSTALL_GIT_REPOSITORY], [
	if [[ -e $1 ]]; then
		proctal_install_git_repository_args='-c advice.detachedHead=false --git-dir=$1/.git --work-tree=$1'

		if test -n $3; then
			proctal_install_git_repository_commit=$3
		else
			proctal_install_git_repository_commit=master
		fi

		if ! git $proctal_install_git_repository_args checkout -f $proctal_install_git_repository_commit > /dev/null 2>&1; then
			git $proctal_install_git_repository_args remote set-url origin $2
			git $proctal_install_git_repository_args fetch --all

			if test "$?" -ne 0; then
				AC_MSG_ERROR([Failed to pull from $2.])
			fi

			git $proctal_install_git_repository_args checkout -f $proctal_install_git_repository_commit > /dev/null

			if test "$?" -ne 0; then
				AC_MSG_ERROR([Commit $proctal_install_git_repository_commit does not exist in repository $2.])
			fi
		fi

		git $proctal_install_git_repository_args clean -fdx > /dev/null
	else
		git clone $2 $1

		if test "$?" -ne 0; then
			AC_MSG_ERROR([Failed to clone $2.])
		fi
	fi
])

dnl PROCTAL_RUN_AUTOCONF(DIR)
dnl
dnl Runs autoconf on a directory.
AC_DEFUN([PROCTAL_RUN_AUTOCONF], [
	pushd $1

	autoreconf -i

	popd
])

dnl PROCTAL_RUN_CONFIGURE(SRCDIR, BUILDDIR, ARGS)
dnl
dnl Runs configure on a directory.
AC_DEFUN([PROCTAL_RUN_CONFIGURE], [
	proctal_run_configure_srcdir=$1
	proctal_run_configure_builddir=$2
	proctal_run_configure_currentdir="$PWD"

	if test -z $proctal_run_configure_builddir; then
		proctal_run_configure_builddir="$proctal_run_configure_srcdir"
	fi

	mkdir -p "$proctal_run_configure_builddir"

	pushd "$proctal_run_configure_builddir"

	"$proctal_run_configure_currentdir/$proctal_run_configure_srcdir"/configure $3

	popd
])

dnl PROCTAL_INTEGER_ENDIANNESS
dnl
dnl If integers are stored in little endian,
dnl PROCTAL_INTEGER_ENDIANNESS_LITTLE is defined, otherwise
dnl PROCTAL_INTEGER_ENDIANNESS_BIG is defined.
AC_DEFUN([PROCTAL_INTEGER_ENDIANNESS], [
	AH_TEMPLATE([PROCTAL_INTEGER_ENDIANNESS_LITTLE], [Whether integers are stored in little endian.])
	AH_TEMPLATE([PROCTAL_INTEGER_ENDIANNESS_BIG], [Whether integers are stored in big endian.])

	AC_C_BIGENDIAN([AC_DEFINE([PROCTAL_INTEGER_ENDIANNESS_BIG])],
		[AC_DEFINE([PROCTAL_INTEGER_ENDIANNESS_LITTLE])],
		[
			AC_MSG_WARN(["Unable to determine integer endianness. Will assume little endian.])
			AC_DEFINE([PROCTAL_INTEGER_ENDIANNESS_LITTLE])
		])
])
