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

dnl PROCTAL_FIND_LIB(VAR, LIB, FUNC)
dnl
dnl Adds --with-LIB and --without-LIB options that allow the user to set
dnl whether they want to compile with the library or not.
dnl
dnl VAR becomes a variable and an Automake conditional. It will also be defined
dnl as a C preprocessor symbol if the library is found.
dnl
dnl if --with-LIB is passed configure will emit an error if the library is not
dnl found.
AC_DEFUN([PROCTAL_FIND_LIB], [
	AH_TEMPLATE([$1], [Defines if $2 should be used.])

	AC_ARG_WITH([$2], [AS_HELP_STRING([--with-$2], [Whether to compile with $2.])], [
		if test "$withval" == "yes"; then
			PROCTAL_CHECK_LIB([$1], [$2], [$3],, [required])
		fi
	], [PROCTAL_CHECK_LIB([$1], [$2], [$3])])

	AM_CONDITIONAL([$1], [test -n "$$1"])

	AM_COND_IF([$1], [AC_DEFINE([$1])])
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

dnl PROCTAL_RUN_CONFIGURE(SRCDIR, BUILDDIR, ARGS)
dnl
dnl Runs configure on a directory.
AC_DEFUN([PROCTAL_RUN_CONFIGURE], [
	proctal_run_configure_srcdir=$1
	proctal_run_configure_builddir=$2

	if test -z "${proctal_run_configure_builddir}"; then
		proctal_run_configure_builddir="${proctal_run_configure_srcdir}"
	fi

	PROCTAL_ABSOLUTE_PATH(proctal_run_configure_script, "${proctal_run_configure_srcdir}"/configure)

	echo "${proctal_run_configure_script}";

	if ! test -f "${proctal_run_configure_script}"; then
		AC_MSG_ERROR([Configure script not found in $1.])
	fi

	mkdir -p "${proctal_run_configure_builddir}"

	if test "$?" != "0"; then
		AC_MSG_ERROR([Failed to create build directory ${proctal_run_configure_builddir}.])
	fi

	pushd "${proctal_run_configure_builddir}" > /dev/null

	"${proctal_run_configure_script}" $3

	if test "$?" != "0"; then
		AC_MSG_ERROR([Configure script failed in $1.])
	fi

	popd > /dev/null
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

dnl PROCTAL_ARFLAGS_FIX
dnl
dnl Overrides the flags for the ar program because the default one causes a
dnl warning message. This is supposedly fixed in recent versions of automake
dnl and libtool but it will take some time before it's widely deployed.
AC_DEFUN([PROCTAL_ARFLAGS_FIX], [
	# This is the warning message that is disturbing the silence:
	# ar: `u' modifier ignored since `D' is the default (see `U')

	# So we're simply going to remove the `u' modifier from the flags list.

	AR_FLAGS=$(echo $AR_FLAGS | sed "s/u//")
	ARFLAGS=$AR_FLAGS

	# One is for libtool the other is for automake.
	AC_SUBST([AR_FLAGS])
	AC_SUBST([ARFLAGS])
])

dnl PROCTAL_CPU_ARCHITECTURE
dnl
dnl Defines PROCTAL_CPU_ARCHITECTURE.
AC_DEFUN([PROCTAL_CPU_ARCHITECTURE], [
	AH_TEMPLATE([PROCTAL_CPU_ARCHITECTURE_X86], [Defines if the CPU architecture is x86.])
	AH_TEMPLATE([PROCTAL_CPU_ARCHITECTURE_X86_64], [Defines if the CPU architecture is x86-64.])
	AH_TEMPLATE([PROCTAL_CPU_ARCHITECTURE_ARM], [Defines if the CPU architecture is arm.])
	AH_TEMPLATE([PROCTAL_CPU_ARCHITECTURE_AARCH64], [Defines if the CPU architecture is aarch64.])

	AC_CANONICAL_BUILD

	case $build_cpu in
	i[3456]86)
		AC_DEFINE([PROCTAL_CPU_ARCHITECTURE_X86])
		;;

	x86_64)
		AC_DEFINE([PROCTAL_CPU_ARCHITECTURE_X86_64])
		;;

	arm)
		AC_DEFINE([PROCTAL_CPU_ARCHITECTURE_ARM])
		;;

	aarch64)
		AC_DEFINE([PROCTAL_CPU_ARCHITECTURE_AARCH64])
		;;

	*)
		AC_MSG_ERROR([Unable to determine CPU architecture.])
	esac
])

dnl PROCTAL_ABSOLUTE_PATH(VAR, PATH)
dnl
dnl Assign VAR the value PATH if it is absolute or $PWD/PATH if it is relative.
AC_DEFUN([PROCTAL_ABSOLUTE_PATH], [
	case $2 in
	/*)
		$1=$2
		;;

	*)
		$1="$PWD/"$2
		;;
	esac
])
