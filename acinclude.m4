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
	AH_TEMPLATE([$1], [Define to 1 if $2 is used.])

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
	AH_TEMPLATE([PROCTAL_INTEGER_ENDIANNESS_LITTLE], [Define to 1 if integers are stored in little endian.])
	AH_TEMPLATE([PROCTAL_INTEGER_ENDIANNESS_BIG], [Define to 1 if integers are stored in big endian.])

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
dnl Defines the following macros and Automake conditionals:
dnl - PROCTAL_CPU_ARCHITECTURE_X86
dnl - PROCTAL_CPU_ARCHITECTURE_X86_64
dnl - PROCTAL_CPU_ARCHITECTURE_ARM
dnl - PROCTAL_CPU_ARCHITECTURE_AARCH64
dnl - PROCTAL_CPU_ARCHITECTURE_UNKNOWN
AC_DEFUN([PROCTAL_CPU_ARCHITECTURE], [
	AC_CANONICAL_HOST

	proctal_cpu_architecture_autoconf_arch="$host_cpu"

	case $proctal_cpu_architecture_autoconf_arch in
	i[3456]86)
		proctal_cpu_architecture_arch=x86
		;;

	x86_64)
		proctal_cpu_architecture_arch=x86_64
		;;

	arm*)
		proctal_cpu_architecture_arch=arm
		;;

	aarch64)
		proctal_cpu_architecture_arch=aarch64
		;;

	*)
		proctal_cpu_architecture_arch=unknown
		AC_MSG_WARN([CPU architecture $proctal_cpu_architecture_autoconf_arch not supported or not recognized.])
		;;
	esac

	AH_TEMPLATE([PROCTAL_CPU_ARCHITECTURE_X86], [Define to 1 if the CPU architecture is x86.])
	AM_CONDITIONAL([PROCTAL_CPU_ARCHITECTURE_X86], [test "$proctal_cpu_architecture_arch" = "x86"])
	AM_COND_IF([PROCTAL_CPU_ARCHITECTURE_X86], [AC_DEFINE([PROCTAL_CPU_ARCHITECTURE_X86])])

	AH_TEMPLATE([PROCTAL_CPU_ARCHITECTURE_X86_64], [Define to 1 if the CPU architecture is x86-64.])
	AM_CONDITIONAL([PROCTAL_CPU_ARCHITECTURE_X86_64], [test "$proctal_cpu_architecture_arch" = "x86_64"])
	AM_COND_IF([PROCTAL_CPU_ARCHITECTURE_X86_64], [AC_DEFINE([PROCTAL_CPU_ARCHITECTURE_X86_64])])

	AH_TEMPLATE([PROCTAL_CPU_ARCHITECTURE_ARM], [Define to 1 if the CPU architecture is arm.])
	AM_CONDITIONAL([PROCTAL_CPU_ARCHITECTURE_ARM], [test "$proctal_cpu_architecture_arch" = "arm"])
	AM_COND_IF([PROCTAL_CPU_ARCHITECTURE_ARM], [AC_DEFINE([PROCTAL_CPU_ARCHITECTURE_ARM])])

	AH_TEMPLATE([PROCTAL_CPU_ARCHITECTURE_AARCH64], [Define to 1 if the CPU architecture is aarch64.])
	AM_CONDITIONAL([PROCTAL_CPU_ARCHITECTURE_AARCH64], [test "$proctal_cpu_architecture_arch" = "aarch64"])
	AM_COND_IF([PROCTAL_CPU_ARCHITECTURE_AARCH64], [AC_DEFINE([PROCTAL_CPU_ARCHITECTURE_AARCH64])])

	AH_TEMPLATE([PROCTAL_CPU_ARCHITECTURE_UNKNOWN], [Define to 1 if the CPU architecture is unknown.])
	AM_CONDITIONAL([PROCTAL_CPU_ARCHITECTURE_UNKNOWN], [test "$proctal_cpu_architecture_arch" = "unknown"])
	AM_COND_IF([PROCTAL_CPU_ARCHITECTURE_UNKNOWN], [AC_DEFINE([PROCTAL_CPU_ARCHITECTURE_UNKNOWN])])
])

dnl PROCTAL_PLATFORM
dnl
dnl Defines the following macros and Automake conditionals:
dnl - PROCTAL_PLATFORM_LINUX
dnl - PROCTAL_PLATFORM_WINDOWS
dnl - PROCTAL_PLATFORM_UNKNOWN
AC_DEFUN([PROCTAL_PLATFORM], [
	AC_CANONICAL_HOST

	proctal_platform_autoconf_os="$host_os"

	case $proctal_platform_autoconf_os in
	linux*)
		proctal_platform=linux
		;;

	mingw*)
		proctal_platform=windows
		;;

	*)
		proctal_platform=unknown
		AC_MSG_WARN([OS $proctal_platform_autoconf_os not supported or not recognized.])
		;;
	esac

	AH_TEMPLATE([PROCTAL_PLATFORM_LINUX], [Define to 1 if the platform is Linux.])
	AM_CONDITIONAL([PROCTAL_PLATFORM_LINUX], [test "$proctal_platform" = "linux"])
	AM_COND_IF([PROCTAL_PLATFORM_LINUX], [AC_DEFINE([PROCTAL_PLATFORM_LINUX])])

	AH_TEMPLATE([PROCTAL_PLATFORM_WINDOWS], [Define to 1 if the platform is Windows.])
	AM_CONDITIONAL([PROCTAL_PLATFORM_WINDOWS], [test "$proctal_platform" = "windows"])
	AM_COND_IF([PROCTAL_PLATFORM_WINDOWS], [AC_DEFINE([PROCTAL_PLATFORM_WINDOWS])])

	AH_TEMPLATE([PROCTAL_PLATFORM_UNKNOWN], [Define to 1 if the platform is unknown.])
	AM_CONDITIONAL([PROCTAL_PLATFORM_UNKNOWN], [test "$proctal_platform" = "unknown"])
	AM_COND_IF([PROCTAL_PLATFORM_UNKNOWN], [AC_DEFINE([PROCTAL_PLATFORM_UNKNOWN])])
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

dnl PROCTAL_RELEASE_VERSION
dnl
dnl Takes the value of PACKAGE_VERSION and creates PROCTAL_VERSION.
AC_DEFUN([PROCTAL_RELEASE_VERSION], [
	AH_TEMPLATE([PROCTAL_VERSION], [Version number.])

	proctal_version_number=`echo $PACKAGE_VERSION | $SED -E 's/^([[0-9]]+)*/\1/'`

	AC_DEFINE_UNQUOTED([PROCTAL_VERSION], [$proctal_version_number])

	AC_SUBST([PROCTAL_VERSION], [$proctal_version_number])
])

dnl PROCTAL_SO_VERSION(CURRENT, REVISION, AGE)
dnl
dnl This macro creates the PROCTAL_LIBTOOL_VERSION substitution variable. That
dnl macro defines the version numbers of the .so library file.
dnl
dnl Rules on how to set those numbers:
dnl - CURRENT must always be incremented by 1 on every release that includes
dnl changes to the interface.
dnl - REVISION must be set to 0 if CURRENT is changed, otherwise it must be
dnl incremented by 1 on every release.
dnl - AGE must only be changed when CURRENT is changed and has to be
dnl incremented by 1 if the interface changes are backwards compatible,
dnl otherwise it must be set to 0.
dnl
AC_DEFUN([PROCTAL_SO_VERSION], [
	AC_SUBST([PROCTAL_LIBTOOL_VERSION], [$1:$2:$3])
])

dnl PROCTAL_COMPILATION_FLAGS
dnl
dnl Sets compilation flags based on existing variables.
AC_DEFUN([PROCTAL_COMPILATION_FLAGS], [
	AC_SUBST([PROCTAL_CFLAGS])
	AC_SUBST([PROCTAL_LDFLAGS])

	if test -n "$PROCTAL_CAPSTONE"; then
		AS_VAR_APPEND([PROCTAL_LDFLAGS], [" -lcapstone"])
	fi

	if test -n "$PROCTAL_KEYSTONE"; then
		AS_VAR_APPEND([PROCTAL_LDFLAGS], [" -lkeystone"])
	fi

	# Darr library.
	AS_VAR_APPEND([PROCTAL_CFLAGS], [" -I${srcdir}/darr/src"])
	AS_VAR_APPEND([PROCTAL_LDFLAGS], [" darr/libdarr.a"])

	# Acur library.
	AS_VAR_APPEND([PROCTAL_CFLAGS], [" -I${srcdir}/acur/src"])
	AS_VAR_APPEND([PROCTAL_LDFLAGS], [" acur/libacur.a"])

	# Set C11 language standard.
	AS_VAR_APPEND([PROCTAL_CFLAGS], [" -std=c11"])

	# Make ssize_t available in C11 mode.
	AS_VAR_APPEND([PROCTAL_CFLAGS], [" -D_XOPEN_SOURCE=500"])

	# Make usleep available.
	AS_VAR_APPEND([PROCTAL_CFLAGS], [" -D_POSIX_C_SOURCE=200112L"])

	# The include directive with the quotes syntax will additionally be
	# relative to the src directory.
	AS_VAR_APPEND([PROCTAL_CFLAGS], [" -iquote${srcdir}/src -iquotesrc"])

	# Make the compiler less forgiving.
	AS_VAR_APPEND([PROCTAL_CFLAGS], [" -Wfatal-errors -Wall"])
	AS_VAR_APPEND([PROCTAL_CFLAGS], [" -Wextra -Wpointer-arith"])
	AS_VAR_APPEND([PROCTAL_CFLAGS], [" -Werror=incompatible-pointer-types"])

	# Ignore less desirable warning messages.
	AS_VAR_APPEND([PROCTAL_CFLAGS], [" -Wno-unused-parameter -Wno-unused-function"])
	AS_VAR_APPEND([PROCTAL_CFLAGS], [" -Wno-unused-label"])

	# Include config.h automatically.
	AS_VAR_APPEND([PROCTAL_CFLAGS], [" -include config.h"])

	# Windows specific options.
	AM_COND_IF([PROCTAL_PLATFORM_WINDOWS], [
		AS_VAR_APPEND([PROCTAL_LDFLAGS], [" -static"])
	])
])

dnl PROCTAL_META
dnl
dnl Allows code to reference contents inside the project.
AC_DEFUN([PROCTAL_META], [
	AH_TEMPLATE([PROCTAL_META_DIR_SRC], [Define to source directory.])

	AC_DEFINE_UNQUOTED([PROCTAL_META_DIR_SRC], ["$srcdir/src"])
])
