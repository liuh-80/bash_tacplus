dnl
dnl File:        configure.in
dnl Revision:    $Id: configure.ac,v 1.0 2021/08/24 12:04:29 liuh@microsoft.com Exp $
dnl Created:     2010/06/09
dnl Author:      Liu Hua <liuh@microsoft.com>
dnl
dnl Process this file with autoconf to produce a configure script
dnl You need autoconf 2.59 or better!
dnl
dnl ---------------------------------------------------------------------------

AC_PREREQ(2.59)
AC_COPYRIGHT([
See the included file: COPYING for copyright information.
])
AC_INIT(bash_tacplus, 1.0.0, [liuh@microsoft.com])

AC_CONFIG_AUX_DIR(config)
AM_INIT_AUTOMAKE([foreign])
AC_CONFIG_SRCDIR([bash_tacplus.c])
AC_CONFIG_HEADER([config.h])
AC_CONFIG_MACRO_DIR([config])

dnl --------------------------------------------------------------------
dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
LT_INIT([disable-static])
AM_PROG_CC_C_O

dnl --------------------------------------------------------------------
dnl Checks for libraries.
AC_CHECK_LIB(tac, tac_connect)
AC_CHECK_LIB(tacsupport, parse_config_file)

case "$host" in
	sparc-* | sparc64-*)
		LIBS="$LIBS -lresolv";;
esac

dnl --------------------------------------------------------------------
dnl Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h ])
AC_CHECK_HEADER(tacplus.h libtac.h cdefs.h, [], [AC_MSG_ERROR([TAC libraries missing. ])] )
AC_CHECK_HEADER(support.h, [], [AC_MSG_ERROR([TAC support libraries missing. ])] )

dnl --------------------------------------------------------------------
dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME

AC_ARG_ENABLE(am-ldcflags, AS_HELP_STRING([--disable-am-ldcflags], [do not add various 'AM_CFLAGS/AM_LDFLAGS']))
if test "x$enable_am_ldcflags" != "xno"; then
   for flag in -fstack-protector-all -Wl,-z,relro -Wl,-z,now -fPIE -pie -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2; do
	my_save_cflags="$CFLAGS"
	CFLAGS=$flag
	AC_MSG_CHECKING([whether CC supports $flag])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
	    [AC_MSG_RESULT([yes])]
	    [AM_CFLAGS="$AM_CFLAGS $flag"]
	    [AM_LDFLAGS="$AM_LDFLAGS $flag"],
	    [AC_MSG_RESULT([no])]
	)
	CFLAGS="$my_save_cflags"
    done
    AC_SUBST([AM_CFLAGS])
    AC_SUBST([AM_LDFLAGS])
fi

dnl --------------------------------------------------------------------
dnl Checks for library functions.
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_CHECK_FUNCS([bzero gethostbyname gettimeofday inet_ntoa select socket logwtmp getrandom])

dnl --------------------------------------------------------------------
dnl Switch for pam module dir
AC_ARG_ENABLE([pamdir], [AS_HELP_STRING([--enable-pamdir],
              [Location to install the pam module ($libdir/security)])],
              [pamdir=$enableval], [pamdir=$libdir/security])
AC_SUBST(pamdir)

AC_ARG_ENABLE(doc, AS_HELP_STRING([--disable-doc], [do not build docs]))
AM_CONDITIONAL(DOC, test "x$enable_doc" != "xno")

dnl --------------------------------------------------------------------
dnl Generate made files
AC_CONFIG_FILES([Makefile
                 bash_tacplus.spec])
AC_OUTPUT
