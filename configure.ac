#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([FULL-PACKAGE-NAME], [VERSION], [BUG-REPORT-ADDRESS])
AM_INIT_AUTOMAKE(pippo, 2.6)
AC_CONFIG_SRCDIR([src])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC

# Checks for libraries.
function foundLibFailed {
        AC_MSG_NOTICE([])
        AC_MSG_NOTICE([])
        AC_MSG_ERROR([!ERROR! Cannot find library '$1'. Please attempt to solve this problem !ERROR!])
}


# Checks for libraries.
AC_CHECK_LIB([pcap], [pcap_create], [], [foundLibFailed 'pcap'])
AC_CHECK_LIB([pthread], [pthread_create], [], [foundLibFailed 'pthread'])

# Check for boost
m4_include([m4/ax_boost_base.m4])
m4_include([m4/ax_boost_program_options.m4])

AX_BOOST_BASE(1.42)
if test "$succeeded" != "yes" ; then
  echo "Error: You need to install the boost library version 1.42 or newer!"
  exit
fi

AX_BOOST_PROGRAM_OPTIONS
if test "x$ax_cv_boost_program_options" = "xno"; then
  echo
  echo "Error: You need to install the boost program options library!"
  echo
  exit
fi

dnl Checks for (installed) libdnet
AC_ARG_WITH(libdnet,
[  --with-libdnet=DIR      use libdnet in DIR],
[ case "$withval" in
  yes|no)
     AC_ERROR([Please specify directory containing dnet-config when using --with-libdnet])
     ;;
  *)
     AC_MSG_CHECKING(for libdnet)
     AC_MSG_RESULT($withval)
     if test -f $withval/src/libdnet.a; then
	DNETINC="-I$withval/include"
	DNETLIB="-L$withval/src -ldnet `$withval/dnet-config --libs`"
     elif test -x $withval/bin/dnet-config; then
	DNETINC="`$withval/bin/dnet-config --cflags`"
	DNETLIB="`$withval/bin/dnet-config --libs`"
     else
        AC_MSG_RESULT(no)
        AC_ERROR(dnet-config not found in $withval/bin)
     fi
     ;;
  esac
  AC_MSG_RESULT(yes) ],
[ dnl This is the default case so let's just use AC_PATH_PROG! --CPK.
  AC_PATH_PROG(dnetconfig, dnet-config, "no")
  if test "$dnetconfig" = "no"; then
     AC_ERROR(dnet-config not found)
  else
     DNETINC="`$dnetconfig --cflags`"
     DNETLIB="`$dnetconfig --libs`"
  fi]
)

dnl We still need to check whether it's dnet or dumbnet as
dnl for example on Debian. We test by looking at the content
dnl of DNETLIB and derive from the library name what version
dnl we're dealing with. If we find a libdumbnet, we prefix
dnl compat/libdnet to our inclusion path. It provides a dnet.h
dnl that transparently includes dumbnet.h for those systems. --CPK.
AC_MSG_CHECKING([whether libdnet is a libdumbnet])
if test `echo $DNETLIB | sed -e '/dumb/=;d'`; then
     AC_MSG_RESULT(yes)
     AC_DEFINE(HAVE_DUMBNET, 1,
		[Define if our libdnet is a libdumbnet])
     DNETCOMPAT="compat/libdnet"
else
     AC_MSG_RESULT(no)
fi

AC_SUBST(DNETCOMPAT)
AC_SUBST(DNETINC)
AC_SUBST(DNETLIB)

# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_OUTPUT(Makefile src/Makefile)
