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


# Checks for header files.

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_OUTPUT(Makefile src/Makefile)
