AC_PREREQ([2.67])
AC_INIT( [fairport], [0.4.0], [snyder.bradleyj@gmail.com])
AM_INIT_AUTOMAKE(fairport, 0.4.0)
AC_OUTPUT(Makefile src/Makefile)

AC_CONFIG_HEADERS([config.h])
#AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([crypto], [MD5_Init])
AC_CHECK_LIB([ao], [ao_initialize])
AC_CHECK_LIB([m], [pow])
AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_LIB([pcre], [pcre_exec])

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.

# Checks for library functions.

AC_OUTPUT
