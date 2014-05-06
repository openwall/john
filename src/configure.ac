#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([john], [1.8.0.bleeding], [noone@dev.null])
##  AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_HEADERS([autoconfig.h])

# include our extra macro code
m4_include([m4/pkg.m4])
m4_include([m4/ax_openmp.m4])
m4_include([m4/ax_opencl.m4])
m4_include([m4/ax_prog_cc_mpi.m4])


dnl Most of these things are boiler plate (from autoscan);
dnl but here's some of my stuff
dnl BEGIN JIM's BLOCK OF STUFF
dnl
dnl  If you want to pass these into your Makefile.in templates, use
dnl    AC_SUBST(ac_variable_name)
dnl  then they'll be available as substitution variables (eg., @ac_variable_name@)
dnl
dnl  If you want to go farther and create cpp macro definitions in autoconfig.h
dnl    AC_DEFINE(ac_variable_name)
dnl  macros:
dnl    AC_CHECK_LIB (library, function, [action-if-found], [action-if-not-found], [other-libraries])
dnl    AC_SEARCH_LIBS (function, search-libs, [action-if-found], [action-if-not-found], [other-libraries])
dnl    AC_SUBST(ac_variable_name)
dnl    AC_DEFINE(ac_variable_name)

LDFLAGS="-L/usr/local/lib -L/usr/local/ssl/lib "

dnl END JIM's BLOCK OF STUFF

# setup options
AC_ARG_WITH(omp, [AS_HELP_STRING([--with-omp],[compile with OpenMP (multi-thread) support. If none is found, OMP is not used. Default: auto])],,with_omp=auto)
AC_ARG_WITH(mpi, [AS_HELP_STRING([--with-mpi],[compile with MPI (parallelization) support. If none is found, MPI is not used. Default: auto])],,[with_mpi=auto])

# Checks for programs.
AC_PROG_CC([gcc cc icc ])
AC_PROG_LN_S
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_CPP
AC_CACHE_SAVE

# Checks for libraries.
################################################
#  NOTE, be VERY careful of spaces around the comma's in the AC_CHECK_LIB. Best to not have any.
#  If there are space, then often that will get a lib to NOT be added to @LIBS@ and cause linkage problems.
################################################
AC_CHECK_LIB([ssl],[SSL_library_init],[],[AC_MSG_FAILURE(JtR can NOT be build without libssl being installed,1)])
AC_CHECK_LIB([crypto],[MD5_Update],[],[AC_MSG_FAILURE(JtR can NOT be build without libssl/libcrypto being installed,1)])
AC_CHECK_LIB([m],[sqrt],[],[AC_MSG_FAILURE(JtR can NOT be build without libm being installed,1)])
AC_CHECK_LIB([z],[deflate],[],[AC_MSG_FAILURE(JtR can NOT be build without libz being installed,1)])
AC_SEARCH_LIBS([crypt],[crypt],[AC_DEFINE(HAVE_LIBCRYPT,1,[Define to 1 if you have the `crypt' library (-lcrypt).])])
AC_CHECK_LIB([k5crypto],[krb5_c_string_to_key_with_params],[],[AC_MSG_WARN(Installing MIT krb5/k5crypto/ library enables several extra formats,1)] )
AC_CHECK_LIB([krb5],[krb5_c_string_to_key_with_params])
AC_CHECK_LIB([gmp],[__gmpz_init],[],[AC_MSG_WARN(Installing libgmp will speed up some hash formats" && echo "   ****" )])
AC_CHECK_LIB([kernel32],[main])
AC_CHECK_LIB([dl],[dlopen])
AC_SEARCH_LIBS([c_regex_iterator_cb],[rexgen librexgen],
               [AC_DEFINE(HAVE_LIBREXGEN,1,[Define to 1 if you have the `rexgen' library (-lrexgen).])],
			   [AC_MSG_WARN(Installing librexgen installs a powerful new wordlist most)])
AC_CHECK_LIB([nsl],[main])
AC_CHECK_LIB([pthread],[main])
AC_CHECK_LIB([rt],[main])
AC_CHECK_LIB([socket],[main])
# mingw stuff from older makefile rules.
AC_CHECK_LIB([wsock32],[main])
AC_CHECK_LIB([lws2_32],[main])
AC_CHECK_LIB([wst],[main])
# in makefile, we need to know if building extra pcap items.
AC_CHECK_LIB([pcap],[main],[AC_SUBST(HAVE_PCAP,1)])

AC_CACHE_SAVE

# check packages:

##################################
# check for NSS
##################################
PKG_CHECK_MODULES([NSS], [nss], AC_SUBST(HAVE_NSS,[-DHAVE_NSS]),
        AC_MSG_WARN(NSS not found - Mozilla format will be omitted.))

##################################
# check for openMP
##################################
AS_IF([test x"$with_omp" = "xauto"],[AX_OPENMP(AC_SUBST(OPENMP_CFLAGS,${ax_cv_c_openmp}))])
AS_IF([test x"$with_omp" = "xyes"],
    [AX_OPENMP([AC_SUBST(OPENMP_CFLAGS,${ax_cv_c_openmp})],
              [AC_MSG_FAILURE([OMP requested, but could not use OMP.])])])

##################################
# check for MPI
##################################
AX_PROG_CC_MPI([test x"$with_mpi" != xno],[use_mpi=yes] [AC_SUBST(HAVE_MPI,[-DHAVE_MPI])],[
  use_mpi=no
  if test x"$with_mpi" = xyes; then
    AC_MSG_FAILURE([MPI compiler requested, but could not use MPI.])
  else
    AC_MSG_WARN([No MPI compiler found, won't use MPI.])
  fi
])

####################################
# still left to do
####################################
# FIXME: Replace `main' with a function in `-lcudart':
AC_CHECK_LIB([cudart],[main])
# FIXME: Replace `main' with a function in `-lOpenCL':
AC_CHECK_LIB([OpenCL],[main])

# Checks for header files.
AC_CHECK_HEADERS([OS.h arpa/inet.h sys/times.h fcntl.h limits.h locale.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h strings.h sys/file.h sys/param.h sys/socket.h sys/time.h sys/timeb.h termios.h unistd.h wchar.h unixlib/local.h netinet/if_ether.h pcap.h])
AC_CACHE_SAVE

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_OFF_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T
AC_CHECK_TYPES([ptrdiff_t])

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_CHECK_FUNCS([atexit endpwent floor ftruncate gethostbyname gettimeofday inet_ntoa isascii memchr memmove memset mkdir munmap pow rmdir select setenv setlocale socket strcasecmp strchr strcspn strdup strerror strncasecmp strrchr strspn strstr strtol strtoul])
AC_CACHE_SAVE

AC_CONFIG_FILES([Makefile
                 aes/Makefile
                 aes/aesni/Makefile
                 aes/openssl/Makefile
                 escrypt/Makefile])
AC_OUTPUT(,echo "timestamp from configure.ac" > autoconfig-stamp-h & echo "I want to echo something")
