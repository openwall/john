#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# Travis CI only has 2.68
AC_PREREQ([2.68])
AC_INIT([john], [1.8.0.bleeding], [noone@dev.null])
##  AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_SRCDIR([john.c])
AC_CONFIG_HEADERS([autoconfig.h])

# include our extra macro code
m4_include([m4/pkg.m4])
m4_include([m4/ax_openmp.m4])
m4_include([m4/ax_opencl.m4])
m4_include([m4/ax_pthread.m4])
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
dnl    AC_RUN_IFELSE(input, [action-if-true], [action-if-false], [action-if-cross-compiling])
dnl    AC_MSG_WARN(message)
dnl    AC_MSG_FAILURE(message)
dnl    AC_MSG_ERROR(message)
dnl    AC_MSG_CHECKING(message)
dnl    AC_MSG_RESULT(message)   (if we use msg_checking, we should use result to tell what happened).
dnl    AC_CHECK_SIZEOF (type-or-expr, [unused], [includes = ‘AC_INCLUDES_DEFAULT’])
dnl    AC_ARG_ENABLE([opencl], [AC_HELP_STRING([--disable-opencl], [do not use OpenCL])], [disable_opencl=$enableval], [disable_opencl='yes'])
dnl    AC_ARG_WITH(omp, [AS_HELP_STRING([--with-omp],[compile with OpenMP (multi-thread) support. If none is found, OMP is not used. Default: auto])],,with_omp=auto)
dnl    gcc -dM -E - < /dev/null
dnl
dnl  guide to easy to do autoconf:  http://www.galassi.org/mark/mydocs/autoconf_tutorial_2.html#SEC2
dnl
dnl  TODO:
dnl    AC_C_BIGENDIAN ([action-if-true], [action-if-false], [action-if-unknown], [action-if-universal])
dnl    AC_C_INLINE
dnl        If the C compiler supports the keyword inline, do nothing. Otherwise define inline
dnl        to __inline__ or __inline if it accepts one of those, otherwise define inline to be empty.
dnl
dnl     AC_REQUIRE([AC_CANONICAL_HOST])[]dnl
dnl       case $host_os in
dnl         *cygwin* ) CYGWIN=yes;;
dnl                * ) CYGWIN=no;;
dnl       esac
dnl
dnl     use $EXEEXT and $OBJEXT  for exe and obj extension.  Set by AC_PROC_CC
dnl

LDFLAGS="-L/usr/local/lib -L/usr/local/ssl/lib "

dnl END JIM's BLOCK OF STUFF

# setup options
AC_ARG_WITH(mpi, [AS_HELP_STRING([--with-mpi],[compile with MPI (parallelization) support. If none is found, MPI is not used. Default: auto])],,[with_mpi=auto])
AC_ARG_WITH(icc-asm, [AS_HELP_STRING([--with-icc-asm],[Use ICC pre-built asm files for intrisic SIMD code Default: no])],,[with_icc_asm=no])

# Checks for programs.
AC_PROG_CC([gcc cc icc ])
AC_PROG_LN_S
AC_PROG_GREP
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_CPP
AC_CACHE_SAVE

#############################################################################
# CPU test code.  We start with SSE2, then SSSE3, then SSE4, ... until we fail
# whatever the last one is, we use it.  NOTE, if AVX fails we still DO test XOP
# since one is intel, one is AMD.  At the very end of configure, we set gcc
# back to whatever the 'best' was.  During running in configure, $CC gets reset
# so the results of our tests must be remembered, and reset just before exit.
#############################################################################
#test SSE2
AC_MSG_CHECKING([for SSE2])
CC_BACKUP=$CC
CPU_STR="Unk"
CPU_NOTFOUND=0
CC="$CC_BACKUP -msse2"
AC_RUN_IFELSE(
  [
  AC_LANG_SOURCE(
	[[#include <emmintrin.h>
      #include <stdio.h>
      int main(){__m128i t;*((long long*)&t)=1;t=_mm_slli_si128(t,7);if((*(unsigned*)&t)==88)printf(".");exit(0);}]]
  )]
  ,[CPU_BEST_FLAGS="-msse2"]dnl
   [CPU_STR="SSE2"]
   [AC_DEFINE([HAVE_SSE2], 1, [enable if compiling for SSE2 archetecture])] dnl
   [AC_MSG_RESULT([yes])]
  ,[CPU_NOTFOUND="1"]
   [AC_MSG_RESULT(no)]
  )
AS_IF([test x"$CPU_NOTFOUND" = "x0"],
[
CC="$CC_BACKUP -mssse3"
CPU_NOTFOUND=0
AC_MSG_CHECKING([for SSSE3])
AC_RUN_IFELSE(
  [
  AC_LANG_SOURCE(
	[[#include <tmmintrin.h>
      #include <stdio.h>
      int main(){__m128i t;*((long long*)&t)=1;t=_mm_shuffle_epi8(t,t);if((*(unsigned*)&t)==88)printf(".");exit(0);}]]
  )]
  ,[CPU_BEST_FLAGS="-mssse3"]dnl
   [CPU_STR="SSSE3"]
   [AC_DEFINE([HAVE_SSSE3], 1, [enable if compiling for SSSE3 archetecture])] dnl
   [AC_MSG_RESULT([yes])]
  ,[CPU_NOTFOUND=1]
   [AC_MSG_RESULT([no])]
  )
]
)
AS_IF([test x"$CPU_NOTFOUND" = "x0"],
[
CC="$CC_BACKUP -msse4.1"
CPU_NOTFOUND=0
AC_MSG_CHECKING([for SSE4.1])
AC_RUN_IFELSE(
  [
  AC_LANG_SOURCE(
	[[#include <smmintrin.h>
      #include <stdio.h>
      int main(){__m128d t;*((long long*)&t)=1;t=_mm_round_pd(t,1);if((*(long long*)&t)==88)printf(".");exit(0);}]]
  )]
  ,[CPU_BEST_FLAGS="-msse4.1"]dnl
   [CPU_STR="SSE4.1"]
   [AC_DEFINE([HAVE_SSE4_1], 1, [enable if compiling for SSE4.1 archetecture])] dnl
   [AC_MSG_RESULT([yes])]
  ,[CPU_NOTFOUND=1]
   [AC_MSG_RESULT([no])]
  )
]
)

AS_IF([test x"$CPU_NOTFOUND" = "x0"],
[
CC="$CC_BACKUP -mavx"
AC_MSG_CHECKING([for AVX])
AC_RUN_IFELSE(
  [
  AC_LANG_SOURCE(
	[[#include <immintrin.h>
      #include <stdio.h>
      int main(){__m256d t;*((long long*)&t)=1;t=_mm256_movedup_pd(t);if((*(long long*)&t)==88)printf(".");exit(0);}]]
  )]
  ,[CPU_BEST_FLAGS="-mavx"]dnl
   [CPU_STR="AVX"]
   [CPU_BEST_FLAGS_MAIN="-DJOHN_AVX"]
   [AC_DEFINE([HAVE_AVX], 1, [enable if compiling for AVX archetecture])] dnl
   [AC_MSG_RESULT([yes])]
  ,[AC_MSG_RESULT([no])]
  )
]
)
AS_IF([test x"$CPU_NOTFOUND" = "x0"],
[
CC="$CC_BACKUP -mxop"
AC_MSG_CHECKING([for XOP])
AC_RUN_IFELSE(
  [
  AC_LANG_SOURCE(
	[[#include <intrin.h>
      #include <stdio.h>
      int main(){__m128i t;*((long long*)&t)=1;t=_mm_roti_epi32(t,5);if((*(long long*)&t)==88)printf(".");exit(0);}]]
  )]
  ,[CPU_BEST_FLAGS="-mxop"]dnl
   [CPU_STR="XOP"]
   [CPU_BEST_FLAGS_MAIN="-DJOHN_XOP"]
   [AC_DEFINE([HAVE_XOP], 1, [enable if compiling for XOP archetecture])] dnl
   [AC_MSG_RESULT([yes])]
  ,[AC_MSG_RESULT([no])]
  )
]
)
CC="$CC_BACKUP"
#############################################################################
# End of JtR CPU test code.  The 'best' found should be in $CPU_BEST
#############################################################################

#############################################################################
# 32 vs 64 bit CPU test code.  Sets these items:
#  -msse2 (or whatever)
#  AESNI=64 (CPU_BIT_STR)  Build type also uses this
#  set ARCH_LINK file
#  sets the extra ASM object.
#  Will later set @USE_ICC_ASM@
#############################################################################
#test 32 vs 64 bit.  Also handle icc asm intrinsics [Also handle X32]
AC_MSG_CHECKING([for 32/64 bit])
CC="$CC_BACKUP -march=native"
# with_icc_asm
AS_IF([test x"$with_icc_asm" != "xno"],
[AC_RUN_IFELSE(
  [
  AC_LANG_SOURCE(
	[[int main() {
	#if defined(__x86_64)||defined(__x86_64__)||defined(__amd64)||defined(__amd64__)||defined(_LP64)||defined(_M_IX86)||\
	    defined(_M_AMD64)||defined(_M_IA64)||defined(_M_X64)||defined(__ILP32__)||defined(__LLP64__)||defined(WIN64)
	exit(0);
	#endif
	exit(1);}]]
  )]
  ,[CPU_BITS="-m64"]dnl
   [CPU_BIT_STR="64"]
   [CC_ASM_OBJS="x86-64.o sse-intrinsics-64.o"]
   [ARCH_LINK="x86-64.h"]
   [CFLAGS+=" -DUSING_ICC_S_FILE"]
   [AC_MSG_RESULT([64-bit])]
  ,[CPU_BITS="-m32"]dnl
   [CPU_BIT_STR="32"]
   [CC_ASM_OBJS="x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o"]
   [ARCH_LINK="x86-sse.h"]
   [CFLAGS+=" -DUSING_ICC_S_FILE"]
   [AC_MSG_RESULT([32-bit])]
   )]
,
[AC_RUN_IFELSE(
  [
  AC_LANG_SOURCE(
	[[int main() {
	#if defined(__x86_64)||defined(__x86_64__)||defined(__amd64)||defined(__amd64__)||defined(_LP64)||defined(_M_IX86)||\
	    defined(_M_AMD64)||defined(_M_IA64)||defined(_M_X64)||defined(__ILP32__)||defined(__LLP64__)||defined(WIN64)
	exit(0);
	#endif
	exit(1);}]]
  )]
  ,[CPU_BITS="-m64"]dnl
   [CPU_BIT_STR="64"]
   [CC_ASM_OBJS="x86-64.o sse-intrinsics.o"]
   [ARCH_LINK="x86-64.h"]
   [AC_MSG_RESULT([64-bit])]
  ,[CPU_BITS="-m32"]dnl
   [CPU_BIT_STR="32"]
   [CC_ASM_OBJS="x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o"]
   [ARCH_LINK="x86-sse.h"]
   [AC_MSG_RESULT([32-bit])]
  )]
 )
CC="$CC_BACKUP"
#############################################################################
# End of JtR 32/64 bit test code.
#############################################################################

#############################################################################
# ASM_MAGIC code.  Here we add certain 'magic' values. Things like
#  -DUNDERSCORES -DBSD -DALIGN_LOG   (for macosx-x86-*)
#  -DUNDERSCORES -DALIGN_LOG for (dos-djgpp-x86-*)
#  -DUNDERSCORES for cygwin / MinGW / VC
#############################################################################
EXTRA_AS_FLAGS=
AC_MSG_CHECKING([for extra ASFLAGS])
CC="$CC_BACKUP"

# this test also detects JUST the underscore issue, and is generic as long as strings and grep exist
AS_IF([echo "int long_ident;" > conftest.c && ${CC} -c conftest.c && strings - conftest.${OBJEXT} | ${GREP} _long_ident > conftest.out],
      [EXTRA_AS_FLAGS+="-DUNDERSCORES "])

AC_RUN_IFELSE(
  [
  AC_LANG_SOURCE(
	[[int main() {
	#if defined(__APPLE__) && defined(__MACH__)
	exit(0);
	#endif
	exit(1);}]]
  )]
  ,[EXTRA_AS_FLAGS+="-DBSD -DALIGN_LOG"])
#AC_RUN_IFELSE(
#  [
#  AC_LANG_SOURCE(
#	[[int main() {
#	#if defined(__DJGPP__)
#	exit(0);
#	#endif
#	exit(1);}]]
#  )]
#  ,[EXTRA_AS_FLAGS+="-DALIGN_LOG"])
AC_MSG_RESULT([$EXTRA_AS_FLAGS])
CC="$CC_BACKUP"

#############################################################################
# End of JtR ASM_MAGIC code
#############################################################################

#############################################################################
# check for unaligned memory access. being allowed
#############################################################################
#
AC_MSG_CHECKING([for unaligned memory access])
CC="$CC_BACKUP"
AC_RUN_IFELSE(
  [
  AC_LANG_SOURCE(
	[[#include <stdio.h>
	int main(){char c[20];*((int*)(&c[1]))=1;*((int*)(&c[2]))=1;*((int*)(&c[3]))=1;if(c[2]==88)printf("foobar");exit(0);}]]
  )]
  ,[ALLOWS_UNALIGNED="1"]
   [AC_MSG_RESULT([allowed])]
  ,[ALLOWS_UNALIGNED="0"]
   [AC_MSG_RESULT([NOT allowed])]
  )
CC="$CC_BACKUP"
#############################################################################
# End of JtR 32/64 bit test code.
#############################################################################

#############################################################################
# Check for LE/BE CPU
#############################################################################
AC_C_BIGENDIAN  #([ARCH_LE=0], [ARCH_LE=1], [action-if-unknown], [action-if-universal])
#############################################################################
# END Check for LE/BE CPU
#############################################################################

# Checks for libraries.
################################################
#  NOTE, be VERY careful of spaces around the comma's in the AC_CHECK_LIB. Best to not have any.
#  If there are space, then often that will get a lib to NOT be added to @LIBS@ and cause linkage problems.
#  also note, if action if found is specified, the -llibname will NOT get appended to LIBS. So it has to be
#  done by 'hand'.  Look at PCAP, where "LIBS += -lpcap" was added. This could also be done by skipping the
#  modified default action, and doing an AS_IF on the next line.
################################################
#
##### Note, for next 2(ssl and crypto), we probably should use pkg-config openssl (--cflags and --libs)
#
AC_CHECK_LIB([ssl],[SSL_library_init],[],[AC_MSG_FAILURE(JtR requires libssl being installed,1)])
AC_CHECK_LIB([crypto],[MD5_Update],[],[AC_MSG_FAILURE(JtR requires libssl/libcrypto being installed,1)])
#################
# libz is found in pkg-config --switch zlib
#################
AC_CHECK_LIB([m],[sqrt],[],[AC_MSG_FAILURE(JtR requires libm being installed,1)])
AC_CHECK_LIB([z],[deflate],[],[AC_MSG_FAILURE(JtR requires libz being installed,1)])
AC_SEARCH_LIBS([crypt],[crypt],[AC_DEFINE(HAVE_CRYPT,1,[Define to 1 if you have the `crypt' library (-lcrypt).])])
AC_CHECK_LIB([k5crypto],[krb5_c_string_to_key_with_params],[],[AC_MSG_WARN(Installing MIT krb5/k5crypto/ library enables several extra formats,1)] )
AC_CHECK_LIB([krb5],[krb5_c_string_to_key_with_params])
AC_CHECK_LIB([gmp],[__gmpz_init],[],[AC_MSG_WARN(Installing libgmp will speed up some hash formats)])
AC_CHECK_LIB([kernel32],[main])
AC_CHECK_LIB([dl],[dlopen])
AC_SEARCH_LIBS([c_regex_iterator_cb],[rexgen librexgen],[AC_DEFINE(HAVE_LIBREXGEN,1,[Define to 1 if you have the `rexgen' library (-lrexgen).])],[AC_MSG_WARN(Installing librexgen would enable a powerful new wordlist mode)])
AC_CHECK_LIB([nsl],[main])
AC_CHECK_LIB([pthread],[main])
AC_CHECK_LIB([rt],[main])
AC_CHECK_LIB([socket],[main])
# mingw stuff from older makefile rules.
AC_CHECK_LIB([wsock32],[main])
AC_CHECK_LIB([lws2_32],[main])
AC_CHECK_LIB([wst],[main])
# in makefile, we need to know if building extra pcap items.
AC_CHECK_LIB([pcap],[pcap_compile], [AC_SUBST(HAVE_PCAP,"1")] [LIBS+="-lpcap"])

AC_CACHE_SAVE

# check packages:

##################################
# check for NSS
##################################
PKG_CHECK_MODULES([NSS], [nss], AC_SUBST(HAVE_NSS,[-DHAVE_NSS]),
        AC_MSG_WARN(NSS not found - Mozilla format will be omitted.))

##################################
# check for openMP  (NOTE, AC_OPENMP does pretty much everything we were doing before)
##################################
#   Here iis with --disable-omp method.
#AC_ARG_ENABLE([openmp], [AS_HELP_STRING([--disable-openmp],[do not use OpenMP])],[disable_openmp=$enableval],[disable_openmp='yes'])
#   Here is the --with-omp method
#AC_ARG_WITH(openmp, [AS_HELP_STRING([--with-openmp],[compile with OpenMP (multi-thread) support. If none is found, OMP is not used. Default: auto])],,with_openmp=auto)
#   Here are the test cases for --with-xxx processing.
#AS_IF([test x"$with_openmp" = "xauto"],[AX_OPENMP(AC_SUBST(OPENMP_CFLAGS,${ax_cv_c_openmp}))])
#AS_IF([test x"$with_openmp" = "xyes"],
#    [AX_OPENMP([AC_SUBST(OPENMP_CFLAGS,${ax_cv_c_openmp})],
#              [AC_MSG_FAILURE([OMP requested, but could not use OMP.])])])
AC_OPENMP

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
# CUDA
####################################
AC_CHECK_LIB([cudart],[cudaGetDeviceCount])
AS_IF(test x${ac_cv_lib_cudart_main} = "xyes",[AC_SUBST(HAVE_CUDA,1)])

####################################
# OpenCL
####################################
AX_OPENCL(C)

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

AC_SUBST([CC_CPU],[${CPU_BEST_FLAGS}])
AC_SUBST([CC_MAIN_CPU],[${CPU_BEST_FLAGS_MAIN}])
AC_SUBST([CC_ASM_OBJS],[${CC_ASM_OBJS}])
AC_SUBST([CPU_BITS],[${CPU_BITS}])
AC_SUBST([CPU_BIT_STR],[${CPU_BIT_STR}])
AC_SUBST([EXTRA_AS_FLAGS],[${EXTRA_AS_FLAGS}])
AC_SUBST([JOHN_BUILD_LABEL],["${CPU_BIT_STR}-bit ${CPU_STR}-autoconf"])

AS_IF([test "x${ALLOWS_UNALIGNED}" = "x1"],
   [AC_DEFINE([ARCH_ALLOWS_UNALIGNED], 1, ["Enable if CPU allows unaligned memory access"])],
   [AC_DEFINE([ARCH_ALLOWS_UNALIGNED], 0, ["Enable if CPU allows unaligned memory access"])])

AS_IF([test "x${ac_cv_c_bigendian}" = "xyes"],
   [AC_DEFINE([ARCH_LITTLE_ENDIAN], 0, ["Enable if CPU is LITTLE ENDIAN arch"])],
   [AC_DEFINE([ARCH_LITTLE_ENDIAN], 1, ["Enable if CPU is LITTLE ENDIAN arch"])])

#ARCH_INT_GT_32  I thought this was 1 for 64 bit builds, but current arch.h seem broken
AC_DEFINE([ARCH_INT_GT_32], 0, ["Enable if CPU is > 32 bit (NOTE, this should not be enabled!)"])

# build proper 'link' to the arch file (based on bit only, for 32 bit, we may want different ones, and for other CPU's we need different ones)
# note, we remove it first.
AS_IF([rm -f arch.h])
AC_CONFIG_LINKS([arch.h:$ARCH_LINK])

AC_CONFIG_FILES([Makefile
                 aes/Makefile
                 aes/aesni/Makefile
                 aes/openssl/Makefile
                 escrypt/Makefile])
AC_OUTPUT(,echo "timestamp from configure.in" > autoconfig-stamp-h & echo "Done - Makefile generated.")
