#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

# Travis CI only has 2.68
AC_PREREQ([2.68])
AC_INIT([john], [1.8.0.bleeding], [john-users mailing list at openwall.com])
##  AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_SRCDIR([john.c])
AC_CONFIG_HEADERS([autoconfig.h])

# include our extra macro code
m4_include([m4/pkg.m4])
m4_include([m4/ax_opencl.m4])
m4_include([m4/ax_pthread.m4])
m4_include([m4/ax_prog_cc_mpi.m4])
m4_include([m4/ax_lang_compiler_ms.m4])
m4_include([m4/ax_jtr_x86_logic.m4])
m4_include([m4/ax_jtr_generic_logic.m4])

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
dnl    AC_CHECK_SIZEOF (type-or-expr, [unused], [includes = 'AC_INCLUDES_DEFAULT'])
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

# Fugly workaround for .gitignore refusing to ignore Makefile since it is
# a managed file (the stub). The result of this is a *local* workaround.
if test -d "../.git"; then
  AC_CHECK_PROG([HAVE_GIT], [git], [yes], [no])
  if test x${HAVE_GIT} = xyes; then
     git update-index --assume-unchanged Makefile
  fi
fi

if test -d /usr/local/lib; then
   LDFLAGS+=" -L/usr/local/lib"
fi
if test -d /usr/local/include; then
   CFLAGS+=" -I/usr/local/include"
fi
if test -d /usr/local/ssl/lib; then
   LDFLAGS+=" -L/usr/local/ssl/lib"
fi
if test -d /usr/local/ssl/include; then
   CFLAGS+=" -I/usr/local/ssl/include"
fi

if test -n "$NVIDIA_CUDA"; then
   if test -d "$NVIDIA_CUDA/include"; then
      CFLAGS+=" -I$NVIDIA_CUDA/include"
   fi
   if test -d "$NVIDIA_CUDA/lib"; then
      LDFLAGS+=" -L$NVIDIA_CUDA/lib"
   fi
else
   if test -d "/usr/local/cuda/include"; then
      CFLAGS+=" -I/usr/local/cuda/include"
   fi
   if test -d "/usr/local/cuda/lib"; then
      LDFLAGS+=" -L/usr/local/cuda/lib"
   fi
fi

if test -n "$AMDAPPSDKROOT"; then
   if test -d "$AMDAPPSDKROOT/include"; then
      CFLAGS+=" -I$AMDAPPSDKROOT/include"
   fi
   if test -d "$AMDAPPSDKROOT/lib"; then
      LDFLAGS+=" -L$AMDAPPSDKROOT/lib"
   fi
fi
if test -n "$ATISTREAMSDKROOT"; then
   if test -d "$ATISTREAMSDKROOT/include"; then
      CFLAGS+=" -I$ATISTREAMSDKROOT/include"
   fi
   if test -d "$ATISTREAMSDKROOT/lib"; then
      LDFLAGS+=" -L$ATISTREAMSDKROOT/lib"
   fi
fi

# Shorthand: -with-arch=-m32 will add '-m32' to CFLAGS, ASFLAGS and LDFLAGS.
AC_ARG_WITH(arch, [AS_HELP_STRING([--with-arch=opt],[Add 'opt' to CFLAGS, LDFLAGS and ASFLAGS (eg. -m32).])],,[with_arch=""])

if test x${with_arch} != x; then
   CFLAGS+=" ${with_arch}"
   CPPFLAGS+=" ${with_arch}"
   CXXFLAGS+=" ${with_arch}"
   LDFLAGS+=" ${with_arch}"
   ASFLAGS+=" ${with_arch}"
fi

# Define Packages.
AC_ARG_WITH(icc-asm, [AS_HELP_STRING([--with-icc-asm],[Use ICC pre-built asm files for intrisic SIMD code. Default: no])],,[with_icc_asm=no])
AC_ARG_WITH(exe-ext, [AS_HELP_STRING([--with-exe-ext],[For Cygwin and MinGW. Set to .exe to allow stand alone symlink exe files. Default is 'empty'])],,[with_exe_ext=""])

# Cludge for endian (if not auto detected)
AC_ARG_WITH(endian, [AS_HELP_STRING([--with-endian=little|big],[Set endianness for target])],,[endian=unknown])

# Define Features. OpenMP and OpenCL are defined in their respective macros.
# We define "--disable-FEATURE" when default is "auto".
# MPI is not "auto" because its network usage might scare people:
AC_ARG_ENABLE([mpi], [AC_HELP_STRING([--enable-mpi], [Use MPI])], [enable_mpi=$enableval], [enable_mpi=no])
AC_ARG_ENABLE([cuda], [AC_HELP_STRING([--disable-cuda], [Do not use CUDA])], [enable_cuda=$enableval], [enable_cuda=auto])
AC_ARG_ENABLE([nss], [AC_HELP_STRING([--disable-nss], [Do not use NSS/NSPR])], [enable_nss=$enableval], [enable_nss=auto])
AC_ARG_ENABLE([native-tests], [AC_HELP_STRING([--disable-native-tests], [Do not use test build system for target features])], [enable_native_tests=$enableval], [enable_native_tests=auto])

####### Actual tests start here #######

# Support cross compile
AC_CANONICAL_HOST

# Check for MPI. Only if MPI not found/wanted: Check for CC.
AX_PROG_CC_MPI([test x"$enable_mpi" != "xno"], [AC_SUBST(HAVE_MPI,[-DHAVE_MPI])],[
   if test x"$enable_mpi" = "xyes"; then
     AC_MSG_FAILURE([No MPI compiler found])
   elif test x"$enable_mpi" != "xno"; then
     AC_MSG_NOTICE([No MPI compiler found, disabling MPI])
   fi
   AC_PROG_CC([gcc cc icc ccc])
])

# At this point we know whether this is a cross compile
# Don't test for $cross_compiling = yes, because it might be 'maybe'.
if test ${enable_native_tests} = auto; then
   if test x${cross_compiling} != xno; then
      AC_MSG_NOTICE([This is a cross-compile; all native tests disabled])
      enable_native_tests=no
   else
      enable_native_tests=yes
   fi
fi

# Checks for programs.
AC_PROG_LN_S
AC_PROG_GREP
AC_PROG_SED
AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_CPP
AC_CACHE_SAVE
# I wish sort was a 'standard' autocheck
AC_PATH_PROG([SORT], [sort])

# Check if we have this at all
PKG_PROG_PKG_CONFIG
if test "x$PKG_CONFIG" = x ; then
    PKG_CONFIG=no
fi

# Cross-compile compliant size checks
AC_CHECK_SIZEOF([char])
AC_CHECK_SIZEOF([unsigned char])
AC_CHECK_SIZEOF([short])
AC_CHECK_SIZEOF([unsigned short])
AC_CHECK_SIZEOF([int])
AC_CHECK_SIZEOF([unsigned])
AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([long])
AC_CHECK_SIZEOF([long long])
AC_CHECK_SIZEOF([double])
AC_CHECK_SIZEOF([long double])
AC_CHECK_SIZEOF([int *])
AC_CHECK_SIZEOF([long long *])
AC_CHECK_SIZEOF([void *])

# Available arch.h's:
# alpha.h
# arm32le.h (mfpu=neon) (we may override the "le")
# ia64.h
# mips32.h (we override the BE defined within it)
# mips64.h
# pa-risc.h
# ppc32.h
# ppc32alt.h (-maltivec)
# ppc64.h (-m64)
# ppc64alt.h (-maltivec -faltivec)
# sparc32.h
# sparc64.h (-m64 -mcpu=ultrasparc) (-xarch=native64)
# vax.h
# x86-64.h (-mx32, -m64)
# x86-any.h
# x86-mmx.h (currently busted)
# x86-sse.h
#
# See http://ftp.netbsd.org/pub/NetBSD/NetBSD-release-6/src/external/bsd/pcc/dist/pcc/configure.ac for many alternatives
#
cpu_family="unkown"
case "$host_cpu" in
  alpha*) ARCH_LINK=alpha.h endian=little ;;
  armeb) ARCH_LINK=arm32le.h endian=big ;;
  arm*) ARCH_LINK=arm32le.h endian=little ;;
  ia64) ARCH_LINK=ia64.h endian=little cpu_family=intel ;;
  i?86) ARCH_LINK=x86-any.h endian=little cpu_family=intel ;;
  m68k*) ARCH_LINK=autoconf_arch.h endian=big ;;
  mipseb) ARCH_LINK=mips32.h endian=big ;;
  mips*) ARCH_LINK=mips32.h endian=little ;;
  pdp*) ARCH_LINK=autoconf_arch.h endian=little ;;
  powerpcle) ARCH_LINK=ppc32.h endian=little ;;
  powerpc*) ARCH_LINK=ppc32.h endian=big ;;
  sparc64) ARCH_LINK=sparc64.h endian=big ;;
  sparc*) ARCH_LINK=sparc32.h endian=big ;;
  vax*) ARCH_LINK=vax.h endian=little ;;
  x86_64) ARCH_LINK=x86-64.h endian=little cpu_family=intel ;;
  *)
     AC_MSG_WARN([Uncertain support for ${target}, please report!])
     ARCH_LINK=autoconf_arch.h
     ;;
esac

# NOTE, later, we will probably do this by parsing the host or target to figure
# out the system, then have a switch statement, based upon the system, calling
# the proper AX_JTR_cputype_SPECIAL_LOGIC function (and of course have to write
# macros for each environment.  We probaby should fall back to calling
# make -f Makefile.orig clean generic or failing with an echo of that message,
# for any environment we do not handle.
CPU_STR="$host_cpu"
AS_IF([test x$cpu_family = xintel], [AX_JTR_X86_SPECIAL_LOGIC])
AC_MSG_CHECKING([for arch.h alternative])
AC_MSG_RESULT([${ARCH_LINK}])
AX_JTR_GENERIC_LOGIC

#############################################################################
# Check for unaligned memory access being allowed
#############################################################################
#
AC_MSG_CHECKING([for unaligned memory access])
CC="$CC_BACKUP"
AC_RUN_IFELSE(
  [
  AC_LANG_SOURCE(
	[[#include <stdio.h>
	extern void exit(int);
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
if test "x$endian" = "xunknown"; then
  AC_C_BIGENDIAN([endian=big], [endian=little])
else
  AC_MSG_CHECKING([for byte ordering according to target triple])
  AC_MSG_RESULT([${endian}])
fi
if test "x$endian" = "xbig"; then
   AC_DEFINE([ARCH_LITTLE_ENDIAN], 0, ["Enable if CPU is LITTLE ENDIAN arch"])
elif test "x$endian" = "xlittle"; then
   AC_DEFINE([ARCH_LITTLE_ENDIAN], 1, ["Enable if CPU is LITTLE ENDIAN arch"])
else
   AC_MSG_FAILURE([Could not determine endianity. Supply '--with-endian=little|big' and re-run])
fi

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

if test x${enable_native_tests} = xyes && test x$PKG_CONFIG != xno; then
   PKG_CHECK_MODULES([OPENSSL], [openssl],
     AC_DEFINE(HAVE_LIBCRYPTO,1,[Define to 1 if you have the `crypto' library (-lcrypto).])
	 AC_DEFINE(HAVE_LIBSSL,1,[Define to 1 if you have the `ssl' library (-lssl).]),
	 AC_MSG_FAILURE(JtR requires OpenSSL being installed,1))
else
   AC_CHECK_HEADER([openssl/opensslv.h],
   [AC_CHECK_LIB([ssl],[SSL_library_init],
      [AC_CHECK_LIB([crypto],[MD5_Update],[],
         [AC_MSG_FAILURE(JtR requires libssl/libcrypto being installed,1)])],
      [AC_MSG_FAILURE(JtR requires libssl being installed,1)])])
fi

#################
# libz is found in pkg-config --switch zlib
#################
AC_CHECK_LIB([m],[sqrt],[],[AC_MSG_FAILURE(JtR requires libm being installed,1)])
AC_CHECK_LIB([z],[deflate],[],[AC_MSG_FAILURE(JtR requires libz being installed,1)])
AC_SEARCH_LIBS([crypt],[crypt],[AC_DEFINE(HAVE_CRYPT,1,[Define to 1 if you have the `crypt' library (-lcrypt).])])
AC_CHECK_LIB([k5crypto],[krb5_c_string_to_key_with_params],[],[AC_MSG_WARN(Installing MIT krb5/k5crypto/ library enables several extra formats,1)] )
AC_CHECK_LIB([krb5],[krb5_c_string_to_key_with_params])
AC_CHECK_HEADERS([gmp.h] [gmp/gmp.h],[AC_CHECK_LIB([gmp],[__gmpz_init])] [break])
AS_IF([test x$ac_cv_lib_gmp___gmpz_init != xyes], [AC_MSG_WARN(Installing libgmp will speed up some hash formats)])
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
AC_CHECK_LIB([pcap],[pcap_compile], [AC_SUBST(HAVE_PCAP,[-DHAVE_PCAP])] [LIBS+=" -lpcap"])

# Check for non-standard variations we can handle
AC_CHECK_HEADER([openssl/whrlpool.h],,[AC_DEFINE([HAVE_NO_SSL_WHIRLPOOL], 1, ["Define if your OpenSSL is built without Whirlpool support"])])

AC_CACHE_SAVE

#################
# Check packages:
#################

# Check for NSS (unless disabled, or cross compiling)
if test x"$enable_nss" != "xno" && test x$PKG_CONFIG != xno; then
      PKG_CHECK_MODULES([NSS], [nss], AC_SUBST(HAVE_NSS,[-DHAVE_NSS]),
         AC_MSG_WARN(NSS not found - Mozilla format will be omitted.))
fi

# Check for openMP (enable/disable handled within the macro).
AC_OPENMP

# Check for CUDA. According to the guru's we should not try to be clever
# with finding directories. If they are not present in normal paths, user
# is supposed to supply them with eg. ./configure LDFLAGS=/usr/local/cuda/lib
if test x"$enable_cuda" != "xno"; then
   AC_CHECK_LIB([cudart],[cudaGetDeviceCount],AC_SUBST(HAVE_CUDA,1) [LIBS+=" -lcudart"],[
   if test x${enable_cuda} = yes; then
      AC_MSG_FAILURE([CUDA not found])
   elif test x"$enable_cuda" != "xno"; then
      AC_MSG_NOTICE([No CUDA found, disabling])
   fi
   ])
fi

# Check for OpenCL (enable/disable handled within the macro)
AX_OPENCL(C)

AS_IF([test x"$with_exe_ext" != "x"], AC_SUBST([EXE_EXT], [${with_exe_ext}]) [echo executable extension: ${with_exe_ext}] )

# Checks for header files.
# Eg. if arpa/inet.h is found, the below will define HAVE_ARPA_INET_H
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
AC_SUBST([ASFLAGS],[${ASFLAGS}])
AC_SUBST([EXTRA_AS_FLAGS],[${EXTRA_AS_FLAGS}])
AC_SUBST([JOHN_BUILD_LABEL],["${CPU_BIT_STR}-bit ${CPU_STR}-autoconf"])

AS_IF([test "x${ALLOWS_UNALIGNED}" = "x1"],
   [AC_DEFINE([ARCH_ALLOWS_UNALIGNED], 1, ["Enable if CPU allows unaligned memory access"])],
   [AC_DEFINE([ARCH_ALLOWS_UNALIGNED], 0, ["Enable if CPU allows unaligned memory access"])])

AS_IF([test $ac_cv_sizeof_int -gt 4],
   [AC_DEFINE([ARCH_INT_GT_32], 1, ["Enable if sizeof(int) > 4"])],
   [AC_DEFINE([ARCH_INT_GT_32], 0, ["Enable if sizeof(int) > 4"])])

AS_IF([[test ${CPU_BIT_STR} -eq 64] && [test ${ac_cv_sizeof_long} -eq 4]],
   [AC_DEFINE([ARCH_WORD], [long long], ["Type with native size"])],
   [AC_DEFINE([ARCH_WORD], [long], ["Type with native size"])])

AS_IF([test ${CPU_BIT_STR} -eq 64],
   [AC_DEFINE([ARCH_SIZE], 8, ["Native CPU width"])],
   [AC_DEFINE([ARCH_SIZE], 4, ["Native CPU width"])])
AC_DEFINE_UNQUOTED([ARCH_BITS], [$CPU_BIT_STR], ["Native CPU width, bits"])
AS_IF([test ${CPU_BIT_STR} -eq 64],
   [AC_DEFINE([ARCH_BITS_LOG], 6, ["Native CPU width, log"])],
   [AC_DEFINE([ARCH_BITS_LOG], 5, ["Native CPU width, log"])])
AC_DEFINE_UNQUOTED([ARCH_BITS_STR], ["$CPU_BIT_STR"], ["Native CPU width, string"])

# build proper 'link' to the arch file (based on bit only, for 32 bit, we may
# want different ones, and for other CPU's we need different ones)
# note, we remove it first.
AS_IF([rm -f arch.h])
AC_CONFIG_LINKS([arch.h:$ARCH_LINK])

##########################################################
# Code  to create @PLUGFORMAT_SRCS@ @PLUGFORMATS_OBJS@
# and fmt_externs.h fmt_registers.h and john_buildrule.h
# moved from Makefile.in to here.
##########################################################
AC_SUBST([PLUGFORMATS_SRCS],[`echo *_plug.c`])
AC_SUBST([PLUGFORMATS_OBJS],[`echo *_plug.c | sed "s/\.c/.o/g"`])
echo "configure: creating ./fmt_externs.h"
LC_ALL=C ${SED} -n 's/^\(struct fmt_main [[^ ]]*\) =.*/extern \1;/p' *_fmt_plug.c | LC_ALL=C ${SORT} > fmt_externs.h
echo "configure: creating ./fmt_registers.h"
LC_ALL=C ${SED} -n 's/^struct fmt_main \([[^ ]]*\) =.*/john_register_one(\&\1);/p' *_fmt_plug.c | LC_ALL=C ${SORT} > fmt_registers.h
echo "configure: creating ./john_build_rule.h"
echo "#define JOHN_BLD \"${CPU_BIT_STR}-bit ${CPU_STR}-autoconf\"" > john_build_rule.h
########################################################
# End of plugin and build_rules generation code
########################################################

AC_CONFIG_FILES([Makefile
                 aes/Makefile
                 aes/aesni/Makefile
                 aes/openssl/Makefile
                 escrypt/Makefile])
AC_OUTPUT(,echo "timestamp from configure.in" > autoconfig-stamp-h & echo "Done - Makefile generated. Now run 'make clean && make'")
