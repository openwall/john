#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# This file is Copyright (c) 2014 by JimF and magnum.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# There's ABSOLUTELY NO WARRANTY, express or implied.
#

dnl TODO: This is the suggested order for tests:
dnl checks for programs
dnl checks for libraries
dnl checks for header files
dnl checks for types
dnl checks for structures
dnl checks for compiler characteristics
dnl checks for library functions
dnl checks for system services

AC_PREREQ([2.69])
AC_INIT([john], [1.8.0.2-bleeding-jumbo],[john-users mailing list at openwall.com])
##  AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_SRCDIR([john.c])
AC_CONFIG_HEADERS([autoconfig.h])

# Include our extra macro code
m4_include([m4/pkg.m4])
m4_include([m4/ax_opencl.m4])
m4_include([m4/ax_pthread.m4])
m4_include([m4/ax_prog_cc_mpi.m4])
m4_include([m4/ax_lang_compiler_ms.m4])
m4_include([m4/jtr_x86_logic.m4])
m4_include([m4/jtr_generic_logic.m4])
m4_include([m4/jtr_systems_specific_logic.m4])
m4_include([m4/jtr_utility_macros.m4])

# Workaround for .gitignore refusing to ignore Makefile since it is
# a managed file (the stub). The result of this is a *local* workaround.
AS_IF([test -d "../.git"],
  [AC_CHECK_PROG([HAVE_GIT], [git], [yes], [no])]
  [AS_IF([test "x$HAVE_GIT" = xyes],
     [git update-index --assume-unchanged Makefile]
  )]
)

# Define precious variables. They get included in --help and need no AC_SUBST
AC_ARG_VAR([CFLAGS_EXTRA], [additional CFLAGS for -Woptions and other things, not used during ./configure but put in resulting Makefile])
AC_ARG_VAR([YASM], [full pathname of yasm (for optional AES-NI support)])

# Define Packages.
# Intrinsics pre-compiled (to .S) with icc
AC_ARG_WITH(icc-asm, [AS_HELP_STRING([--with-icc-asm],[Use ICC pre-built asm files for intrisic SIMD code. Default: no])],,[with_icc_asm=no])
# Use OpenSSL (default: yes).
AC_ARG_WITH(openssl, [AS_HELP_STRING([--without-openssl],[Do not use Openssl (CommonCrypto must be enabled)])],,[with_openssl=yes])
# Use CommonCrypto (default: no)
AC_ARG_WITH(commoncrypto, [AS_HELP_STRING([--with-commoncrypto],[Use CommonCrypto])],,[with_commoncrypto=no])
# Cludge for endian (if not auto detected)
AC_ARG_WITH(endian, [AS_HELP_STRING([--with-endian=little|big],[Set endianness for target if it doesn't detect properly])],,[endian=unknown])

# Define Features. OpenMP and OpenCL are defined in their respective macros.
# We define "--disable-FEATURE" when default is "auto".
# MPI is not "auto" because its network usage might scare people:
AC_ARG_ENABLE([mpi], [AC_HELP_STRING([--enable-mpi], [Use OpenMPI])], [enable_mpi=$enableval], [enable_mpi=no])
AC_ARG_ENABLE([cuda], [AC_HELP_STRING([--disable-cuda], [Do not use CUDA])], [enable_cuda=$enableval], [enable_cuda=auto])
AC_ARG_ENABLE([nss], [AC_HELP_STRING([--disable-nss], [Do not use NSS/NSPR])], [enable_nss=$enableval], [enable_nss=auto])
AC_ARG_ENABLE([pcap], [AC_HELP_STRING([--disable-pcap], [Do not build helpers depending on PCAP])], [enable_pcap=$enableval], [enable_pcap=auto])
AC_ARG_ENABLE([native-tests], [AC_HELP_STRING([--disable-native-tests], [Do not use test build system for target features])], [enable_native_tests=$enableval], [enable_native_tests=auto])
AC_ARG_ENABLE([ln-s], [AS_HELP_STRING([--enable-ln-s],[Use ln -s vs symlink.c wrappers (Cygwin only)])], [enable_ln_s=$enableval], [enable_ln_s=no])
AC_ARG_ENABLE([pkg-config], [AS_HELP_STRING([--disable-pkg-config],[do not use pkg-config for any probing tests])], [enable_pkg_config=$enableval], [enable_pkg_config=auto])

####### Actual tests start here #######

# Support cross compile
AC_CANONICAL_HOST

# Check for MPI. Only if MPI not found/wanted: Check for CC.
using_mpi=no
AX_PROG_CC_MPI([test "x$enable_mpi" != xno],
   [AC_SUBST(HAVE_MPI,[-DHAVE_MPI])]
   [using_mpi=yes],
   [AS_IF([test "x$enable_mpi" = xyes],
     [AC_MSG_FAILURE([No MPI compiler found])],
     [test "x$enable_mpi" != xno],
     [AC_MSG_NOTICE([No MPI compiler found, disabling MPI])])
     AC_PROG_CC([gcc cc icc ccc])
   ]
)

# At this point we know whether this is a cross compile
# Don't test for $cross_compiling = yes, because it might be 'maybe'.
if test "x$enable_native_tests" = xauto; then
   if test "x$cross_compiling" != xno; then
      AC_MSG_NOTICE([This is a cross-compile; all native tests disabled])
      enable_native_tests=no
   else
      enable_native_tests=yes
   fi
fi

###
# Here we call setting up many -I in CFLAGS, and -L in
# LDFLAGS for 'normal' paths, IF we find them.
###
AS_IF([test "x$cross_compiling" = xno], [JTR_SET_NORMAL_INCLUDES])

###
# check compiler switches here.  OPT_NORMAL, then
#  OPT_INLINE, then extra CFLAGS are checked.
###
#
# first test a totally BOGUS command line switch, to make sure that the
# detection logic actually detects BAD command switches
CFLAGS_EX=""
JTR_FLAG_CHECK([-fFOO_BAR_SWITCH_NOT_VALID], 0)
# note, check message must be done after the first call to JTR_FLAG_CHECK. Since this is
# the first macro that will use $CC, a lot of messages will happen.  We need to make that first
# macro 'call', so that those messages are output, THEN we make our checking message.
AC_MSG_CHECKING([arg check macro with $CC])
JTR_FLAG_CHECK([-mFOO_BAR_SWITCH_NOT_VALID], 0)
JTR_FLAG_CHECK([-m666], 0)
AS_IF([test "x${CFLAGS_EX}" = x],
   [AC_MSG_RESULT([yes])]
   JTR_FLAG_CHECK_WORKS=yes
   ,[AC_MSG_RESULT([no])])

# Now, we only do option checking, IF this worked, i.e. that option was not detected as valid
AS_IF([test "x$JTR_FLAG_CHECK_WORKS" = xyes],
[
   CFLAGS_EX=""
   # first fill out JtR's OPT_NORMAL= value
   JTR_FLAG_CHECK([-funroll-loops], 1)
   OPT_NORMAL_V=${CFLAGS_EX}
   AC_SUBST([OPT_NORMAL_FLAGS],["${OPT_NORMAL_V}"])

   # now fill in extras for JtR's OPT_INLINE= value
   CFLAGS_EX=""
   JTR_FLAG_CHECK([-Os], 1)
   JTR_FLAG_CHECK([-funroll-loops], 0)
   JTR_FLAG_CHECK([-finline-functions], 1)
   AC_SUBST([OPT_INLINE_FLAGS],["${CFLAGS_EX}"])

   # now fill out CFLAGS
   CFLAGS_EX=""
   JTR_FLAG_CHECK([-Wall], 1)
   JTR_FLAG_CHECK([-Wdeclaration-after-statement], 1)
   JTR_FLAG_CHECK([-fomit-frame-pointer], 1)
   # Silly OSX warnings
   JTR_FLAG_CHECK([-Wno-deprecated-declarations], 1)
   # clang warnings
   #JTR_FLAG_CHECK([-Wno-format-extra-args], 1)
   #JTR_FLAG_CHECK([-Wno-unneeded-internal-declaration], 1)
   JTR_LIST_ADD(CFLAGS_EXTRA, ["$CFLAGS_EX"])
],[dnl
   AC_MSG_NOTICE([Unable to validate $CC command line arguments. CFLAGS may need to be passed to ./configure for proper build])
])

# Checks for programs.
AC_PROG_LN_S
AC_PROG_GREP
dnl AC_PROG_EGREP Do not trust this one
AC_PROG_SED
dnl AC_PROG_CXX
AC_PROG_MAKE_SET
AC_PROG_CPP
AC_PROG_MKDIR_P
AC_CACHE_SAVE
AC_PATH_PROG([SORT], [sort])
AC_PATH_PROG([AR], [ar])
AC_PATH_PROG([FIND], [find])

# Check if we have this at all
PKG_PROG_PKG_CONFIG
AC_MSG_CHECKING([if pkg-config will be used])
if test "x$PKG_CONFIG" = x || test "x$enable_pkg_config" == xno ; then
	AC_MSG_RESULT([no])
	PKG_CONFIG=no
else
	AC_MSG_RESULT([yes])
fi

# Cross-compile compliant size checks
# size_t and off_t are post-poned to after feature macros are set
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
# x86-mmx.h (currently busted in many formats)
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
     AC_MSG_WARN([Uncertain support for ${host}, please report!])
     ARCH_LINK=autoconf_arch.h
     ;;
esac

# NOTE, later, we will probably do this by parsing the host or target to figure
# out the system, then have a switch statement, based upon the system, calling
# the proper JTR_cputype_SPECIAL_LOGIC function (and of course have to write
# macros for each environment.  We probaby should fall back to calling
# make -f Makefile.orig clean generic or failing with an echo of that message,
# for any environment we do not handle.
CPU_STR="$host_cpu"
AS_IF([test "x$cpu_family" = xintel], [JTR_X86_SPECIAL_LOGIC])
AC_MSG_CHECKING([for arch.h alternative])
AC_MSG_RESULT([${ARCH_LINK}])
JTR_GENERIC_LOGIC

# Set a variable detecting x86-64 w/ X32 ABI
if test "x$ax_intel_x32" = xyes; then
   using_x32=", X32 ABI"
else
   using_x32=""
fi

#############################################################################
# Check for unaligned memory access being allowed
# TODO: Needs fix for cross compile (we can infer it from $host_cpu)
#############################################################################
AC_MSG_CHECKING([for unaligned memory access allowed])
if test "x$enable_native_tests" = xyes; then
   AC_RUN_IFELSE(dnl
     [dnl
     AC_LANG_SOURCE(dnl
           [[#include <stdio.h>
           extern void exit(int);
           int main(){char c[20];*((int*)(&c[1]))=1;*((int*)(&c[2]))=1;*((int*)(&c[3]))=1;if(c[2]==88)printf("foobar");exit(0);}]]
     )]
     ,[ALLOWS_UNALIGNED="1"]
      [AC_MSG_RESULT([yes])]
     ,[ALLOWS_UNALIGNED="0"]
      [AC_MSG_RESULT([no])]
   )
elif test "x$cpu_family" = xintel; then
   ALLOWS_UNALIGNED="1"
   AC_MSG_RESULT([yes])
else
   ALLOWS_UNALIGNED="0"
   AC_MSG_RESULT([unknown, assuming no])
fi

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
# Checks for libraries.
#
# NOTE, be VERY careful of spaces around the comma's in the AC_CHECK_LIB. Best
# to not have any.  If there are space, then often that will get a lib to NOT
# be added to @LIBS@ and cause linkage problems.  Also note, if action if found
# is specified, the -llibname will NOT get appended to LIBS. So it has to be
# done by 'hand'.
################################################

AS_IF([test "x$with_commoncrypto" != xyes && test "x$with_openssl" = xno],
   [AC_MSG_FAILURE([At least one of OpenSSL and CommonCrypto must be used],1)]
)

AS_IF([test "x$with_commoncrypto" = xyes],
   [AC_CHECK_HEADER([CommonCrypto/CommonDigest.h],
   [AC_CHECK_LIB([System], [CCKeyDerivationPBKDF],
         [AC_CHECK_LIB([System], [CCCryptorCreate], [JTR_LIST_ADD(CFLAGS,"-DCOMMON_DIGEST_FOR_OPENSSL")] [AC_SUBST(COMMONCRYPTO_LIBS, [-lSystem])] [AC_DEFINE(HAVE_COMMONCRYPTO,1,[Define to 1 if you have the CommonCrypto library.])], [AC_MSG_FAILURE([No CommonCrypto found],1)])]dnl
       )]dnl
   )]dnl
)

AS_IF([test "x$with_openssl" != xno],
   [if test "x$enable_native_tests" = xyes -a "x$PKG_CONFIG" != xno; then
   PKG_CHECK_MODULES([OPENSSL], [openssl],
      AC_DEFINE(HAVE_LIBCRYPTO,1,[Define to 1 if you have the `crypto' library (-lcrypto).])
         AC_DEFINE(HAVE_LIBSSL,1,[Define to 1 if you have the `ssl' library (-lssl).]),
	    AC_MSG_FAILURE([JtR requires OpenSSL being installed],1))
else
   AS_IF([test "x${OPENSSL_CFLAGS}${OPENSSL_LIBS}" != "x"],
      [AC_MSG_CHECKING([supplied paths for OpenSSL])]
      [JTR_LIST_ADD(CFLAGS, [$OPENSSL_CFLAGS])]
      [AC_MSG_RESULT([$OPENSSL_CFLAGS $OPENSSL_LIBS])],
      [test "x$cross_compiling" = xno],
      [JTR_SET_NORMAL_SSL_INCLUDES([/usr/local/ssl])]
      [AC_CHECK_HEADER([openssl/opensslv.h],
	 [AC_CHECK_LIB([ssl],[SSL_library_init],
	    [AC_CHECK_LIB([crypto],[MD5_Update],
	       [AC_DEFINE(HAVE_LIBSSL,1,[Define to 1 if you have the `ssl' library (-lssl).])]
	       [AC_DEFINE(HAVE_LIBCRYPTO,1,[Define to 1 if you have the `crypto' library (-lcrypto).])]
		  [OPENSSL_LIBS="-lssl -lcrypto"],
	       [AC_MSG_FAILURE(JtR requires libssl/libcrypto being installed,1)])],
	    [AC_MSG_FAILURE(JtR requires libssl being installed,1)]
	 )],
	 [AC_MSG_FAILURE(JtR requires OpenSSL headers being installed,1)]
      )]
   )
   fi]
)

#################
# libz is found in pkg-config --switch zlib
#################
AC_CHECK_LIB([m],[sqrt],[AC_DEFINE(HAVE_LIBM,1,[Define to 1 if you have the `m' library (-lm).])] [AC_SUBST(M_LIBS, [-lm])],[AC_MSG_FAILURE(JtR requires libm being installed,1)])
AC_CHECK_LIB([z],[deflate],[AC_DEFINE(HAVE_LIBZ,1,[Define to 1 if you have the `z' library (-lz).])] [AC_SUBST(Z_LIBS, [-lz])],[AC_MSG_FAILURE(JtR requires libz being installed,1)])
BACKUP_LIBS="$LIBS"
LIBS=""
AC_SEARCH_LIBS([crypt],[crypt],[AC_DEFINE(HAVE_CRYPT,1,[Define to 1 if you have the `crypt' library (-lcrypt).])])
AC_SUBST(CRYPT_LIBS, [$LIBS])
LIBS="$BACKUP_LIBS"
# Check for Kerberos5 libs
krb5_found=no
AC_CHECK_HEADER([krb5.h],
  [AC_SEARCH_LIBS([krb5_is_thread_safe], [krb5 k5crypto])]
  [AC_SEARCH_LIBS([krb5_c_string_to_key], [krb5 k5crypto])]
  [AC_SEARCH_LIBS([krb5_c_string_to_key_with_params], [krb5 k5crypto])]
  [AC_SEARCH_LIBS([krb5_free_keyblock_contents], [krb5 k5crypto],
    [AS_IF([test "x$ac_cv_search_krb5_c_string_to_key" = "xnone required"],
      [AC_DEFINE([HAVE_HEIMDAL],1,[Define to 1 if you have Heimdal krb5.])]
      [AC_DEFINE([HAVE_MKSHIM],1,[Define to 1 if you have Heimdal with MKShim.])]
      [krb5_found="yes (Heimdal w/ MKShim)"],
      [AC_CHECK_HEADERS([heim_err.h heimdal/heim_err.h],
        [AC_DEFINE([HAVE_HEIMDAL],1,[Define to 1 if you have Heimdal krb5.])]
        [krb5_found="yes, Heimdal"]
       ,[krb5_found="yes, MIT"])]
    )]
    [AC_DEFINE([HAVE_KRB5],1,[Define to 1 if you have the Kerberos 5 libs.])]
    [AC_SUBST(KRB5_LIBS, ["$LIBS"])]
  )]
  [LIBS="$BACKUP_LIBS"]
)
AC_CHECK_HEADERS([gmp.h] [gmp/gmp.h], [AC_CHECK_LIB([gmp],[__gmpz_init], AC_DEFINE([HAVE_LIBGMP],1,[Define to 1 if you have the `gmp' library (-lgmp).]) [AC_SUBST(GMP_LIBS, [-lgmp])])] [break])
AC_CHECK_HEADER([skey.h], [AC_CHECK_LIB([skey],[skey_set_algorithm],
                          AC_DEFINE([HAVE_SKEY],1,[Define to 1 if you have skey library and headers]) [AC_SUBST(SKEY_LIBS, [-lskey])])])
AC_MSG_CHECKING([for S/Key])
AS_IF([test "x${ac_cv_lib_skey_skey_set_algorithm}" != xyes],
   [AC_MSG_RESULT([using our own code])],
   [AC_MSG_RESULT([using system library])]
)
AC_CHECK_LIB([kernel32],[main])
AC_CHECK_LIB([dl],[dlopen],[AC_DEFINE(HAVE_LIBDL,1,[Define to 1 if you have the `dl' library (-ldl).])] [AC_SUBST(DL_LIBS, [-ldl])])
using_rexgen=no
BACKUP_LIBS="$LIBS"
LIBS=""
AC_CHECK_HEADER([librexgen/api/c/librexgen.h],
  [AC_SEARCH_LIBS([c_regex_iterator_cb],[rexgen librexgen],
    using_rexgen=yes
    [AC_DEFINE(HAVE_LIBREXGEN,1,[Define to 1 if you have the `rexgen' library (-lrexgen).])])])
AC_SUBST(REXGEN_LIBS, [$LIBS])
LIBS="$BACKUP_LIBS"
# in makefile, we need to know if building extra pcap items.
if test "x$enable_pcap" != xno ; then
  AC_CHECK_HEADERS([pcap.h pcap/pcap.h],[AC_CHECK_LIB([pcap],[pcap_compile],
        [AC_SUBST(HAVE_PCAP,[-DHAVE_PCAP])] [AC_SUBST(PCAP_LIBS, [-lpcap])])]
        [break])
else
  AC_MSG_NOTICE([PCAP check disabled])
fi

####################################
# Check for variations we can handle
####################################
AC_HEADER_TIME
ACX_HEADER_STRING
# Check missing stuff in OpenSSL (too old, or disabled features)
LIBS_ORIG="$LIBS"
CFLAGS_ORIG="$CFLAGS"
LIBS="$OPENSSL_LIBS $COMMONCRYPTO_LIBS $LIBS"
CFLAGS="$OPENSSL_CFLAGS $CFLAGS"
AS_IF([test "$with_commoncrypto" = yes], [AC_DEFINE([HAVE_SHA256],1,[Define to 1 if you have the `SHA256' function.])])
AC_CHECK_FUNCS([EVP_aes_256_xts SHA256 WHIRLPOOL AES_encrypt EVP_sha512 BIO_new])
LIBS="$LIBS_ORIG"
CFLAGS="$CFLAGS_ORIG"

AC_CACHE_SAVE

#################
# Check packages:
#################

# Check for NSS
using_nss=no
AS_IF([test "x$enable_nss" != xno],
   [AS_IF([test "x$PKG_CONFIG" != xno],
      [PKG_CHECK_MODULES([NSS], [nss], using_nss=yes [AC_SUBST(HAVE_NSS,[-DHAVE_NSS])],:)],
      [AS_IF([test "x${NSS_CFLAGS}${NSS_LIBS}" != "x"],
         [AC_MSG_CHECKING([supplied paths for NSS])]
         [AC_MSG_RESULT([$NSS_CFLAGS $NSS_LIBS])]
         using_nss=yes
      )]
      [AC_MSG_CHECKING([for NSS])]
      [AC_MSG_RESULT([$using_nss])]
   )]
)

# Check for openMP (enable/disable handled within the macro).
AC_OPENMP

# Check for OpenCL (enable/disable handled within the macro)
AS_IF([test "x$cross_compiling" = xno -a "x$enable_opencl" != xno],
      [JTR_SET_OPENCL_INCLUDES])
AX_OPENCL(C)

# Check for CUDA, including headers.
JTR_CUDA

# Checks for header files.
# Eg. if sys/times.h is found, the below will define HAVE_SYS_TIMES_H
AC_CHECK_HEADERS([OS.h arpa/inet.h crypt.h fcntl.h limits.h locale.h \
                  net/ethernet.h netdb.h netinet/in.h netinet/in_systm.h \
                  stddef.h stdint.h stdlib.h string.h strings.h \
                  sys/ethernet.h sys/file.h sys/param.h sys/socket.h \
                  sys/time.h sys/timeb.h sys/times.h sys/types.h termios.h \
                  unistd.h unixlib/local.h wchar.h windows.h])
# Quirks for Solaris and OpenBSD
AC_CHECK_HEADERS([net/if.h], [], [],[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
])
AC_CHECK_HEADERS([net/if_arp.h], [], [],[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
])
AC_CHECK_HEADERS([netinet/if_ether.h], [], [],[
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NET_IF_ARP_H
#include <net/if_arp.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
])
AC_CHECK_HEADERS([netinet/ip.h], [], [], [
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
])
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
AC_FUNC_MMAP

# until we write a rpl_malloc replacement, we CAN NOT look for AC_FUNC_MALLOC.
#AC_FUNC_MALLOC
# we need a rpl_realloc before using this one.
#AC_FUNC_REALLOC

AC_CHECK_FUNCS([fseek64 fseeko fseeko64 _fseeki64 lseek64 lseek ftell64 ftello \
               ftello64 _ftelli64 fopen64 _fopen64 memmem sleep atexit \
               endpwent floor ftruncate gethostbyname gettimeofday inet_ntoa \
               isascii mkdir rmdir setenv putenv strcasecmp strncasecmp \
               stricmp strcmpi _stricmp _strcmpi strnicmp strncmpi _strnicmp \
               _strncmpi strrchr strcspn strspn strtol strtoul strlwr strupr \
               bzero atoll _atoi64 snprintf sprintf_s])
#AC_CHECK_FUNCS([memchr memmove memset munmap pow \
#                select setlocale socket strchr \
#                strdup strerror strstr])
AC_CACHE_SAVE

AC_SUBST([CC_CPU],["${CPU_BEST_FLAGS}"])
AC_SUBST([CC_MAIN_CPU],["${CPU_BEST_FLAGS_MAIN}"])
AC_SUBST([CC_ASM_OBJS],["${CC_ASM_OBJS}"])
AC_SUBST([CPU_BITS],["${CPU_BITS}"])
AC_SUBST([CPU_BIT_STR],["${CPU_BIT_STR}"])
AC_SUBST([ASFLAGS],["${ASFLAGS}"])
AC_SUBST([EXTRA_AS_FLAGS],["${EXTRA_AS_FLAGS}"])

AS_IF([test "x$ALLOWS_UNALIGNED" = x1],
   [AC_DEFINE([ARCH_ALLOWS_UNALIGNED], 1, ["Enable if CPU allows unaligned memory access"])],
   [AC_DEFINE([ARCH_ALLOWS_UNALIGNED], 0, ["Enable if CPU allows unaligned memory access"])])

AS_IF([test $ac_cv_sizeof_int -gt 4],
   [AC_DEFINE([ARCH_INT_GT_32], 1, ["Enable if sizeof(int) > 4"])],
   [AC_DEFINE([ARCH_INT_GT_32], 0, ["Enable if sizeof(int) > 4"])])

AS_IF([[test "$CPU_BIT_STR" -eq 64] && [test "$ac_cv_sizeof_long" -eq 4]],
   [AC_DEFINE([ARCH_WORD], [long long], ["Type with native size"])],
   [AC_DEFINE([ARCH_WORD], [long], ["Type with native size"])])

AS_IF([test "$CPU_BIT_STR" -eq 64],
   [AC_DEFINE([ARCH_SIZE], 8, ["Native CPU width"])],
   [AC_DEFINE([ARCH_SIZE], 4, ["Native CPU width"])])
AC_DEFINE_UNQUOTED([ARCH_BITS], [$CPU_BIT_STR], ["Native CPU width, bits"])
AS_IF([test "$CPU_BIT_STR" -eq 64],
   [AC_DEFINE([ARCH_BITS_LOG], 6, ["Native CPU width, log"])],
   [AC_DEFINE([ARCH_BITS_LOG], 5, ["Native CPU width, log"])])
AC_DEFINE_UNQUOTED([ARCH_BITS_STR], ["$CPU_BIT_STR"], ["Native CPU width, string"])

if test "$CPU_BIT_STR" = "32"; then
   aesni_arch="86"
else
   aesni_arch="64"
fi
AC_SUBST([AESNI_ARCH],["$aesni_arch"])

aesni_os=""
aesni_options="DISABLED"
if test "x$ax_intel_x32" = xyes; then
   aesni_os=linux aesni_options="-g dwarf2 -f elfx32"
else
   case "$host" in
      x86_64*darwin*)
         aesni_os=darwin
         aesni_options="--prefix=_ -f macho${CPU_BIT_STR}"
      ;;
      i?86*darwin*)
         aesni_os=darwin
         aesni_options="-f macho${CPU_BIT_STR}"
      ;;
      *86*linux*)
         aesni_os=linux
         aesni_options="-g dwarf2 -f elf${CPU_BIT_STR}"
      ;;
      *86*cygwin*)
         aesni_os=cygwin
         aesni_options="-f win${CPU_BIT_STR}"
      ;;
   esac
fi
if test "x$aesni_options" != xDISABLED; then
   AC_CACHE_CHECK([for yasm that supports "$aesni_options]", [ac_cv_path_YASM],
      [AC_PATH_PROGS_FEATURE_CHECK([YASM], [yasm],
         [[yasmout=`$ac_path_YASM $aesni_options 2>&1 | grep "No input files"`
           test "x$yasmout" != x \
           && ac_cv_path_YASM=$ac_path_YASM ac_path_YASM_found=:]]
         )])
fi
if test "x$aesni_options" != xDISABLED -a "x$ac_path_YASM_found" != xfalse; then
   using_aesni="run-time detection"
elif test "$cpu_family" = intel; then
   using_aesni="depends on OpenSSL"
else
   using_aesni=no
fi
AC_SUBST([YASM], [$ac_cv_path_YASM])
AC_SUBST([AESNI_OS],["$aesni_os"])
AC_SUBST([YASM_OPTIONS],["$aesni_options"])

JTR_SYSTEMS_SPECIFIC_LOGIC

# The size of size_t and/or off_t might change when feature macros (chosen in
# JTR_SYSTEMS_SPECIFIC_LOGIC) are used.
CFLAGS_BACKUP="$CFLAGS"
CFLAGS="$CFLAGS $CFLAGS_EXTRA"
AC_CHECK_SIZEOF([size_t])
AC_CHECK_SIZEOF([off_t])
CFLAGS="$CFLAGS_BACKUP"

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
echo "#define JOHN_BLD \"${host_os} ${CPU_BIT_STR}-bit${using_x32} ${CPU_STR}-autoconf\"" > john_build_rule.h
########################################################
# End of plugin and build_rules generation code
########################################################

AC_SUBST([HOST_OS],["$host_os"])
AC_CONFIG_FILES([Makefile
                 aes/Makefile
                 aes/aesni/Makefile
                 aes/openssl/Makefile
                 escrypt/Makefile])
AC_OUTPUT(,echo "timestamp from configure.in" > autoconfig-stamp-h)

########################################################
#    ONLY _COSMETICAL_ OUTPUT STUFF BELOW THIS LINE
########################################################
if test "x$CL_LIBS" = x; then
   using_cl=no
else
   using_cl=yes
fi

# Hard to get proper info from AC_OPENMP. If it's enabled with no special
# options needed, we might end up listing it as disabled
if test "x$ac_cv_prog_c_openmp" != x -a  "x$enable_openmp" != xno -a dnl
        "x$ac_cv_prog_c_openmp" != xunsupported ; then
   using_omp=yes
else
   using_omp=no
fi

if test "x$ac_cv_search_crypt" != xno; then
   using_crypt=yes
else
   using_crypt=no
fi

if test "x$host_cpu" != "x$CPU_STR" ; then
   host_cpu="$host_cpu $CPU_STR"
fi

# Ensure reports of tests does not show up blank:
if test "x$ac_cv_func_fork_works" = x ; then
   ac_cv_func_fork_works=no
fi
if test "x$ac_cv_lib_gmp___gmpz_init" = x ; then
   ac_cv_lib_gmp___gmpz_init=no
fi
if test "x$ac_cv_lib_pcap_pcap_compile" = x ; then
   ac_cv_lib_pcap_pcap_compile=no
fi
if test $(echo "$CFLAGS" | ${GREP} -c -- "-O") -eq 0 &&
   test $(echo "$CFLAGS" | ${GREP} -c -- "-xO") -eq 0 &&
   test $(echo "$CFLAGS" | ${GREP} -c -- "-fast\b") -eq 0; then
   echo
   AC_MSG_WARN([No recognized optimization option present in CFLAGS])
fi
if test "x$endian" = "big"; then
   using_endian="BE"
else
   using_endian="LE"
fi

cat <<EOF
dnl =======================================================================

Configured for building John the Ripper ${PACKAGE_VERSION}:

Target CPU .................................. ${host_cpu}, ${CPU_BIT_STR}-bit ${using_endian}${using_x32}
AES-NI support .............................. ${using_aesni}
Target OS ................................... ${host_os}
Cross compiling ............................. ${cross_compiling}
Legacy arch header .......................... ${ARCH_LINK}
OpenMPI support (default disabled) .......... ${using_mpi}
Fork support ................................ ${ac_cv_func_fork_works}
OpenMP support .............................. ${using_omp}
OpenCL support .............................. ${using_cl}
CUDA support ................................ ${using_cuda}
Generic crypt(3) mode ....................... ${using_crypt}

Optional libraries found:
Rexgen (extra cracking mode) ................ ${using_rexgen}
GMP (performance) ........................... ${ac_cv_lib_gmp___gmpz_init}
NSS/NSPR (Mozilla format) ................... ${using_nss}
Kerberos5 (krb5-18/23 formats) .............. ${krb5_found}
PCAP (vncpcap2john and SIPdump) ............. ${ac_cv_lib_pcap_pcap_compile}

Install missing libraries to get any needed features that were omitted.

Configure finished.  Do 'make -s' to compile.
EOF
dnl =======================================================================
