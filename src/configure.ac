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

dnl this MUST be done early, so that the proper JtR overridden help message
dnl creation macro is the one that gets set first.
m4_include([m4/jtr_specific_configure_help_message.m4])

AC_PREREQ([2.69])
AC_INIT([john], [jumbo],[john-users mailing list at openwall.com])
##  AM_INIT_AUTOMAKE([foreign subdir-objects])
AC_CONFIG_SRCDIR([john.c])
AC_CONFIG_HEADERS([autoconfig.h])
AC_PREFIX_DEFAULT([../run])

# Include our extra macro code
m4_include([m4/pkg.m4])
m4_include([m4/ax_opencl.m4])
m4_include([m4/ax_pthread.m4])
m4_include([m4/ax_prog_cc_mpi.m4])
m4_include([m4/ax_lang_compiler_ms.m4])
m4_include([m4/ax_check_gnu_make.m4])
m4_include([m4/jtr_x86_logic.m4])
m4_include([m4/jtr_mic_logic.m4])
m4_include([m4/jtr_arm_logic.m4])
m4_include([m4/jtr_generic_logic.m4])
m4_include([m4/jtr_systems_specific_logic.m4])
m4_include([m4/jtr_utility_macros.m4])
m4_include([m4/jtr_local_conf.m4])

# Define precious variables. They get included in --help and need no AC_SUBST
AC_ARG_VAR([CFLAGS_EXTRA], [additional CFLAGS for -Woptions and other things, not used during ./configure but put in resulting Makefile])
AC_ARG_VAR([YASM], [full pathname of yasm (for optional AES-NI support)])
AC_ARG_VAR([AS], [full pathname of assembler to use])
AC_ARG_VAR([AR], [full pathname of "ar" to use])
AC_ARG_VAR([LD], [full pathname of linker to use])

# Define Packages.
# Intrinsics pre-compiled (to .S) with icc
AC_ARG_WITH(icc-asm, [AS_HELP_STRING([--with-icc-asm],[Use ICC pre-built asm files for intrisic SIMD code. Default: no])],,[with_icc_asm=no])
# Use OpenSSL (default: yes).
AC_ARG_WITH(openssl, [AS_HELP_STRING([--without-openssl],[Do not use Openssl (CommonCrypto must be enabled)])],,[with_openssl=yes])
# Use CommonCrypto (default: no)
AC_ARG_WITH(commoncrypto, [AS_HELP_STRING([--with-commoncrypto],[Use CommonCrypto])],,[with_commoncrypto=no])
# Cludge for endian (if not auto detected)
AC_ARG_WITH(endian, [AS_HELP_STRING([--with-endian=little|big],[Set endianness for target if it doesn't detect properly])],,[endian=unknown])
# -DJOHN_SYSTEMWIDE
AC_ARG_WITH(systemwide, [AS_HELP_STRING([--with-systemwide],[install for all users])],,[with_systemwide=no])
AC_ARG_WITH(flock, [AS_HELP_STRING([--with-flock],[use flock() file locking instead of fcntl()])],,[with_flock=no])

AC_ARG_ENABLE([memdbg], [AC_HELP_STRING([--enable-memdbg], [Enable memdbg memory debugging (safe level)])], [memdbg=$enableval], [memdbg=no])
AC_ARG_ENABLE([asan], [AS_HELP_STRING([--enable-asan], [* Build with AddressSanitizer])], [asan=$enableval], [asan=no])
AC_ARG_ENABLE([plugin-dependencies], [AS_HELP_STRING([--disable-plugin-dependencies], [Do not create best-effort Makefile dependencies for plugins])], [plug_deps=$enableval], [plug_deps=yes])

# Define Features. OpenMP and OpenCL are defined in their respective macros.
# We define "--disable-FEATURE" when default is "auto".
# MPI is not "auto" because its network usage might scare people:
AC_ARG_ENABLE([openmp-for-fast-formats], [AC_HELP_STRING([--enable-openmp-for-fast-formats], [Enable OpenMP for fast formats (usually a bad idea - use fork instead)])], [ompfast=$enableval], [ompfast=no])
AC_ARG_ENABLE([mpi], [AC_HELP_STRING([--enable-mpi], [Use OpenMPI])], [enable_mpi=$enableval], [enable_mpi=no])
AC_ARG_ENABLE([rexgen], [AC_HELP_STRING([--enable-rexgen], [Use rexgen library if present])], [enable_rexgen=$enableval], [enable_rexgen=auto])
AC_ARG_ENABLE([cuda], [AC_HELP_STRING([--disable-cuda], [Do not use CUDA])], [enable_cuda=$enableval], [enable_cuda=auto])
AC_ARG_ENABLE([pcap], [AC_HELP_STRING([--disable-pcap], [Do not build helpers depending on PCAP])], [enable_pcap=$enableval], [enable_pcap=auto])
AC_ARG_ENABLE([native-tests], [AC_HELP_STRING([--disable-native-tests], [Do not test build system for target features. Implies --disable-native-march.])], [enable_native_tests=$enableval], [enable_native_tests=auto])
AC_ARG_ENABLE([native-march], [AC_HELP_STRING([--disable-native-march], [Do not use things like -march=native even if valid compiler option(s). Native tests still can be run in this mode])], [enable_native_march=$enableval], [enable_native_march=auto])
AC_ARG_ENABLE([ln-s], [AS_HELP_STRING([--enable-ln-s],[Use ln -s vs symlink.c wrappers (Cygwin only)])], [enable_ln_s=$enableval], [enable_ln_s=no])
AC_ARG_ENABLE([pkg-config], [AS_HELP_STRING([--disable-pkg-config],[do not use pkg-config for any probing tests])], [enable_pkg_config=$enableval], [enable_pkg_config=auto])
AC_ARG_ENABLE([nt-full-unicode], [AS_HELP_STRING([--enable-nt-full-unicode],[support 4-byte UTF-8 for MS formats])], [enable_nt_unicode=$enableval], [enable_nt_unicode=no])
AC_ARG_ENABLE([int128], [AC_HELP_STRING([--disable-int128], [Do not use int128])], [enable_int128=$enableval], [enable_int128=auto])
AC_ARG_ENABLE([experimental-code], [AC_HELP_STRING([--enable-experimental-code], [Use experimental code])], [experimental=$enableval], [experimental=no])

####### Actual tests start here #######

# Assert that we don't have a stray GNUmakefile left in the tree :-(
if test -f GNU?akefile; then
   AC_MSG_ERROR([Stray GNUmakefile (or GNUMakefile) detected. Please remove it])
fi

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

# --disable-native-tests implies --disable-native-march
if test "x$enable_native_tests" = xno; then
   enable_native_march=no
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
AC_MSG_CHECKING([arg check macro for -m with $CC])
JTR_FLAG_CHECK([-mFOO_BAR_SWITCH_NOT_VALID], 0)
JTR_FLAG_CHECK([-m666], 0)
AS_IF([test "x${CFLAGS_EX}" = x],
   [AC_MSG_RESULT([yes])]
   JTR_FLAG_CHECK_WORKS=yes
   ,[AC_MSG_RESULT([no])])

# This gave false positives on gcc 4.4.7, see issue #682
CFLAGS_EX=""
AC_MSG_CHECKING([arg check macro for -Q with $CC])
JTR_FLAG_CHECK([-QFOO_BAR_SWITCH_NOT_VALID], 0)
AS_IF([test "x${CFLAGS_EX}" = x],
   [AC_MSG_RESULT([yes])]
   JTR_FLAG_Q_CHECK_WORKS=yes
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

   # pick -Og or -O1 for debug targets (applies to ASan too)
   CFLAGS_EX=""
   JTR_FLAG_CHECK([-Og], 1)
   if test "x${CFLAGS_EX}" != x ; then
      O_DEBUG=${CFLAGS_EX}
   else
      O_DEBUG="-O1"
   fi
   AC_SUBST([O_DEBUG],[$O_DEBUG])

   # if user requested  ASan, make sure we can properly build/link with it.
if test "x$asan" = xyes ; then
   CFLAGS_EX=""
   LDFLAGS_BAK=${LDFLAGS}
   JTR_FLAG_CHECK_LINK([-fsanitize=address], 1)
   if test "x${CFLAGS_EX}" = x ; then
      JTR_FLAG_CHECK_LINK([-faddress-sanitizer], 1)
      if test "x${CFLAGS_EX}" = x ; then
         asan=no
      else
         LDFLAGS="-faddress-sanitizer $LDFLAGS"
      fi
   else
      LDFLAGS="-fsanitize=address $LDFLAGS"
   fi
   LDFLAGS=${LDFLAGS_BAK}
fi

   # now fill out CFLAGS
   CFLAGS_EX=""
   JTR_FLAG_CHECK([-Wall], 1)
   JTR_FLAG_CHECK([-Wdeclaration-after-statement], 1)
if test "x$asan" = xyes ; then
   JTR_FLAG_CHECK([-fno-omit-frame-pointer], 1)
else
   JTR_FLAG_CHECK([-fomit-frame-pointer], 1)
fi
   # gcc bug workaround, see issue 632
   JTR_FLAG_CHECK([--param allow-store-data-races=0], 1)
   # Silly OSX warnings
   JTR_FLAG_CHECK([-Wno-deprecated-declarations], 1)
   # clang warnings
   JTR_FLAG_CHECK([-Wno-format-extra-args], 1)
   #JTR_FLAG_CHECK([-Wno-unneeded-internal-declaration], 1)
   AS_IF([test "x$JTR_FLAG_Q_CHECK_WORKS" = xyes], [JTR_FLAG_CHECK([-Qunused-arguments],1)])
   # Justified and Ancient (see #1093)
   JTR_FLAG_CHECK([-std=gnu89], 1)
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
AX_CHECK_GNU_MAKE()
AC_PROG_MAKE_SET
AC_PROG_CPP
AC_PROG_MKDIR_P
AC_CACHE_SAVE
AC_PATH_PROG([SORT], [sort])
AC_PATH_PROG([FIND], [find])
AC_PATH_PROG([PERL], [perl])
AS_IF([test -z "$AS"], [AS="$CC"])
AS_IF([test -z "$LD"], [LD="$CC"])
AS_IF([test -z "$AR"], [AC_PATH_PROG([AR], [ar])])
AS_IF([test -z "$STRIP"], [AC_PATH_PROG([STRIP], [strip])])

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
# *****************************************************************

dnl *** AC_CHECK_SIZEOF([char])
dnl *** AC_CHECK_SIZEOF([unsigned char])
AC_CHECK_SIZEOF([short])
dnl *** AC_CHECK_SIZEOF([unsigned short])
AC_CHECK_SIZEOF([int])
dnl *** AC_CHECK_SIZEOF([unsigned])
dnl *** AC_CHECK_SIZEOF([unsigned int])
AC_CHECK_SIZEOF([long])
AC_CHECK_SIZEOF([long long])
dnl *** AC_CHECK_SIZEOF([double])
dnl *** AC_CHECK_SIZEOF([long double])
AC_CHECK_SIZEOF([int *])
dnl ** AC_CHECK_SIZEOF([long long *])
AC_CHECK_SIZEOF([void *])
dnl  Not sure how to do sizeof function pointer in configure. I will add this one to jumbo.h 'by hand'
dnl AC_CHECK_SIZEOF([int *function()]

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
# x86-mmx.h
# x86-sse.h
#
# See http://ftp.netbsd.org/pub/NetBSD/NetBSD-release-6/src/external/bsd/pcc/dist/pcc/configure.ac for many alternatives
# *****************************************************************
#
cpu_family="unkown"
CPU_STR="$host_cpu"
case "$host_cpu" in
  alpha*) ARCH_LINK=alpha.h endian=little ;;
  armeb) ARCH_LINK=arm32le.h endian=big ;;
  arm*) ARCH_LINK=arm32le.h endian=little
        JTR_ARM_SPECIAL_LOGIC
        ;;
  ia64) ARCH_LINK=ia64.h endian=little cpu_family=intel ;;
  i?86) ARCH_LINK=x86-any.h endian=little cpu_family=intel ;;
  m68k*) ARCH_LINK=autoconf_arch.h endian=big ;;
  mic) ARCH_LINK=mic.h endian=little
       JTR_MIC_SPECIAL_LOGIC
       ;;
  mips|mipseb) ARCH_LINK=mips32.h endian=big ;;
  mipsel) ARCH_LINK=mips32.h endian=little ;;
  mips64|mips64eb|mipseb64) ARCH_LINK=mips64.h endian=big ;;
  mips64el|mipsel64) ARCH_LINK=mips64.h endian=little ;;
  mips64*) ARCH_LINK=mips64.h endian=big ;;
  mips*) ARCH_LINK=mips32.h endian=big ;;
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
# macros for each environment.  We probably should fall back to calling
# make -f Makefile.legacy clean generic or failing with an echo of that message,
# for any environment we do not handle.
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
   [if test "x$enable_native_tests" != xno -a "x$PKG_CONFIG" != xno; then
   PKG_CHECK_MODULES([OPENSSL], [openssl],
      AC_DEFINE(HAVE_LIBCRYPTO,1,[Define to 1 if you have the `crypto' library (-lcrypto).])
         AC_DEFINE(HAVE_LIBSSL,1,[Define to 1 if you have the `ssl' library (-lssl).]),
	    AC_MSG_FAILURE([JtR requires OpenSSL and OpenSSL-devel being installed. Install if not installed.
Try using --disable-pkg-config and possibly helping configure find oSSL by providing hints in CFLAGS and LDFLAGS],1))
else
   AS_IF([test "x${OPENSSL_CFLAGS}${OPENSSL_LIBS}" != "x" -o "x$cross_compiling" = "xyes" -o "x$enable_native_tests" = xno -o "x$PKG_CONFIG" = xno],
      [AC_MSG_CHECKING([supplied paths for OpenSSL])]
      [JTR_LIST_ADD(CFLAGS, [$OPENSSL_CFLAGS])]
      [if test "x$cross_compiling" = "xyes" -a "x$OPENSSL_LIBS" = "x"; then
        OPENSSL_LIBS="-lssl -lcrypto"
        fi]
      LIBS_ORIG="$LIBS"
      LIBS="$LIBS $OPENSSL_LIBS"
      [AC_MSG_RESULT([$OPENSSL_CFLAGS $OPENSSL_LIBS])]
      [if test "x$cross_compiling" = xno; then
         JTR_SET_NORMAL_SSL_INCLUDES([/usr/local/ssl])
	   fi]
      [AC_CHECK_HEADER([openssl/opensslv.h],
	   [AC_CHECK_LIB([ssl],[SSL_library_init],
	    [AC_CHECK_LIB([crypto],[MD5_Update],
	       [AC_DEFINE(HAVE_LIBSSL,1,[Define to 1 if you have the `ssl' library (-lssl).])]
	       [AC_DEFINE(HAVE_LIBCRYPTO,1,[Define to 1 if you have the `crypto' library (-lcrypto).])]
		  [OPENSSL_LIBS="-lssl -lcrypto"],
	       [AC_MSG_FAILURE(JtR requires libssl/libcrypto being installed,1)])],
	    [AC_MSG_FAILURE(JtR requires libssl being installed,1)]
	   )
	  LIBS="$LIBS_ORIG"],
	 [AC_MSG_FAILURE(JtR requires OpenSSL headers being installed,1)]
      )]
   )
   fi]
)

#################
# libz is found in pkg-config --switch zlib
#################
AC_CHECK_LIB([m],[sqrt],[AC_DEFINE(HAVE_LIBM,1,[Define to 1 if you have the `m' library (-lm).])] [AC_SUBST(M_LIBS, [-lm])],[AC_MSG_FAILURE(JtR requires libm being installed,1)])
AC_CHECK_LIB([z],[deflate],[AC_DEFINE(HAVE_LIBZ,1,[Define to 1 if you have the `z' library (-lz).])] [AC_SUBST(Z_LIBS, [-lz])])
BACKUP_LIBS="$LIBS"
LIBS=""
AC_SEARCH_LIBS([crypt],[crypt],[AC_DEFINE(HAVE_CRYPT,1,[Define to 1 if you have the `crypt' library (-lcrypt).])])
AC_SUBST(CRYPT_LIBS, [$LIBS])
LIBS="$BACKUP_LIBS"

AC_CHECK_HEADERS([gmp.h] [gmp/gmp.h], [AC_CHECK_LIB([gmp],[__gmpz_init], AC_DEFINE([HAVE_LIBGMP],1,[Define to 1 if you have the `gmp' library (-lgmp).]) [AC_SUBST(GMP_LIBS, [-lgmp])])] [break])
AC_CHECK_HEADER([skey.h], [AC_CHECK_LIB([skey],[skey_set_algorithm],
                          AC_DEFINE([HAVE_SKEY],1,[Define to 1 if you have skey library and headers]) [AC_SUBST(SKEY_LIBS, [-lskey])])])
AC_MSG_CHECKING([for S/Key])
AS_IF([test "x${ac_cv_lib_skey_skey_set_algorithm}" != xyes],
   [AC_MSG_RESULT([using our own code])],
   [AC_MSG_RESULT([using system library])]
)
AC_CHECK_HEADER([bzlib.h], [AC_CHECK_LIB([bz2],[main],
                          AC_DEFINE([HAVE_LIBBZ2],1,[Define to 1 if you have bz2 library and headers]) [AC_SUBST(BZ2_LIBS, [-lbz2])])])
AC_CHECK_LIB([kernel32],[main])
AC_CHECK_LIB([dl],[dlopen],[AC_DEFINE(HAVE_LIBDL,1,[Define to 1 if you have the `dl' library (-ldl).])] [AC_SUBST(DL_LIBS, [-ldl])])

AC_CHECK_HEADERS([intrin.h], break)

BACKUP_LIBS="$LIBS"

LIBS=""
using_rexgen=no
# Check for rexgen only if rexgen wanted
if test "x$enable_rexgen" != xno ; then
	AC_CHECK_HEADER([librexgen/c/librexgen.h],
	  [AC_SEARCH_LIBS([c_simplestring_new],[rexgen librexgen],
		using_rexgen=yes
		[AC_DEFINE(HAVE_LIBREXGEN,1,[Define to 1 if you have the `rexgen' library (-lrexgen).])])])
	AC_SUBST(REXGEN_LIBS, [$LIBS])
else
  AC_MSG_NOTICE([rexgen check not enabled])
fi

if test "x$ompfast" = xyes ; then
   AC_DEFINE([FAST_FORMATS_OMP], 1, ["Enable if you want OpenMP for fast formats"])
fi

if test "x$memdbg" = xyes ; then
   MEMDBG_CFLAGS="-DMEMDBG_ON"
fi
AC_SUBST([MEMDBG_CFLAGS],["${MEMDBG_CFLAGS}"])


LIBS="$BACKUP_LIBS"
# in makefile, we need to know if building extra pcap items.
if test "x$enable_pcap" != xno ; then
  AC_CHECK_HEADERS([pcap.h pcap/pcap.h],[AC_CHECK_LIB([pcap],[pcap_compile],
        [AC_SUBST(HAVE_PCAP,[-DHAVE_PCAP])] [AC_SUBST(PCAP_LIBS, [-lpcap])])]
        [break])
  AC_CHECK_HEADERS([pcap.h pcap/pcap.h],[AC_CHECK_LIB([wpcap],[pcap_compile],
        [AC_SUBST(HAVE_PCAP,[-DHAVE_PCAP])] [AC_SUBST(PCAP_LIBS, [-lwpcap])])]
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
AC_CHECK_FUNCS([EVP_aes_256_xts SHA256 WHIRLPOOL RIPEMD160 AES_encrypt EVP_sha512 BIO_new])
LIBS="$LIBS_ORIG"
CFLAGS="$CFLAGS_ORIG"

AC_CACHE_SAVE

#################
# Check packages:
#################

# Check for openMP (enable/disable handled within the macro).
AC_OPENMP

# Check for OpenCL (enable/disable handled within the macro)
AS_IF([test "x$cross_compiling" = xno -a "x$enable_opencl" != xno],
      [JTR_SET_OPENCL_INCLUDES])
AX_OPENCL(C)
if test "x$CL_LIBS" = x; then
   using_cl=no
else
   using_cl=yes
   HAVE_OPENCL=-DHAVE_OPENCL
fi

# Check for CUDA, including headers.
JTR_CUDA

# Checks for header files.
# Eg. if sys/times.h is found, the below will define HAVE_SYS_TIMES_H
AC_CHECK_HEADERS([arpa/inet.h crypt.h fcntl.h limits.h locale.h malloc.h \
                  net/ethernet.h netdb.h netinet/in.h netinet/in_systm.h \
                  stdint.h string.h strings.h \
                  sys/ethernet.h sys/file.h sys/param.h sys/socket.h \
                  sys/time.h sys/times.h sys/types.h termios.h \
                  unistd.h unixlib/local.h windows.h])
dnl -----------------------------------------
dnl AC_CHECK_HEADERS([OS.h])        dnl (wrapped with __BEOS__)
dnl AC_CHECK_HEADERS([stddef.h])    dnl too many to worry about. If this is an issue later, we will deal with it.
dnl AC_CHECK_HEADERS([stdlib.h ])   dnl too many to worry about. If this is an issue later, we will deal with it. NOTE, it is included sometime earlier on some other check
dnl AC_CHECK_HEADERS([sys/timeb.h]) dnl (wrapped with windows/msc/cygwin wrappers)
dnl AC_CHECK_HEADERS([wchar.h ])    dnl (wrapped with __linux__ & HAVE_LIBDL)
dnl -----------------------------------------
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
AS_IF([test $CPU_BIT_STR -ge 64], [AS_IF([test "x$enable_int128" != xno], [AC_CHECK_TYPES([int128, __int128, __int128_t])])])

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE

# JtR's usage of fork may not work on minwin, even though the AC_FUNC_FORK says it should
case "$host_os" in
  mingw*)
    # FORK is known to 'compile' but to fail and not be usable.
    ac_cv_func_fork=no
    ac_cv_func_fork_works=no
    ac_cv_func_vfork=no
    ac_cv_func_vfork_works=no
    AC_MSG_CHECKING([for working fork])
    AC_MSG_RESULT([no - os disabled])
    AC_MSG_CHECKING([for working vfork])
    AC_MSG_RESULT([no - os disabled])
    ;;
  *)
    AC_FUNC_FORK
    ;;
esac
# until we write a rpl_malloc replacement, we CAN NOT look for AC_FUNC_MALLOC.
#AC_FUNC_MALLOC
# we need a rpl_realloc before using this one.
#AC_FUNC_REALLOC

dnl --------------------------------------------------------------------
dnl these checks HAVE to be there (we have code using them)
dnl   setenv/putenv  fseek/ftell set,   memmem  sleep
dnl   stri*cmp/strcasecmp strlwr/strupr/strrev
dnl --------------------------------------------------------------------
AC_CHECK_FUNCS([fseek64 fseeko fseeko64 _fseeki64 lseek64 lseek ftell64 ftello \
               ftello64 _ftelli64 fopen64 _fopen64 memmem mmap sleep \
               setenv putenv strcasecmp strncasecmp \
               stricmp strcmpi _stricmp _strcmpi strnicmp strncmpi _strnicmp \
               _strncmpi strnlen strlwr strupr strrev \
               atoll _atoi64 snprintf sprintf_s strcasestr])
dnl AC_CHECK_FUNCS([memchr memmove memset munmap pow \
dnl                 select setlocale socket strchr \
dnl                 strdup strerror strstr
dnl  these extras removed for issue #910
dnl                 endpwent isascii mkdir rmdir atexit floor
dnl                 ftruncate gethostbyname gettimeofday inet_ntoa
dnl                 strrchr strcspn strspn strtol strtoul
dnl ])

# This will stop at first found, will be used for mem_alloc_aligned()
AC_CHECK_FUNCS([posix_memalign aligned_alloc memalign __mingw_aligned_malloc _aligned_malloc], break)

AC_CACHE_SAVE

AC_SUBST([CC_CPU],["${CPU_BEST_FLAGS}"])
AC_SUBST([CC_MAIN_CPU],["${CPU_BEST_FLAGS_MAIN}"])
AC_SUBST([CC_ASM_OBJS],["${CC_ASM_OBJS}"])
AC_SUBST([CPU_BITS],["${CPU_BITS}"])
AC_SUBST([CPU_BIT_STR],["${CPU_BIT_STR}"])
AC_SUBST([ASFLAGS],["${ASFLAGS}"])
AC_SUBST([EXTRA_AS_FLAGS],["${EXTRA_AS_FLAGS}"])

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
   case "${host}_${CFLAGS}" in
      *_*-mno-mmx*) ;;
      *_*-mno-sse2*) ;;
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
   AC_CACHE_CHECK([for yasm that supports "$aesni_options"], [ac_cv_path_YASM],
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

if test "x$asan" = xyes ; then
   CFLAGS=`echo $CFLAGS | sed 's/-g //g; s/-O2 //g'`
   CFLAGS=`echo $CFLAGS | sed 's/-g$//g; s/-O2$//g'`
   CFLAGS="-g $O_DEBUG -fsanitize=address $CFLAGS"
   LDFLAGS="-fsanitize=address $LDFLAGS"
fi

#add ARCH_LITTLE_ENDIAN to command line, IF we know it is big or little
if test "x$endian" = "xbig"; then
   CFLAGS="$CFLAGS -DARCH_LITTLE_ENDIAN=0"
   ASFLAGS="$ASFLAGS -DARCH_LITTLE_ENDIAN=0"
else
   if test "x$endian" = "xlittle"; then
      CFLAGS="$CFLAGS -DARCH_LITTLE_ENDIAN=1"
      ASFLAGS="$ASFLAGS -DARCH_LITTLE_ENDIAN=1"
   fi
fi

# build proper 'link' to the arch file (based on bit only, for 32 bit, we may
# want different ones, and for other CPU's we need different ones)
# note, we remove it first.
AS_IF([rm -f arch.h])
AC_CONFIG_LINKS([arch.h:$ARCH_LINK])

# For the fastest MS formats, full Unicode support (4-byte UTF-8) can
# mean a 10% performance hit. Default is support for up to 3-byte UTF-8
# which corresponds to full UCS-2 or Unicode BMP.
AS_IF([test "x$enable_nt_unicode" != xno], [AC_DEFINE([NT_FULL_UNICODE],1,[Define to 1 if you want support for 4-byte UTF-8 in fast MS formats.])])

# Use features that may not yet be stable
AS_IF([test "x$experimental" != xno], [AC_DEFINE([USE_EXPERIMENTAL],1,[Define to 1 if you want to include experimental code.])])

# code to create M4_INCLUDES (all ./m4/*.m4 )
AC_SUBST([M4_INCLUDES],[`echo m4/*.m4`])

# Handle --prefix -> JOHN_SYSTEMWIDE_EXEC
AS_IF([test $prefix != "../run" && test $prefix != "NONE" ],
   [CFLAGS="$CFLAGS -DJOHN_SYSTEMWIDE -DJOHN_SYSTEMWIDE_EXEC='\"$prefix\"'"],
   [AS_IF([test $with_systemwide != no], [CFLAGS="$CFLAGS -DJOHN_SYSTEMWIDE"
   prefix=/usr/libexec/john])]
)

if test x$with_flock != xno; then
   CFLAGS="$CFLAGS -DPREFER_FLOCK"
fi

#if test ${CPU_STR} = "AVX2" || test ${host_cpu} = "k1om"; then
#   if test x$experimental = xno; then
#      AC_DEFINE([DYNAMIC_DISABLED], 1, [Disables Dynamic format completely])
#   fi
#fi

####################################################
# Code  to create @PLUGFORMATS_OBJS@ and
# john_buildrule.h moved from Makefile.in to here.
####################################################
echo "configure: creating *_plug.c object rules"
if test "`echo *_plug.c`" != "*_plug.c"; then
   AC_SUBST([PLUGFORMATS_OBJS],[`echo *_plug.c | sed "s/\.c/.o/g"`])
   if test "x$plug_deps" = xyes -a "x$PERL" != x ; then
      echo "configure: creating Makefile dependencies"
      AC_SUBST([PLUGFORMATS_DEPS],[`$PERL ./plugin_deps.pl *_plug.c`])
   fi
fi

echo "configure: creating ./john_build_rule.h"
echo "#define JOHN_BLD \"${host_os} ${CPU_BIT_STR}-bit${using_x32} ${CPU_STR}-autoconf\"" > john_build_rule.h

AC_SUBST([HOST_OS],["$host_os"])
AC_CONFIG_FILES([Makefile
                 aes/Makefile
                 aes/aesni/Makefile
                 aes/openssl/Makefile
                 escrypt/Makefile])
AC_OUTPUT(,echo "timestamp from configure.in" > autoconfig-stamp-h)

##########################################################
# Create fmt_externs.h and fmt_registers.h
# This needs arch.h to be linked so can't happen before
# AC_OUTPUT
##########################################################
echo "configure: creating ./fmt_externs.h"
echo >fmt_externs.h
if test "`echo *_fmt_plug.c`" != "*_fmt_plug.c"; then
   $CPP -P -DAC_BUILT $CPPFLAGS $CPU_BEST_FLAGS $CFLAGS $HAVE_OPENCL $HAVE_CUDA $CFLAGS_EXTRA $OPENMP_CFLAGS $OPENSSL_CFLAGS -DFMT_EXTERNS_H *_fmt_plug.c | LC_ALL=C $GREP "extern struct fmt_main" | LC_ALL=C $SORT -f > fmt_externs.h
fi
echo "configure: creating ./fmt_registers.h"
echo > fmt_registers.h
if test "`echo *_plug.c`" != "*_plug.c"; then
   $CPP -P -DAC_BUILT $CPPFLAGS $CPU_BEST_FLAGS $CFLAGS $CFLAGS_EXTRA $OPENMP_CFLAGS $OPENSSL_CFLAGS -DFMT_REGISTERS_H *_fmt_plug.c | LC_ALL=C $GREP "john_register_one" | LC_ALL=C $SORT -f > fmt_registers.h
fi
if test "`echo opencl_*_fmt_plug.c`" != "opencl_*_fmt_plug.c"; then
   $CPP -P -DAC_BUILT $CPPFLAGS $CPU_BEST_FLAGS $CFLAGS $HAVE_OPENCL $HAVE_CUDA $CFLAGS_EXTRA $OPENMP_CFLAGS $OPENSSL_CFLAGS -DFMT_REGISTERS_H opencl_*_fmt_plug.c | LC_ALL=C $GREP "john_register_one" | LC_ALL=C $SORT -f >> fmt_registers.h
fi
if test "`echo cuda_*_fmt_plug.c`" != "cuda_*_fmt_plug.c"; then
   $CPP -P -DAC_BUILT $CPPFLAGS $CPU_BEST_FLAGS $CFLAGS $HAVE_OPENCL $HAVE_CUDA $CFLAGS_EXTRA $OPENMP_CFLAGS $OPENSSL_CFLAGS -DFMT_REGISTERS_H cuda_*_fmt_plug.c | LC_ALL=C $GREP "john_register_one" | LC_ALL=C $SORT -f >> fmt_registers.h
fi

########################################################
# Creates ./run/john.local.conf but ONLY if it does not
# exist. The file will have a valid comment section, and
# will be pre-seeded with all 'Local:' sections possible
# at the time of creation.
JTR_JOHN_LOCAL_CONF
########################################################

########################################################
#    ONLY _COSMETICAL_ OUTPUT STUFF BELOW THIS LINE
########################################################

# Hard to get proper info from AC_OPENMP. If it's enabled with no special
# options needed, we might end up listing it as disabled
if test "x$ac_cv_prog_c_openmp" != x -a  "x$enable_openmp" != xno -a dnl
        "x$ac_cv_prog_c_openmp" != xunsupported ; then
   if test "x$ompfast" = "xyes"; then
      using_omp=yes
   else
      using_omp="yes (not for fast formats)"
   fi
else
   using_omp=no
fi

if test "x$ac_cv_search_crypt" != xno; then
   using_crypt=yes
else
   using_crypt=no
fi

if test "x$ac_cv_lib_z_deflate" != xno; then
   using_zlib=yes
else
   using_zlib=no
fi

if test "x$ac_cv_lib_bz2_main" != xno; then
   using_bz2=yes
else
   using_bz2=no
fi

if test "x$ac_cv_func_mmap" != xno; then
   using_mmap=yes
else
   using_mmap=no
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
using_pcap=no
if test "x$ac_cv_lib_pcap_pcap_compile" = xyes ; then
    using_pcap=yes
fi
if test "x$ac_cv_lib_wpcap_pcap_compile" = xyes; then
   using_pcap=yes
fi
if test $(echo "$CFLAGS" | ${GREP} -c -- "-O") -eq 0 &&
   test $(echo "$CFLAGS" | ${GREP} -c -- "-xO") -eq 0 &&
   test $(echo "$CFLAGS" | ${GREP} -c -- "-fast\b") -eq 0; then
   echo
   AC_MSG_WARN([No recognized optimization option present in CFLAGS])
fi
if test "x$endian" = "xbig"; then
   using_endian="BE"
else
   using_endian="LE"
fi
if test x$_cv_gnu_make_command = x; then
   use_make=make
else
   use_make=$_cv_gnu_make_command
fi

if test "x$MEMDBG_CFLAGS" = "x"; then
   memdbg_settings="disabled"
else
   memdbg_settings=${MEMDBG_CFLAGS}
fi

if test "x$asan" = xyes ; then
   asan="enabled"
else
   asan="disabled"
fi

if test "x$enable_int128" = xno; then
   have_int128=disabled
elif test "x$ac_cv_type_int128" = xyes ||
   test "x$ac_cv_type___int128" = xyes ||
   test "x$ac_cv_type___int128_t" = xyes; then
   have_int128=yes
else
   have_int128=no
fi

cat <<EOF
dnl =======================================================================

Configured for building John the Ripper ${PACKAGE_VERSION}:

Target CPU .................................. ${host_cpu}, ${CPU_BIT_STR}-bit ${using_endian}${using_x32}
AES-NI support .............................. ${using_aesni}
Target OS ................................... ${host_os}
Cross compiling ............................. ${cross_compiling}
Legacy arch header .......................... ${ARCH_LINK}

Optional libraries/features found:
Experimental code ........................... ${experimental}
OpenMPI support (default disabled) .......... ${using_mpi}
Fork support ................................ ${ac_cv_func_fork_works}
OpenMP support .............................. ${using_omp}
OpenCL support .............................. ${using_cl}
CUDA support ................................ ${using_cuda}
Generic crypt(3) format ..................... ${using_crypt}
Rexgen (extra cracking mode) ................ ${using_rexgen}
GMP (PRINCE mode and faster SRP formats) .... ${ac_cv_lib_gmp___gmpz_init}
PCAP (vncpcap2john and SIPdump) ............. ${using_pcap}
Z (pkzip format, gpg2john) .................. ${using_zlib}
BZ2 (gpg2john extra decompression logic) .... ${using_bz2}
128-bit integer (faster PRINCE mode) ........ ${have_int128}
Memory map (share/page large files) ......... ${using_mmap}

Development options (these may hurt performance when enabled):
Memdbg memory debugging settings ............ ${memdbg_settings}
AddressSanitizer ("ASan") ................... ${asan}

Install missing libraries to get any needed features that were omitted.

Configure finished.  Now '${use_make} clean && ${use_make} -s' to compile.
EOF
dnl =======================================================================
