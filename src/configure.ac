dnl                                               -*- Autoconf -*-
dnl Process this file with autoconf to produce a configure script.
dnl
dnl This file is Copyright (c) 2014 by JimF and magnum.
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted.
dnl
dnl There's ABSOLUTELY NO WARRANTY, express or implied.
dnl

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
AC_CONFIG_SRCDIR([john.c])
AC_CONFIG_HEADERS([autoconfig.h])
AC_PREFIX_DEFAULT([../run])

dnl Include our extra macro code
m4_include([m4/pkg.m4])
m4_include([m4/ax_opencl.m4])
m4_include([m4/ax_pthread.m4])
m4_include([m4/ax_prog_cc_mpi.m4])
m4_include([m4/ax_lang_compiler_ms.m4])
m4_include([m4/ax_check_gnu_make.m4])
m4_include([m4/jtr_asm_magic.m4])
m4_include([m4/jtr_x86_logic.m4])
m4_include([m4/jtr_mic_logic.m4])
m4_include([m4/jtr_ppc_logic.m4])
m4_include([m4/jtr_arm_logic.m4])
m4_include([m4/jtr_generic_logic.m4])
m4_include([m4/jtr_systems_specific_logic.m4])
m4_include([m4/jtr_utility_macros.m4])
m4_include([m4/ax_ztex.m4])

dnl Define precious variables. They get included in --help and need no AC_SUBST
AC_ARG_VAR([CFLAGS_EXTRA], [additional CFLAGS for -Woptions and other things, not used during ./configure but put in resulting Makefile])
AC_ARG_VAR([YASM], [full pathname of yasm (for optional AES-NI support)])
AC_ARG_VAR([AS], [full pathname of assembler to use])
AC_ARG_VAR([AR], [full pathname of "ar" to use])
AC_ARG_VAR([LD], [full pathname of linker to use])

dnl Define Packages.
dnl Use OpenSSL (default: yes).
AC_ARG_WITH(openssl, [AS_HELP_STRING([--without-openssl],[Do not use OpenSSL (exclude much functionality)])],,[with_openssl=yes])
AC_ARG_WITH(unrar, [AS_HELP_STRING([--without-unrar],[Omit non-free unrar code (rendering RAR v3 support incomplete)])],,[with_unrar=yes])
dnl Cludge for endian (if not auto detected)
AC_ARG_WITH(endian, [AS_HELP_STRING([--with-endian=little|big],[Set endianness for target if it doesn't detect properly])],,[endian=unknown])
dnl -DJOHN_SYSTEMWIDE
AC_ARG_WITH(systemwide, [AS_HELP_STRING([--with-systemwide],[install for all users])],,[with_systemwide=no])

AC_ARG_ENABLE([asan], [AS_HELP_STRING([--enable-asan], [* Build with AddressSanitizer])], [asan=$enableval], [asan=no])
AC_ARG_ENABLE([ubsan], [AS_HELP_STRING([--enable-ubsan], [* Build with UndefinedBehaviorSanitizer])], [ubsan=$enableval], [ubsan=no])
AC_ARG_ENABLE([ubsantrap], [AS_HELP_STRING([--enable-ubsantrap], [* Build with UndefinedBehaviorSanitizer, crashes on failure])], [ubsantrap=$enableval], [ubsantrap=no])
AC_ARG_ENABLE([simd], [AS_HELP_STRING([--disable-simd, --enable-simd=foo], [* Build forcing SIMD logic to be disabled, or force use of "foo" for SIMD (eg. --enable-simd=altivec)])], [simd=$enableval], [simd=yes])
AC_ARG_ENABLE([plugin-dependencies], [AS_HELP_STRING([--disable-plugin-dependencies], [Do not create best-effort Makefile dependencies for plugins])], [plug_deps=$enableval], [plug_deps=yes])

AC_ARG_ENABLE([werror], [AS_HELP_STRING([--enable-werror], [Treat warnings as errors])], [werror=$enableval], [werror=no])

dnl Define Features. OpenMP and OpenCL are defined in their respective macros.
dnl We define "--disable-FEATURE" when default is "auto".
dnl MPI is not "auto" because its network usage might scare people:
AC_ARG_ENABLE([openmp-for-fast-formats], [AC_HELP_STRING([--enable-openmp-for-fast-formats], [Enable OpenMP for fast formats (usually a bad idea - use fork instead)])], [ompfast=$enableval], [ompfast=no])
AC_ARG_ENABLE([mpi], [AC_HELP_STRING([--enable-mpi], [Use OpenMPI])], [enable_mpi=$enableval], [enable_mpi=no])
AC_ARG_ENABLE([rexgen], [AC_HELP_STRING([--enable-rexgen], [Enable use of rexgen library (unreliable!)])], [enable_rexgen=$enableval], [enable_rexgen=no])
AC_ARG_ENABLE([pcap], [AC_HELP_STRING([--disable-pcap], [Do not build helpers depending on PCAP])], [enable_pcap=$enableval], [enable_pcap=auto])
AC_ARG_ENABLE([native-tests], [AC_HELP_STRING([--disable-native-tests], [Do not test build system for target features.])], [enable_native_tests=$enableval], [enable_native_tests=auto])
AC_ARG_ENABLE([native-march], [AC_HELP_STRING([--enable-native-march], [Use things like -march=native if valid compiler option(s).])], [enable_native_march=$enableval], [enable_native_march=no])
AC_ARG_ENABLE([ln-s], [AS_HELP_STRING([--enable-ln-s],[Use ln -s vs symlink.c wrappers (Cygwin only)])], [enable_ln_s=$enableval], [enable_ln_s=no])
AC_ARG_ENABLE([pkg-config], [AS_HELP_STRING([--enable-pkg-config],[use pkg-config for some probing tests])], [enable_pkg_config=$enableval], [enable_pkg_config=no])
AC_ARG_ENABLE([nt-full-unicode], [AS_HELP_STRING([--enable-nt-full-unicode],[support 4-byte UTF-8 for MS formats])], [enable_nt_unicode=$enableval], [enable_nt_unicode=no])
AC_ARG_ENABLE([int128], [AC_HELP_STRING([--disable-int128], [Do not use int128])], [enable_int128=$enableval], [enable_int128=auto])
AC_ARG_ENABLE([experimental-code], [AC_HELP_STRING([--enable-experimental-code], [Use experimental code])], [experimental=$enableval], [experimental=no])
AC_ARG_ENABLE([fuzz], [AC_HELP_STRING([--enable-fuzz], [Fuzzing prepare(), valid(), init(), etc])], [fuzz=$enableval], [fuzz=no])
AC_ARG_ENABLE([libfuzzer], [AC_HELP_STRING([--enable-libfuzzer], [Fuzzing using libFuzzer])], [libfuzzer=$enableval], [libfuzzer=no])

dnl ===================== Actual tests start here ========================

dnl Assert that we don't have a stray GNUmakefile left in the tree :-(
if test -f GNU?akefile; then
   AC_MSG_ERROR([Stray GNUmakefile (or GNUMakefile) detected. Please remove it])
fi

dnl Support cross compile
AC_CANONICAL_HOST

dnl Check for MPI. Only if MPI not found/wanted: Check for CC.
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

dnl At this point we know whether this is a cross compile
dnl Don't test for $cross_compiling = yes, because it might be 'maybe'.
if test "x$enable_native_tests" = xauto; then
   if test "x$cross_compiling" != xno; then
      AC_MSG_NOTICE([This is a cross-compile; all native tests disabled])
      enable_native_tests=no
   else
      enable_native_tests=yes
   fi
fi

dnl ======================================================================
dnl Here we call setting up many -I in CFLAGS, and -L in
dnl LDFLAGS for 'normal' paths, IF we find them.
dnl ======================================================================
AS_IF([test "x$cross_compiling" = xno], [JTR_SET_NORMAL_INCLUDES])

dnl ======================================================================
dnl only do auto unit-tests logic IF we are not cross compiling
dnl ======================================================================
AS_IF([test "x$enable_native_tests" = xyes], [AC_SUBST(UNIT_TESTS_DEPENDENCY,[unit-tests])])

dnl ======================================================================
dnl check compiler switches here.  OPT_NORMAL, then
dnl  OPT_INLINE, then extra CFLAGS are checked.
dnl ======================================================================
dnl
dnl first test a totally BOGUS command line switch, to make sure that the
dnl detection logic actually detects BAD command switches
CFLAGS_EX=""
JTR_FLAG_CHECK([-fFOO_BAR_SWITCH_NOT_VALID], 0)
dnl note, check message must be done after the first call to JTR_FLAG_CHECK. Since this is
dnl the first macro that will use $CC, a lot of messages will happen.  We need to make that first
dnl macro 'call', so that those messages are output, THEN we make our checking message.
AC_MSG_CHECKING([arg check macro for -m with $CC])
JTR_FLAG_CHECK([-mFOO_BAR_SWITCH_NOT_VALID], 0)
JTR_FLAG_CHECK([-m666], 0)
AS_IF([test "x${CFLAGS_EX}" = x],
   [AC_MSG_RESULT([yes])]
   JTR_FLAG_CHECK_WORKS=yes
   ,[AC_MSG_RESULT([no])])

dnl This gave false positives on gcc 4.4.7, see issue 682
CFLAGS_EX=""
AC_MSG_CHECKING([arg check macro for -Q with $CC])
JTR_FLAG_CHECK([-QFOO_BAR_SWITCH_NOT_VALID], 0)
AS_IF([test "x${CFLAGS_EX}" = x],
   [AC_MSG_RESULT([yes])]
   JTR_FLAG_Q_CHECK_WORKS=yes
   ,[AC_MSG_RESULT([no])])

dnl Now, we only do option checking, IF this worked, i.e. that option was not detected as valid
AS_IF([test "x$JTR_FLAG_CHECK_WORKS" = xyes],
[
   CFLAGS_EX=""
   dnl first fill out JtR's OPT_NORMAL= value
   JTR_FLAG_CHECK([-funroll-loops], 1)
   OPT_NORMAL_V=${CFLAGS_EX}
   AC_SUBST([OPT_NORMAL_FLAGS],["${OPT_NORMAL_V}"])

   dnl now fill in extras for JtR's OPT_INLINE= value
   CFLAGS_EX=""
   JTR_FLAG_CHECK([-Os], 1)
   JTR_FLAG_CHECK([-funroll-loops], 0)
   JTR_FLAG_CHECK([-finline-functions], 1)
   AC_SUBST([OPT_INLINE_FLAGS],["${CFLAGS_EX}"])

   dnl pick -Og or -O1 for debug targets (applies to ASan/UbSan too)
   CFLAGS_EX=""
   JTR_FLAG_CHECK([-Og], 1)
   if test "x${CFLAGS_EX}" != x ; then
      O_DEBUG=${CFLAGS_EX}
   else
      O_DEBUG="-O1"
   fi
   AC_SUBST([O_DEBUG],[$O_DEBUG])

   dnl if user requested  ASan, make sure we can properly build/link with it.
if test "x$asan" = xyes ; then
   CFLAGS_EX=""
   LDFLAGS_BAK=${LDFLAGS}
   JTR_FLAG_CHECK_LINK([-fsanitize=address], 1)
   if test "x${CFLAGS_EX}" = x ; then
      JTR_FLAG_CHECK_LINK([-faddress-sanitizer], 1)
      if test "x${CFLAGS_EX}" = x ; then
         AC_MSG_FAILURE([Could not find all required ASAN components])
      else
         LDFLAGS="-faddress-sanitizer $LDFLAGS"
      fi
   else
      LDFLAGS="-fsanitize=address $LDFLAGS"
   fi
   LDFLAGS=${LDFLAGS_BAK}
fi

   dnl if user requested  UbSan, make sure we can properly build/link with it.
if test "x$ubsan" = xyes ; then
   CFLAGS_EX=""
   LDFLAGS_BAK=${LDFLAGS}
   JTR_FLAG_CHECK_LINK([-DWITH_UBSAN -DARCH_ALLOWS_UNALIGNED=0 -fsanitize=undefined], 1)
   if test "x${CFLAGS_EX}" = x ; then
      AC_MSG_FAILURE([Could not find all required UBSAN components])
   else
      LDFLAGS="-fsanitize=undefined $LDFLAGS"
   fi
   LDFLAGS=${LDFLAGS_BAK}
fi
if test "x$ubsantrap" = xyes ; then
   CFLAGS_EX=""
   LDFLAGS_BAK=${LDFLAGS}
   JTR_FLAG_CHECK_LINK([-DWITH_UBSAN -DARCH_ALLOWS_UNALIGNED=0 -fsanitize=undefined -fsanitize-undefined-trap-on-error], 1)
   if test "x${CFLAGS_EX}" = x ; then
      AC_MSG_FAILURE([Could not find all required UBSAN components])
   else
      LDFLAGS="-fsanitize=undefined $LDFLAGS"
   fi
   LDFLAGS=${LDFLAGS_BAK}
fi


   dnl now fill out CFLAGS
   CFLAGS_EX=""
   JTR_FLAG_CHECK([-Wall], 1)

   dnl False positives from gcc 8
   if (test "x$asan" != xyes); then
      JTR_NOWARN_CHECK([stringop-truncation], 1)
      JTR_NOWARN_CHECK([format-overflow], 1)
   fi

   dnl False positives from gcc 9
   if (test "x$asan" != xyes); then
      JTR_NOWARN_CHECK([format-truncation], 1)
   fi

   dnl Really silly clang warnings stopping us from doing sanity checks
   JTR_NOWARN_CHECK([tautological-constant-out-of-range-compare], 1)

   AS_IF([test "x$werror" = xyes],
      JTR_FLAG_CHECK([-Werror], 1)
      JTR_NOWARN_CHECK([error=cpp], 1)
      JTR_NOWARN_CHECK([[error=#warnings]], 1)
      JTR_NOWARN_CHECK([error=stringop-truncation], 1)
      JTR_NOWARN_CHECK([error=format-overflow], 1)
   )
   if test "x$asan" = xyes || test "x$ubsan" = xyes || test "x$ubsantrap" ; then
      JTR_FLAG_CHECK([-fno-omit-frame-pointer], 1)
   else
      JTR_FLAG_CHECK([-fomit-frame-pointer], 1)
   fi

   dnl gcc bug workaround, see issue 632
   JTR_FLAG_CHECK([--param allow-store-data-races=0], 1)
   dnl Silly OSX warnings
   JTR_NOWARN_CHECK([deprecated-declarations], 1)
   dnl clang warnings
   JTR_FLAG_CHECK([-Wformat-extra-args], 1)
   JTR_FLAG_CHECK([-Wunused-but-set-variable], 1)
   dnl JTR_NOWARN_CHECK([unneeded-internal-declaration], 1)
   AS_IF([test "x$JTR_FLAG_Q_CHECK_WORKS" = xyes], [JTR_FLAG_CHECK([-Qunused-arguments],1)])
   dnl Justified and Ancient (see issue 1093)
   JTR_FLAG_CHECK([-std=gnu89], 1)
   dnl We like reproducible builds
   JTR_FLAG_CHECK([-Wdate-time], 1)
   JTR_LIST_ADD(CFLAGS_EXTRA, ["$CFLAGS_EX"])
],
   AC_MSG_NOTICE([Unable to validate $CC command line arguments. Using standard values.])
   CFLAGS_EXTRA="-Wall -O2 -fomit-frame-pointer"
)

dnl early check of 64 bit systems.
case "$host_cpu" in
  ia64|mips64|mips64eb|mipseb64|mips64el|mipsel64|mips64*|powerpc64*|sparc64)
    CFLAGS_EX=""
    JTR_FLAG_CHECK_LINK([-m64], 1)
    if test "x${CFLAGS_EX}" != x ; then
      LDFLAGS="-m64 $LDFLAGS"
      CFLAGS="-m64 $CFLAGS"
      ASFLAGS="-m64 $ASFLAGS"
    fi
    ;;
  *)
    AC_MSG_CHECKING([if gcc supports -m64])
    AC_MSG_RESULT([skipped])
    ;;
esac

dnl Cross compile compliant 32/64 bit test code.
AC_MSG_CHECKING([for 32/64 bit])
AC_LINK_IFELSE(
   [AC_LANG_SOURCE(
      [extern void exit(int);
      int main() {
      #if defined(_LP64) || defined(__LP64__) || defined(_LLP64) || defined(__LLP64__) || \
        defined(__x86_64) || defined(__x86_64__) || defined(__amd64) || defined(__amd64__) || \
        defined(_M_AMD64) || defined(_M_X64) || defined(WIN64) || \
        defined(__IA64__) || defined(__ia64) || defined(_M_IA64) || \
        defined(__aarch64__) || defined(__ppc64__)
          exit(0);}
      #else
          BORK!
      #endif
      ]
   )]
  ,[CPU_BITS="-m64"]
   [CPU_BIT_STR="64"]
   [AC_MSG_RESULT([64-bit])]
  ,[CPU_BITS="-m32"]
   [CPU_BIT_STR="32"]
   [AC_MSG_RESULT([32-bit])]
)

if test "x${CPU_BITS}" = x-m64 ; then
  JTR_SET_64_INCLUDES
fi

dnl Checks for programs.
AC_PROG_LN_S
AC_PROG_GREP
dnl AC_PROG_EGREP Do not trust this one
AC_PROG_SED
dnl AC_PROG_CXX
AX_CHECK_GNU_MAKE()
MAKE=$_cv_gnu_make_command
AC_PROG_MAKE_SET
AC_PROG_CPP
AC_PROG_MKDIR_P
AC_CACHE_SAVE
AC_PATH_PROG([SORT], [sort])
AC_PATH_PROG([FIND], [find])
AC_PATH_PROG([PERL], [perl])
if test "x$PERL" = x ; then
  AC_MSG_FAILURE([No perl executable found])
fi
AS_IF([test -z "$AS"], [AS="$CC"])
AS_IF([test -z "$LD"], [LD="$CC"])
AS_IF([test -z "$AR"], [AC_PATH_TOOL([AR], [ar], [ar], [$PATH:/usr/ccs/bin])])
AS_IF([test -z "$STRIP"], [AC_CHECK_TOOL([STRIP], [strip], [strip])])
AS_IF([test -z "$STRINGS"], [AC_CHECK_TOOL([STRINGS], [strings], [strings])])

dnl Check if we have this at all
PKG_PROG_PKG_CONFIG
AC_MSG_CHECKING([if pkg-config will be used])
if test "x$PKG_CONFIG" = x || test "x$enable_pkg_config" = xno ; then
  JTR_MSG_RESULT_FAILIF_FORCED([xno], [x$enable_pkg_config], [pkg-config is NOT available])
  PKG_CONFIG=no
else
  AC_MSG_RESULT([yes])
fi

dnl
dnl Here, we use perl (if it was found!) and if there is a ../run/john.pot
dnl file, to find out if there are any .pot lines that will be TOO long
dnl for this version of JtR.  WE have reduced the max pot line length to
dnl 1k (it was 30000 or 300000 bytes long before).  So we now need to make
dnl sure that all lines are approprate.  We use ../run/potcheck.pl to validate
dnl the .pot file here.  IF there are problems, we simply inform the user to
dnl fix his .pot file (with ../run/potcheck.pl) and do NOT allow configure
dnl to succeeed.
dnl
if ( test -e ../run/john.pot ) ; then
AC_MSG_CHECKING([if potcheck.pl succeeds])
if test "x$PERL" = x ; then
   AC_MSG_RESULT([no Perl (unable to check)])
else
   $PERL ../run/potcheck.pl -validate < ../run/john.pot
   ret=$?
   if ( test $ret -ne 0 ) ; then
      AC_MSG_RESULT([no])
      AC_MSG_ERROR([NOTE, john will not run properly until you fix your ../run/john.pot file using '../run/potcheck.pl -longline_fix'])
   fi
   AC_MSG_RESULT([yes])
fi
fi

dnl Cross-compile compliant size checks
dnl size_t and off_t are post-poned to after feature macros are set

AC_CHECK_SIZEOF([short])
AC_CHECK_SIZEOF([int])
AC_CHECK_SIZEOF([long])
AC_CHECK_SIZEOF([long long])
AC_CHECK_SIZEOF([wchar_t])
AC_CHECK_SIZEOF([int *])
AC_CHECK_SIZEOF([void *])
dnl Not sure how to do sizeof function pointer in configure. I will add this
dnl one to jumbo.h 'by hand'
dnl AC_CHECK_SIZEOF([int *function()]

dnl Handle --disable-simd or --enable-simd=foo
SIMD_FLAGS=""
CFLAGS_EX=""
case "$simd" in
  yes|auto)
    ;;
  no)
    AC_MSG_NOTICE([SIMD logic disabled by request])
    AC_SUBST([JOHN_NO_SIMD], ["-DJOHN_NO_SIMD"])
    [case "$host_cpu" in
      aarch64|arm*|powerpc*)
        SIMD_NAME="(SIMD disabled)"
      ;;
    esac]
    ;;
  neon)
    AS_CASE([$host_cpu],
      [arm*],
        JTR_FLAG_CHECK_LINK([-mfpu=neon], 2)
        SIMD_NAME="NEON",
      [aarch64],
        JTR_FLAG_CHECK_LINK([-march=armv8-a+simd], 2)
        SIMD_NAME="ASIMD",
      AC_ERROR([NEON/ASIMD only applicable for ARM CPU's])
    )
    JTR_ARM_SIMD_LOGIC
    ;;
  asimd)
    JTR_FLAG_CHECK_LINK([-march=armv8-a+simd], 2)
    SIMD_NAME="ASIMD"
    JTR_ARM_SIMD_LOGIC
    ;;
  altivec1)
    JTR_FLAG_CHECK_LINK([-maltivec], 2)
    JTR_FLAG_CHECK_LINK([-msvx], 2)
    SIMD_NAME="Altivec"
    ;;
  altivec*)
    JTR_FLAG_CHECK_LINK([-maltivec], 2)
    JTR_FLAG_CHECK_LINK([-msvx], 2)
    JTR_FLAG_CHECK_LINK([-mpower8vector], 2)
    SIMD_NAME="Altivec2"
    ;;
  dnl Handle known cases of --enable-simd=foo --> -mfoo
  mmx|sse*|ssse3|avx*|xop*)
    SIMD_NAME=`echo $simd | tr a-z A-Z`
    AC_MSG_NOTICE([Trying to force $SIMD_NAME using default method (--enable-simd=$simd).])
    JTR_FLAG_CHECK_LINK([-m${simd}], 2)
    ;;
  *)
    SIMD_NAME=`echo $simd | tr a-z A-Z`
    AC_MSG_ERROR([SIMD type $SIMD_NAME not supported (--enable-simd=$simd)])
esac
JTR_LIST_ADD(SIMD_FLAGS, ["$CFLAGS_EX"])

dnl ======================================================================
dnl Available arch.h's:
dnl alpha.h
dnl arm32le.h (mfpu=neon) (we may override the "le")
dnl arm64le.h (we may override the "le")
dnl ia64.h
dnl mips32.h (we override the BE defined within it)
dnl mips64.h
dnl pa-risc.h
dnl ppc32.h  (with or without -maltivec)
dnl ppc64.h (-m64 with or without -maltivec)
dnl sparc32.h
dnl sparc64.h (-m64 -mcpu=ultrasparc) (-xarch=native64)
dnl vax.h
dnl x86-64.h (-mx32, -m64)
dnl x86-any.h
dnl x86-mmx.h
dnl x86-sse.h

cpu_family="unkown"
case "$host_cpu" in
  alpha*) ARCH_LINK=alpha.h endian=little ;;
  armeb) ARCH_LINK=arm32le.h endian=big ;;
  aarch64) ARCH_LINK=arm64le.h endian=little
    AC_MSG_CHECKING([special compiler flags])
    AC_MSG_RESULT([ARM64])
    AS_IF([test $simd != no],
        [SIMD_NAME="ASIMD"]
        JTR_ARM_SIMD_LOGIC
      )
    ;;
  arm*) ARCH_LINK=arm32le.h endian=little
    AC_MSG_CHECKING([special compiler flags])
    AC_MSG_RESULT([ARM])
    JTR_ARM_SPECIAL_LOGIC
    JTR_ARM_SIMD_LOGIC
    ;;
  ia64) ARCH_LINK=ia64.h endian=little cpu_family=intel ;;
  i?86) ARCH_LINK=x86-any.h endian=little cpu_family=intel ;;
  m68k*) ARCH_LINK=autoconf_arch.h endian=big ;;
  mic) ARCH_LINK=mic.h endian=little
    AC_MSG_CHECKING([special compiler flags])
    AC_MSG_RESULT([MIC])
    JTR_MIC_SPECIAL_LOGIC
    ;;
  mips|mipseb) ARCH_LINK=mips32.h endian=big ;;
  mipsel) ARCH_LINK=mips32.h endian=little ;;
  mips64|mips64eb|mipseb64) ARCH_LINK=mips64.h endian=big ;;
  mips64el|mipsel64) ARCH_LINK=mips64.h endian=little ;;
  mips64*) ARCH_LINK=mips64.h endian=big ;;
  mips*) ARCH_LINK=mips32.h endian=big ;;
  pdp*) ARCH_LINK=autoconf_arch.h endian=little ;;
  powerpc64le) ARCH_LINK=ppc64.h endian=little
    AC_MSG_CHECKING([special compiler flags])
    AC_MSG_RESULT([PPC64le])
    JTR_PPC64_SPECIAL_LOGIC
    ;;
  powerpc64*) ARCH_LINK=ppc64.h endian=big
    AC_MSG_CHECKING([special compiler flags])
    AC_MSG_RESULT([PPC64])
    JTR_PPC64_SPECIAL_LOGIC
    ;;
  powerpcle) ARCH_LINK=ppc32.h endian=little
    AC_MSG_CHECKING([special compiler flags])
    AC_MSG_RESULT([PPC32le])
    JTR_PPC32_SPECIAL_LOGIC
    ;;
  powerpc*) ARCH_LINK=ppc32.h endian=big
    AC_MSG_CHECKING([special compiler flags])
    AC_MSG_RESULT([PPC32])
    JTR_PPC32_SPECIAL_LOGIC
    ;;
  sparc64) ARCH_LINK=sparc64.h endian=big ;;
  sparc*) ARCH_LINK=sparc32.h endian=big ;;
  vax*) ARCH_LINK=vax.h endian=little ;;
  x86_64) ARCH_LINK=x86-64.h endian=little cpu_family=intel ;;
  *)
     AC_MSG_WARN([Uncertain support for ${host}, please report!])
     ARCH_LINK=autoconf_arch.h
     ;;
esac

dnl NOTE, later, we will probably do this by parsing the host or target to figure
dnl out the system, then have a switch statement, based upon the system, calling
dnl the proper JTR_cputype_SPECIAL_LOGIC function (and of course have to write
dnl macros for each environment.  We probably should fall back to calling
dnl make -f Makefile.legacy clean generic or failing with an echo of that message,
dnl for any environment we do not handle.
JTR_ASM_MAGIC
AS_IF([test "x$cpu_family" = xintel],
       AC_MSG_CHECKING([special compiler flags])
       AC_MSG_RESULT([Intel x86])
       [JTR_X86_SPECIAL_LOGIC]
     )
AC_MSG_CHECKING([for arch.h alternative])
AC_MSG_RESULT([${ARCH_LINK}])
JTR_GENERIC_LOGIC

dnl Set a variable detecting x86-64 w/ X32 ABI
if test "x$ax_intel_x32" = xyes; then
   using_x32=", X32 ABI"
else
   using_x32=""
fi

dnl ======================================================================
dnl Check for LE/BE CPU
dnl ======================================================================
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

dnl ======================================================================
dnl Checks for libraries.
dnl
dnl NOTE, be VERY careful of spaces around the comma's in the AC_CHECK_LIB. Best
dnl to not have any.  If there are space, then often that will get a lib to NOT
dnl be added to @LIBS@ and cause linkage problems.  Also note, if action if found
dnl is specified, the -llibname will NOT get appended to LIBS. So it has to be
dnl done by 'hand'.
dnl ======================================================================

AS_IF([test "x$with_openssl" != xno],
   [if test "x$enable_native_tests" != xno -a "x$PKG_CONFIG" != xno; then
   PKG_CHECK_MODULES([OPENSSL], [openssl],
      AC_DEFINE(HAVE_LIBCRYPTO,1,[Define to 1 if you have the `crypto' library (-lcrypto).])
         AC_DEFINE(HAVE_LIBSSL,1,[Define to 1 if you have the `ssl' library (-lssl).]),
         AC_MSG_FAILURE([OpenSSL and/or its development libraries not found. Try using --disable-pkg-config and possibly helping configure find them by providing hints in CPPFLAGS and LDFLAGS (or use --without-openssl option)],1))
else
   AS_IF([test "x${OPENSSL_CFLAGS}${OPENSSL_LIBS}" != "x" -o "x$cross_compiling" = "xyes" -o "x$enable_native_tests" = xno -o "x$PKG_CONFIG" = xno],
      [AC_MSG_CHECKING([supplied paths for OpenSSL])]
      [JTR_LIST_ADD(CFLAGS, [$OPENSSL_CFLAGS])]
      [if test "x$cross_compiling" = "xyes" -a "x$OPENSSL_LIBS" = "x"; then
        OPENSSL_LIBS="${OPENSSL_LIBS} -lssl -lcrypto"
      fi]
      LIBS_ORIG="$LIBS"
      LIBS="$LIBS $OPENSSL_LIBS"
      [AC_MSG_RESULT([$OPENSSL_CFLAGS $OPENSSL_LIBS])]
      [if test "x$cross_compiling" = xno; then
         JTR_SET_NORMAL_SSL_INCLUDES([/usr/local/ssl])
      fi]
      [AC_CHECK_HEADER([openssl/opensslv.h],
      [AC_CHECK_LIB([ssl],[SSL_CTX_new],
      [AC_CHECK_LIB([crypto],[MD5_Update],
         [AC_DEFINE(HAVE_LIBSSL,1,[Define to 1 if you have the `ssl' library (-lssl).])]
         [AC_DEFINE(HAVE_LIBCRYPTO,1,[Define to 1 if you have the `crypto' library (-lcrypto).])]
         [OPENSSL_LIBS="${OPENSSL_LIBS} -lssl -lcrypto"],
         [AC_MSG_FAILURE([libssl/libcrypto not found, install them or use --without-openssl option],1)])],
         [AC_MSG_FAILURE([libssl not found, install it or use --without-openssl option],1)]
      )
    LIBS="$LIBS_ORIG"],
    [AC_MSG_FAILURE([OpenSSL headers not found, install them or use --without-openssl option],1)]
   )]
  )
  fi]
)

AC_MSG_CHECKING([for (non-free) ClamAV unrar code])
if test $with_unrar = yes; then
  for sf in unrar.c unrarcmd.c unrarfilter.c unrarhlp.c unrarppm.c unrarvm.c unrar.h unrarcmd.h unrarfilter.h unrarhlp.h unrarppm.h unrarvm.h; do
    if test ! -s $sf; then
      unrar_files="no (files missing)"
      AC_MSG_RESULT([no])
      break
    fi
  done
  if test -z "$unrar_files"; then
    unrar_files="yes"
    AC_MSG_RESULT([yes])
    AC_DEFINE(HAVE_UNRAR, 1, [Define to 1 if you have the ClamAV unrar files.])
    AC_SUBST([UNRAR_OBJS], "unrarcmd.o unrarfilter.o unrarhlp.o unrar.o unrarppm.o unrarvm.o")
  fi
else
  unrar_files="no (disabled)"
  AC_MSG_RESULT([disabled])
fi

AC_CHECK_LIB([m],[sqrt],[AC_DEFINE(HAVE_LIBM,1,[Define to 1 if you have the `m' library (-lm).])] [AC_SUBST(M_LIBS, [-lm])],[AC_MSG_FAILURE(JtR requires libm being installed,1)])
AC_CHECK_LIB([rt],[clock_gettime],[AC_DEFINE(HAVE_LIBRT,1,[Define to 1 if you have clock_gettime in the `rt' library (-lrt).])] [AC_SUBST(RT_LIBS, [-lrt])])
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
AC_CHECK_HEADERS([openssl/cmac.h], break)

BACKUP_LIBS="$LIBS"

LIBS=""
using_rexgen=no
dnl Check for rexgen only if rexgen wanted
if test "x$enable_rexgen" != xno ; then
  AC_CHECK_HEADER([librexgen/version.h],
    [AC_SEARCH_LIBS([rexgen_version_int],[rexgen librexgen],
      [AC_MSG_CHECKING([librexgen minimum version])] && [AC_TRY_RUN([unsigned int rexgen_version_int();int main() { return ! (rexgen_version_int() >= 0x020105); }],
        AC_MSG_RESULT([usable]) && [using_rexgen=yes],
        AC_MSG_RESULT([TOO old. Rexgen not usable!]))]
    )]
  )
  if test "x$using_rexgen" = "xyes" ; then
    AC_DEFINE(HAVE_LIBREXGEN,1,[Define to 1 if you have the `rexgen' library (-lrexgen).])
  else
    if test "x$enable_rexgen" = "xyes" ; then
      AC_MSG_FAILURE([rexgen not installed, or unusable version])
    fi
  fi
  AC_SUBST(REXGEN_LIBS, [$LIBS])
else
  AC_MSG_NOTICE([rexgen check not enabled])
fi

if test "x$ompfast" = xyes ; then
   AC_DEFINE([FAST_FORMATS_OMP], 1, ["Enable if you want OpenMP for fast formats"])
fi

LIBS="$BACKUP_LIBS"
dnl in makefile, we need to know if building extra pcap items.
if test "x$enable_pcap" != xno ; then
  AC_CHECK_HEADERS([pcap.h pcap/pcap.h],[AC_CHECK_LIB([pcap],[pcap_compile],
        [AC_SUBST(HAVE_PCAP,[-DHAVE_PCAP])] [AC_SUBST(PCAP_LIBS, [-lpcap])])]
        [break])
  AC_CHECK_HEADERS([pcap.h pcap/pcap.h],[AC_CHECK_LIB([wpcap],[pcap_compile],
        [AC_SUBST(HAVE_PCAP,[-DHAVE_PCAP])] [AC_SUBST(PCAP_LIBS, [-lwpcap])])]
        [break])
  if test x"$enable_pcap" = xyes ; then
    if test x"$ac_cv_lib_pcap_pcap_compile" != xyes ; then
      if test x"$ac_cv_lib_wpcap_pcap_compile" != xyes; then
        AC_MSG_FAILURE([PCAP not installed/usable])
      fi
    fi
  fi
else
  AC_MSG_NOTICE([PCAP check disabled])
fi

dnl ======================================================================
dnl Check for variations we can handle
dnl ======================================================================
AC_HEADER_TIME
ACX_HEADER_STRING
dnl Check missing stuff in OpenSSL (too old, or disabled features)
LIBS_ORIG="$LIBS"
CFLAGS_ORIG="$CFLAGS"
LIBS="$OPENSSL_LIBS $LIBS"
CFLAGS="$OPENSSL_CFLAGS $CFLAGS"
AC_CHECK_FUNCS([SHA256 WHIRLPOOL RIPEMD160 AES_encrypt DSA_get0_pqg])
LIBS="$LIBS_ORIG"
CFLAGS="$CFLAGS_ORIG"

AC_CACHE_SAVE

dnl ======================================================================
dnl Check packages:
dnl ======================================================================

dnl Check for openMP (enable/disable handled within the macro).
AC_OPENMP

dnl Check for OpenCL (enable/disable handled within the macro)
AS_IF([test "x$cross_compiling" = xno -a "x$enable_opencl" != xno],
      [JTR_SET_OPENCL_INCLUDES])
AX_OPENCL(C)
if test "x$CL_LIBS" = x; then
   using_cl=no
else
   using_cl=yes
   HAVE_OPENCL=-DHAVE_OPENCL
fi

dnl ZTEX USB-FPGA module support (if --enable-ztex=yes)
AX_ZTEX

dnl Checks for header files.
dnl Eg. if sys/times.h is found, the below will define HAVE_SYS_TIMES_H
AC_CHECK_HEADERS([arpa/inet.h crypt.h dirent.h limits.h locale.h \
                  malloc.h net/ethernet.h netdb.h netinet/in.h \
                  netinet/in_systm.h string.h strings.h \
                  sys/ethernet.h sys/file.h sys/param.h sys/socket.h \
                  sys/time.h sys/times.h sys/types.h termios.h \
                  unistd.h unixlib/local.h windows.h])
dnl ======================================================================
dnl AC_CHECK_HEADERS([OS.h])        dnl (wrapped with __BEOS__)
dnl AC_CHECK_HEADERS([stddef.h])    dnl too many to worry about. If this is an issue later, we will deal with it.
dnl AC_CHECK_HEADERS([stdlib.h ])   dnl too many to worry about. If this is an issue later, we will deal with it. NOTE, it is included sometime earlier on some other check
dnl AC_CHECK_HEADERS([sys/timeb.h]) dnl (wrapped with windows/msc/cygwin wrappers)
dnl AC_CHECK_HEADERS([wchar.h ])    dnl (wrapped with __linux__ & HAVE_LIBDL)
dnl ======================================================================
dnl Quirks for Solaris and OpenBSD
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

dnl Checks for typedefs, structures, and compiler characteristics.
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

if test "x$enable_int128" = xno; then
   have_int128=disabled
elif test "x$ac_cv_type_int128" = xyes ||
   test "x$ac_cv_type___int128" = xyes ||
   test "x$ac_cv_type___int128_t" = xyes; then
   have_int128=yes
else
   if test "x$enable_int128" = xyes; then
      AC_MSG_FAILURE([int128 is not capable on this build])
   fi
   have_int128=no
fi

dnl Checks for library functions.
AC_FUNC_ERROR_AT_LINE

dnl JtR's usage of fork may not work on minwin, even though the AC_FUNC_FORK says it should
case "$host_os" in
  mingw*)
    dnl FORK is known to 'compile' but to fail and not be usable.
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

dnl ======================================================================
dnl these checks HAVE to be there (we have code using them)
dnl   setenv/putenv  fseek/ftell set,   memmem  sleep
dnl   stri*cmp/strcasecmp strlwr/strupr/strrev
dnl ======================================================================
AC_CHECK_FUNCS([fseek64 fseeko fseeko64 _fseeki64 lseek64 lseek ftell64 ftello \
               ftello64 _ftelli64 fopen64 _fopen64 memmem mmap sleep \
               setenv putenv strcasecmp strncasecmp \
               stricmp strcmpi _stricmp _strcmpi strnicmp strncmpi _strnicmp \
               _strncmpi strnlen strlwr strupr strrev \
               atoll _atoi64 snprintf sprintf_s strcasestr])
dnl AC_CHECK_FUNCS([memchr memmove memset munmap pow \
dnl                 select setlocale socket strchr \
dnl                 strdup strerror strstr
dnl  these extras removed for issue 910
dnl                 endpwent isascii mkdir rmdir atexit floor
dnl                 ftruncate gethostbyname gettimeofday inet_ntoa
dnl                 strrchr strcspn strspn strtol strtoul
dnl ])

dnl Mesa claims to support OpenCL 1.2, but does not.
CFLAGS_BACKUP=$CFLAGS
LIBS_BACKUP=$LIBS
CFLAGS="$CFLAGS $CL_CFLAGS"
LIBS="$LIBS $CL_LIBS"
AC_CHECK_FUNC([clGetKernelArgInfo], [AC_DEFINE(HAVE_OPENCL_1_2, 1, [Define to 1 if you (really) have OpenCL 1.2.])])
CFLAGS=$CFLAGS_BACKUP
LIBS=$LIBS_BACKUP

dnl This will stop at first found, will be used for mem_alloc_aligned()
AC_CHECK_FUNCS([posix_memalign aligned_alloc memalign __mingw_aligned_malloc _aligned_malloc], break)

AC_CACHE_SAVE

if test "x$simd" != xno ; then
  CPU_BEST_FLAGS_MAIN=-DJOHN_$(echo ${SIMD_NAME} | tr .a-z _A-Z)
fi

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
elif test "$with_openssl" = "yes" -a "$cpu_family" = intel; then
   using_aesni="depends on OpenSSL"
else
   using_aesni=no
fi
AC_SUBST([YASM], [$ac_cv_path_YASM])
AC_SUBST([AESNI_OS],["$aesni_os"])
AC_SUBST([YASM_OPTIONS],["$aesni_options"])

JTR_SYSTEMS_SPECIFIC_LOGIC

dnl The size of size_t and/or off_t might change when feature macros (chosen in
dnl JTR_SYSTEMS_SPECIFIC_LOGIC) are used.
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

if test "x$ubsan" = xyes ; then
   CFLAGS=`echo $CFLAGS | sed 's/-g //g; s/-O2 //g'`
   CFLAGS=`echo $CFLAGS | sed 's/-g$//g; s/-O2$//g'`
   CFLAGS="-g $O_DEBUG -DWITH_UBSAN -DARCH_ALLOWS_UNALIGNED=0 -fsanitize=undefined $CFLAGS"
   ASFLAGS="-DWITH_UBSAN -DARCH_ALLOWS_UNALIGNED=0 -fsanitize=undefined $ASFLAGS"
   CPPFLAGS="-DWITH_UBSAN -DARCH_ALLOWS_UNALIGNED=0 $CPPFLAGS"
   LDFLAGS="-fsanitize=undefined $LDFLAGS"
fi

if test "x$ubsantrap" = xyes ; then
   if test "x$ubsan" = xyes ; then
     AC_MSG_ERROR([--enable-ubsan and --enable-ubsantrap are mutually exclusive. Pick one or the other (or NONE)])
   fi
   CFLAGS=`echo $CFLAGS | sed 's/-g //g; s/-O2 //g'`
   CFLAGS=`echo $CFLAGS | sed 's/-g$//g; s/-O2$//g'`
   CFLAGS="-g $O_DEBUG -DWITH_UBSAN -DARCH_ALLOWS_UNALIGNED=0 -fsanitize=undefined -fsanitize-undefined-trap-on-error $CFLAGS"
   ASFLAGS="-DWITH_UBSAN -DARCH_ALLOWS_UNALIGNED=0 -fsanitize=undefined -fsanitize-undefined-trap-on-error $ASFLAGS"
   CPPFLAGS="-DWITH_UBSAN -DARCH_ALLOWS_UNALIGNED=0 $CPPFLAGS"
   LDFLAGS="-fsanitize=undefined -fsanitize-undefined-trap-on-error $LDFLAGS"
fi

dnl add ARCH_LITTLE_ENDIAN to command line, IF we know it is big or little
if test "x$endian" = "xbig"; then
   CFLAGS="$CFLAGS -DARCH_LITTLE_ENDIAN=0"
   ASFLAGS="$ASFLAGS -DARCH_LITTLE_ENDIAN=0"
else
   if test "x$endian" = "xlittle"; then
      CFLAGS="$CFLAGS -DARCH_LITTLE_ENDIAN=1"
      ASFLAGS="$ASFLAGS -DARCH_LITTLE_ENDIAN=1"
   fi
fi

dnl build proper 'link' to the arch file (based on bit only, for 32 bit, we may
dnl want different ones, and for other CPU's we need different ones)
dnl note, we remove it first.
AS_IF([rm -f arch.h])
AC_CONFIG_LINKS([arch.h:$ARCH_LINK])

dnl For the fastest MS formats, full Unicode support (4-byte UTF-8) can
dnl mean a 10% performance hit. Default is support for up to 3-byte UTF-8
dnl which corresponds to full UCS-2 or Unicode BMP.
AS_IF([test "x$enable_nt_unicode" != xno], [AC_DEFINE([NT_FULL_UNICODE],1,[Define to 1 if you want support for 4-byte UTF-8 in fast MS formats.])])

dnl Use features that may not yet be stable
AS_IF([test "x$experimental" != xno], [AC_DEFINE([USE_EXPERIMENTAL],1,[Define to 1 if you want to include experimental code.])])

dnl In makefile, we need to know if building extra fuzz items.
if test "x$fuzz" != xno ; then
   AC_SUBST(HAVE_FUZZ,[-DHAVE_FUZZ])
else
   AC_MSG_NOTICE([Fuzz check disabled])
fi

dnl In makefile, we need to know if building with libFuzzer.
if test "x$libfuzzer" != xno ; then
   AC_SUBST(HAVE_LIBFUZZER,[-DHAVE_LIBFUZZER])
else
   AC_MSG_NOTICE([Fuzzing (using libFuzzer) check disabled])
fi

dnl code to create M4_INCLUDES (all ./m4/*.m4 )
AC_SUBST([M4_INCLUDES],[`echo m4/*.m4`])

dnl Handle --prefix -> JOHN_SYSTEMWIDE
dnl A prefix of /usr/local will mean execs in /usr/local/bin and the rest
dnl in /usr/local/share/john
AS_IF([test $prefix != "../run" && test $prefix != "NONE" ],
   [CFLAGS="$CFLAGS -DJOHN_SYSTEMWIDE -DJOHN_SYSTEMWIDE_EXEC='\"$prefix/bin\"' -DJOHN_SYSTEMWIDE_HOME='\"$prefix/share/john\"'"],
   [AS_IF([test $with_systemwide != no], [CFLAGS="$CFLAGS -DJOHN_SYSTEMWIDE"
   prefix=/usr/libexec/john])]
)

if test x$with_flock != xno; then
   CFLAGS="$CFLAGS -DPREFER_FLOCK"
fi

dnl if test ${SIMD_NAME} = "AVX2" || test ${host_cpu} = "k1om"; then
dnl   if test x$experimental = xno; then
dnl      AC_DEFINE([DYNAMIC_DISABLED], 1, [Disables Dynamic format completely])
dnl   fi
dnl fi

dnl ======================================================================
dnl Code  to create @PLUGFORMATS_OBJS@ and
dnl john_buildrule.h moved from Makefile.in to here.
dnl don't build opencl_*plug.c unless an opencl build
dnl ======================================================================
if test x$using_cl = xyes ; then
  AC_MSG_NOTICE([creating *_plug.c and OpenCL object rules])
else
  AC_MSG_NOTICE([creating *_plug.c rules])
fi
if test "`echo *_plug.c`" != "*_plug.c"; then
   AC_SUBST([PLUGFORMATS_OBJS],[`echo *_plug.c | sed 's/opencl[[A-Za-z0-9_\-]]*\.c //g;s/\.c/.o/g'`])
   AC_SUBST([OPENCL_PLUGFORMATS_OBJS],[`echo opencl*_plug.c | sed 's/\.c/.o/g'`])
   if test "x$plug_deps" = xyes -a "x$PERL" != x ; then
      AC_MSG_NOTICE([creating Makefile dependencies])
      AC_SUBST([PLUGFORMATS_DEPS],[`$PERL ./plugin_deps.pl *_plug.c`])
   fi
fi

AC_MSG_NOTICE([creating ./john_build_rule.h])
echo "#define JOHN_BLD \"${host_os} ${CPU_BIT_STR}-bit${using_x32} ${host_cpu} ${SIMD_NAME} AC\"" > john_build_rule.h

AC_SUBST([HOST_OS],["$host_os"])
AC_CONFIG_FILES([Makefile
                 aes/Makefile
                 aes/aesni/Makefile
                 aes/openssl/Makefile
                 secp256k1/Makefile
                 ed25519-donna/Makefile
		 poly1305-donna/Makefile])

dnl Escaping the '#' in things like "-Wno-error=#warnings" is required in
dnl Makefile but forbidden when *not* in Makefile so we need to back-up
dnl CFLAGS_EXTRA before writing Makefile, and revert after (duh!)
CFLAGS_EXTRA_BACKUP=$CFLAGS_EXTRA
CFLAGS_EXTRA=$(echo $CFLAGS_EXTRA | sed 's/#/\\#/g')

dnl This actually writes Makefile et al.
AC_OUTPUT(,echo "timestamp from configure.in" > autoconfig-stamp-h)

CFLAGS_EXTRA=$CFLAGS_EXTRA_BACKUP

dnl ======================================================================
dnl Create fmt_externs.h and fmt_registers.h
dnl This needs arch.h to be linked so can't happen before
dnl AC_OUTPUT
dnl ======================================================================
AC_MSG_NOTICE([creating ./fmt_externs.h])
rm -f fmt_externs.h

CFLAGS_EX2=
if test "x$simd" = xno ; then
   CFLAGS_EX2=-DJOHN_NO_SIMD
fi

if test "`echo *_fmt_plug.c`" != "*_fmt_plug.c"; then
   $CPP -P -DAC_BUILT $CFLAGS_EX2 $CPPFLAGS $CPU_BEST_FLAGS $CFLAGS $HAVE_OPENCL $CFLAGS_EXTRA $OPENMP_CFLAGS $OPENSSL_CFLAGS -DFMT_EXTERNS_H *_fmt_plug.c | LC_ALL=C $GREP "extern struct fmt_main" | LC_ALL=C $SORT -f > fmt_externs.h
fi
dnl if the file was not created, then bail.
if test -f fmt_externs.h -a ! -s fmt_externs.h; then
  cp Makefile.stub Makefile
  AC_MSG_ERROR([The build of fmt_externs.h failed. Can not continue!])
fi
dnl if file does not exist, then create a blank one (i.e. no *_plug.c files)
if test ! -f fmt_externs.h; then
  echo >fmt_externs.h
fi
AC_MSG_NOTICE([creating ./fmt_registers.h])
rm -f fmt_registers.h
if test "`echo *_fmt_plug.c`" != "*_fmt_plug.c"; then
   $CPP -P -DAC_BUILT $CFLAGS_EX2 $CPPFLAGS $CPU_BEST_FLAGS $CFLAGS $CFLAGS_EXTRA $OPENMP_CFLAGS $OPENSSL_CFLAGS -DFMT_REGISTERS_H *_fmt_plug.c | LC_ALL=C $GREP "john_register_one" | LC_ALL=C $SORT -f > fmt_registers.h
fi
dnl if the file was not created, then bail.
if test -f fmt_registers.h -a ! -s fmt_registers.h; then
  cp Makefile.stub Makefile
  AC_MSG_ERROR([The build of fmt_registers.h failed. Can not continue!])
fi
dnl if file does not exist, then create a blank one (i.e. no *_plug.c files)
if test ! -f fmt_registers.h; then
  echo >fmt_registers.h
fi

if test "`echo opencl_*_fmt_plug.c`" != "opencl_*_fmt_plug.c"; then
   $CPP -P -DAC_BUILT $CFLAGS_EX2 $CPPFLAGS $CPU_BEST_FLAGS $CFLAGS $HAVE_OPENCL $CFLAGS_EXTRA $OPENMP_CFLAGS $OPENSSL_CFLAGS -DFMT_REGISTERS_H opencl_*_fmt_plug.c | LC_ALL=C $GREP "john_register_one" | LC_ALL=C $SORT -f >> fmt_registers.h
fi

dnl ======================================================================
dnl            ONLY _COSMETICAL_ OUTPUT STUFF BELOW THIS LINE
dnl ======================================================================

dnl Hard to get proper info from AC_OPENMP. If it's enabled with no special
dnl options needed, we might end up listing it as disabled
if test "x$ac_cv_prog_c_openmp" != x -a  "x$enable_openmp" != xno -a dnl
        "x$ac_cv_prog_c_openmp" != xunsupported ; then
   if test "x$ompfast" = "xyes"; then
      using_omp=yes
   else
      using_omp="yes (not for fast formats)"
   fi
else
   if test "x$ompfast" = "xyes"; then
     AC_MSG_FAILURE([OMP for fast formats requested, but no OMP on this system])
   fi
   using_omp=no
fi

if test "x$ac_cv_search_crypt" != xno; then
   using_crypt=yes
else
   using_crypt=no
fi

if test "x$ac_cv_lib_z_deflate" = xyes; then
   using_zlib=yes
else
   using_zlib=no
fi

if test "x$ac_cv_lib_bz2_main" = xyes; then
   using_bz2=yes
else
   using_bz2=no
fi

if test "x$ac_cv_func_mmap" != xno; then
   using_mmap=yes
else
   using_mmap=no
fi

if test -n "$SIMD_NAME"; then
   CPU_NAME="$host_cpu $SIMD_NAME"
else
   CPU_NAME=$host_cpu
fi

dnl Ensure reports of tests does not show up blank:
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
   AC_MSG_WARN([No recognized optimization option present in CFLAGS "$CFLAGS"])
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

if test "x$asan" = xyes ; then
   asan="enabled"
else
   asan="disabled"
fi

if test "x$ubsan" = xyes ; then
   ubsan="enabled"
else
   ubsan="disabled"
fi

if test "x$ubsantrap" = xyes ; then
   ubsan="enabled (trap)"
fi

cat <<EOF
dnl ======================================================================

Configured for building John the Ripper ${PACKAGE_VERSION}:

Target CPU ......................................... ${CPU_NAME}, ${CPU_BIT_STR}-bit ${using_endian}${using_x32}
AES-NI support ..................................... ${using_aesni}
Target OS .......................................... ${host_os}
Cross compiling .................................... ${cross_compiling}
Legacy arch header ................................. ${ARCH_LINK}

Optional libraries/features found:
Memory map (share/page large files) ................ ${using_mmap}
Fork support ....................................... ${ac_cv_func_fork_works}
OpenMP support ..................................... ${using_omp}
OpenCL support ..................................... ${using_cl}
Generic crypt(3) format ............................ ${using_crypt}
OpenSSL (many additional formats) .................. ${with_openssl}
libgmp (PRINCE mode and faster SRP formats) ........ ${ac_cv_lib_gmp___gmpz_init}
128-bit integer (faster PRINCE mode) ............... ${have_int128}
libz (7z, pkzip and some other formats) ............ ${using_zlib}
libbz2 (7z and gpg2john bz2 support) ............... ${using_bz2}
libpcap (vncpcap2john and SIPdump) ................. ${using_pcap}
Non-free unrar code (complete RAR support) ......... ${unrar_files}
librexgen (regex mode, see doc/README.librexgen) ... ${using_rexgen}
OpenMPI support (default disabled) ................. ${using_mpi}
Experimental code (default disabled) ............... ${experimental}
ZTEX USB-FPGA module 1.15y support ................. ${ztex}

EOF
dnl === this section is NOT output, unless there is some debugging flag enabled.
if test "$ubsan" != "disabled" || test "$asan" != "disabled" ||
   test "$fuzz" != "no" ; then
cat <<EOF
Development options (these may hurt performance when enabled):
AddressSanitizer ("ASan") .......................... ${asan}
UndefinedBehaviorSanitizer ("UbSan") ............... ${ubsan}
Fuzzing test ....................................... ${fuzz}

EOF
fi

echo "Install missing libraries to get any needed features that were omitted."
echo ""
echo "Configure finished.  Now \"${use_make} -s clean && ${use_make} -sj4\" to compile."
dnl ======================================================================
