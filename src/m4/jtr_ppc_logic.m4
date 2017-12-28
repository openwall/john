dnl Redistribution and use in source or binary forms, with or without
dnl modification, are permitted.
dnl
dnl Special compiler flags for Power.
dnl
dnl from Makefile.legacy, checks we want to test against
dnl "-finline-functions -finline-limit=4000 -fno-strict-aliasing -maltivec"
dnl Also added -mvsx and -mpower8-vector
dnl
AC_DEFUN([JTR_PPC64_SPECIAL_LOGIC], [
  echo "checking special compiler flags... PowerPC64"
  CPU_BEST_FLAGS=""
  INLINE_FLAGS=""
  ac_saved_cflags_ex="$CFLAGS_EX"
  CFLAGS_EX=""
  JTR_FLAG_CHECK([-finline-functions], 1)
  if test "x$CFLAGS_EX" != x ; then INLINE_FLAGS="$INLINE_FLAGS -finline-functions" ; fi
  CFLAGS_EX=""
  JTR_FLAG_CHECK([-finline-limit=4000], 1)
  if test "x$CFLAGS_EX" != x ; then INLINE_FLAGS="$INLINE_FLAGS -finline-limit=4000" ; fi
  CFLAGS_EX=""
  JTR_FLAG_CHECK([-fno-strict-aliasing], 1)
  if test "x$CFLAGS_EX" != x ; then INLINE_FLAGS="$INLINE_FLAGS -fno-strict-aliasing" ; fi

  $CC -P $EXTRA_AS_FLAGS $CPPFLAGS $CPU_BEST_FLAGS $CFLAGS $CFLAGS_EXTRA ppc_cpuid.c -o test_cpuid

  [if test "x$simd" = "xyes" -a "`./test_cpuid PPC_FEATURE_HAS_ALTIVEC`" = "1" -a "`./test_cpuid PPC_FEATURE_HAS_VSX`" = "1" -a  "`./test_cpuid PPC_FEATURE2_ARCH_2_07`" = "1"] ; then
    CFLAGS_EX=""
    JTR_FLAG_CHECK([-maltivec], 1)
    if test "x$CFLAGS_EX" != x ; then CPU_BEST_FLAGS="$CPU_BEST_FLAGS -maltivec" INLINE_FLAGS="$INLINE_FLAGS -maltivec" SIMD_NAME="Altivec" ; fi
    CFLAGS_EX=""
    JTR_FLAG_CHECK([-mvsx], 1)
    if test "x$CFLAGS_EX" != x ; then CPU_BEST_FLAGS="$CPU_BEST_FLAGS -mvsx" ; fi
    CFLAGS_EX=""
    JTR_FLAG_CHECK([-mpower8-vector], 1)
    if test "x$CFLAGS_EX" != x ; then CPU_BEST_FLAGS="$CPU_BEST_FLAGS -mpower8-vector" ; fi
  fi

  rm test_cpuid

  CFLAGS_EX="$ac_saved_cflags_ex"

  AC_SUBST([OPT_INLINE_FLAGS],["${INLINE_FLAGS}"])
])
dnl
dnl from Makefile.legacy, checks we want to test against
dnl -finline-functions -finline-limit=4000 -fno-strict-aliasing -maltivec
dnl Also added -mvsx and -mpower8-vector
dnl
AC_DEFUN([JTR_PPC32_SPECIAL_LOGIC], [
  echo "checking special compiler flags... PowerPC32"
  CPU_BEST_FLAGS=""
  INLINE_FLAGS=""
  ac_saved_cflags_ex="$CFLAGS_EX"
  CFLAGS_EX=""
  JTR_FLAG_CHECK([-finline-functions], 1)
  if test "x$CFLAGS_EX" != x ; then INLINE_FLAGS="$INLINE_FLAGS -finline-functions" ; fi
  CFLAGS_EX=""
  JTR_FLAG_CHECK([-finline-limit=4000], 1)
  if test "x$CFLAGS_EX" != x ; then INLINE_FLAGS="$INLINE_FLAGS -finline-limit=4000" ; fi
  CFLAGS_EX=""
  JTR_FLAG_CHECK([-fno-strict-aliasing], 1)
  if test "x$CFLAGS_EX" != x ; then INLINE_FLAGS="$INLINE_FLAGS -fno-strict-aliasing" ; fi

  $CC -P $EXTRA_AS_FLAGS $CPPFLAGS $CPU_BEST_FLAGS $CFLAGS $CFLAGS_EXTRA ppc_cpuid.c -o test_cpuid

  [if test "x$simd" = "xyes" && test "`./test_cpuid PPC_FEATURE_HAS_ALTIVEC`" = "1" -a "`./test_cpuid PPC_FEATURE_HAS_VSX`" = "1" -a "`./test_cpuid PPC_FEATURE2_ARCH_2_07`" = "1"] ; then
    CFLAGS_EX=""
    JTR_FLAG_CHECK([-maltivec], 1)
    if test "x$CFLAGS_EX" != x ; then CPU_BEST_FLAGS="$CPU_BEST_FLAGS -maltivec" INLINE_FLAGS="$INLINE_FLAGS -maltivec" SIMD_NAME="Altivec" ; fi
    CFLAGS_EX=""
    JTR_FLAG_CHECK([-mvsx], 1)
    if test "x$CFLAGS_EX" != x ; then CPU_BEST_FLAGS="$CPU_BEST_FLAGS -mvsx" ; fi
    CFLAGS_EX=""
    JTR_FLAG_CHECK([-mpower8-vector], 1)
    if test "x$CFLAGS_EX" != x ; then CPU_BEST_FLAGS="$CPU_BEST_FLAGS -mpower8-vector" ; fi
  fi

  rm test_cpuid

  AC_SUBST([OPT_INLINE_FLAGS],["${INLINE_FLAGS}"])
])
