dnl Redistribution and use in source or binary forms, with or without
dnl modification, are permitted.
dnl
dnl Special compiler flags for Power.

AC_DEFUN([JTR_PPC64_SPECIAL_LOGIC], [
  echo "checking special compiler flags... PowerPC64"
  CPU_BEST_FLAGS=""
  INLINE_FLAGS=""	# taken from Makefile.legacy:  OPT_INLINE="-finline-functions -finline-limit=4000 -fno-strict-aliasing -maltivec"
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

  CFLAGS_EX=""
  JTR_FLAG_CHECK([-maltivec], 1)
  if test "x$CFLAGS_EX" != x ; then CPU_BEST_FLAGS="$CPU_BEST_FLAGS -maltivec" INLINE_FLAGS="$INLINE_FLAGS -maltivec" CPU_STR="ALTIVEC" ; fi
  CFLAGS_EX=""
  JTR_FLAG_CHECK([-mvsx], 1)
  if test "x$CFLAGS_EX" != x ; then CPU_BEST_FLAGS="$CPU_BEST_FLAGS -mvsx" ; fi
  CFLAGS_EX=""
  JTR_FLAG_CHECK([-mpower8-vector], 1)
  if test "x$CFLAGS_EX" != x ; then CPU_BEST_FLAGS="$CPU_BEST_FLAGS -mpower8-vector" ; fi
  CFLAGS_EX="$ac_saved_cflags_ex"

  AC_SUBST([OPT_INLINE_FLAGS],["${INLINE_FLAGS}"])
])
