dnl JtR configure Arm-NEON instruction active probe test
dnl Copyright (C) 2014 Jim Fougeron, for John Ripper project.
dnl This file put into public domain. unlimited permission to
dnl copy and/or distribute it, with or without modifications,
dnl as long as this notice is preserved.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY, to the extent permitted by law; without
dnl even the implied warranty of MERCHANTABILITY or FITNESS FOR A
dnl PARTICULAR PURPOSE.
dnl
dnl this code will probe test an ARM system, to see if it can handle
dnl NEON code.
dnl
AC_DEFUN([JTR_ARM_SPECIAL_LOGIC], [
CC_BACKUP=$CC
CFLAGS_BACKUP=$CFLAGS
dnl
dnl ======================================================================
dnl Arm-NEON Active CPU probe test.  We check for NEON instructions.
dnl At the very end of configure, we set gcc back to whatever the 'best' was.
dnl During running in configure, $CC gets reset so the results of our tests
dnl must be remembered, and reset just before exit.
dnl ======================================================================

if test "x$simd" = xyes ; then

CFLAGS="$CFLAGS -O0"
if test "x$enable_native_tests" = xyes; then
  AC_MSG_NOTICE([Testing build host's native CPU features])
  CC="$CC_BACKUP -mfpu=neon"
  AC_MSG_CHECKING([for NEON])
  AC_RUN_IFELSE(
    [
    AC_LANG_SOURCE(
    [[#include <arm_neon.h>
  #include <stdio.h>
  extern void exit(int);
  int main(){uint32x4_t t;*((long*)&t)=1;t=veorq_u32(t,t);if((*(unsigned*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mfpu=neon"]
     [SIMD_NAME="NEON"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT(no)]
  )
  CC="$CC_BACKUP -march=armv8-a+simd"
  AC_MSG_CHECKING([for ASIMD])
  AC_RUN_IFELSE(
    [
    AC_LANG_SOURCE(
    [[#include <arm_neon.h>
  #include <stdio.h>
  extern void exit(int);
  int main(){uint32x4_t t;*((long*)&t)=1;t=veorq_u32(t,t);if((*(unsigned*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-march=armv8-a+simd"]
     [SIMD_NAME="ASIMD"]
     [AC_MSG_RESULT([yes])]
     [ARCH_LINK=arm64le.h]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT(no)]
  )
else
dnl ======================================================================
dnl               cross-compile versions of the same tests
dnl ======================================================================
  AC_MSG_CHECKING([for NEON])
  CC="$CC_BACKUP -mfpu=neon"
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
    [[#include <arm_neon.h>
  #include <stdio.h>
  extern void exit(int);
  int main(){uint32x4_t t;*((long*)&t)=1;t=veorq_u32(t,t);if((*(unsigned*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mfpu=neon"]
     [SIMD_NAME="NEON"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT(no)]
  )
  AC_MSG_CHECKING([for ASIMD])
  CC="$CC_BACKUP -march=armv8-a+simd"
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
    [[#include <arm_neon.h>
  #include <stdio.h>
  extern void exit(int);
  int main(){uint32x4_t t;*((long*)&t)=1;t=veorq_u32(t,t);if((*(unsigned*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-march=armv8-a+simd"]
     [SIMD_NAME="ASIMD"]
     [ARCH_LINK=arm64le.h]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT(no)]
  )
fi
fi

CC="$CC_BACKUP"
CFLAGS="$CFLAGS_BACKUP"
])


AC_DEFUN([JTR_ARM_SIMD_LOGIC], [
  if test "$SIMD_NAME" = "NEON" || test "$SIMD_NAME" = "ASIMD" ; then
    ac_saved_cflags_ex="$CFLAGS_EX"
    CFLAGS_EX=""
    JTR_FLAG_CHECK([-fno-strict-aliasing], 1)
    if test "x$CFLAGS_EX" != x ; then
      INLINE_FLAGS="$INLINE_FLAGS -fno-strict-aliasing"
    fi
    CFLAGS_EX="$ac_saved_cflags_ex"
    AC_SUBST([OPT_INLINE_FLAGS],["${INLINE_FLAGS}"])
  fi
])
