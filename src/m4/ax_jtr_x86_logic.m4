# Copyright (C) 2014 Jim Fougeron, for John Ripper project.
# This file put into public domain. unlimited permission to
# copy and/or distribute it, with or without modifications,
# as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY, to the extent permitted by law; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.
#
# this code will probe test many flavors of intel CPU's looking
# for different CPU instruction abilities. It does not use the
# CPUID instructions, instead actually issuing instructions that
# are known to be only processable by specific CPU types, and
# simply doing the instruction, and returning 0.  If the cpu
# instruction can NOT be done, then the test will CORE, and
# we know that those CPU instructions are NOT handled.  Once
# we hit a bad test, we are done, since the CPU will not have
# instructions above that level.  The exception is XOP vs AVX.
# there may not always be a 100% follow through on those types,
# since one of them was built by Intel, the other by AMD. When
# we detect SSE4, we simply perform the final tests, without
# worrying about failed results.  But if we had failed at SSE4
# then we would know the CPU has SSE3 (or SSSE3), and nothing
# further. If there is no SSE4, then there will never be a need
# to test for AVX or XOP.  This CPU simply does not have them.
#
#############################################################################
# CPU test code.  We start with SSE2, then SSSE3, then SSE4, ... until we fail
# whatever the last one is, we use it.  NOTE, if AVX fails we still DO test XOP
# since one is intel, one is AMD.  At the very end of configure, we set gcc
# back to whatever the 'best' was.  During running in configure, $CC gets reset
# so the results of our tests must be remembered, and reset just before exit.
#############################################################################
#
#
#############################################################################
# ASM_MAGIC code.  Here we add certain 'magic' values. Things like
#  -DUNDERSCORES -DBSD -DALIGN_LOG   (for macosx-x86-*)
#  -DUNDERSCORES -DALIGN_LOG for (dos-djgpp-x86-*)
#  -DUNDERSCORES for cygwin / MinGW / VC
#############################################################################
#

AC_DEFUN([AX_JTR_X86_SPECIAL_LOGIC], [
CC_BACKUP=$CC
CFLAGS_BACKUP=$CFLAGS
CFLAGS="$CFLAGS -O0"
CPU_STR="Unk"
CPU_NOTFOUND=0
CC="$CC_BACKUP -msse2"
AC_MSG_CHECKING([for SSE2])
AC_RUN_IFELSE(
  [
  AC_LANG_SOURCE(
	[[#include <emmintrin.h>
      #include <stdio.h>
      extern void exit(int);
      int main(){__m128i t;*((long long*)&t)=1;t=_mm_slli_si128(t,7);if((*(unsigned*)&t)==88)printf(".");exit(0);}]]
  )]
  ,[CPU_BEST_FLAGS="-msse2"] dnl
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
      extern void exit(int);
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
      extern void exit(int);
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
      extern void exit(int);
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
      extern void exit(int);
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
CFLAGS="$CFLAGS_BACKUP"

# Achtung, M4 porn, NSFW!
# If we're not cross compiling, check for -march=native and add it too
if test x${cross_compiling} = xno; then
   AC_MSG_CHECKING([whether compiler understands -march=native])
   CC="$CC_BACKUP -march=native"
   AC_RUN_IFELSE(
     [AC_LANG_SOURCE([int main() { return 0; }])],
     [AC_MSG_RESULT(yes)]
     [CPU_BEST_FLAGS="-march=native $CPU_BEST_FLAGS"],
     [AC_MSG_RESULT(no)]
     # or -xarch=native64
     [AC_MSG_CHECKING([whether compiler understands -xarch=native64])
      CC="$CC_BACKUP -xarch=native64"
      AC_RUN_IFELSE(
        [AC_LANG_SOURCE([int main() { return 0; }])],
        [AC_MSG_RESULT(yes)]
        [CPU_BEST_FLAGS="-xarch=native64 $CPU_BEST_FLAGS"],
        [AC_MSG_RESULT(no)]
        # or -xarch=native
        [AC_MSG_CHECKING([whether compiler understands -xarch=native])
         CC="$CC_BACKUP -xarch=native"
         AC_RUN_IFELSE(
           [AC_LANG_SOURCE([int main() { return 0; }])],
           [AC_MSG_RESULT(yes)]
           [CPU_BEST_FLAGS="-xarch=native $CPU_BEST_FLAGS"],
           [AC_MSG_RESULT(no)]
           # or "-arch host"
           [AC_MSG_CHECKING([whether compiler understands -arch host])
            CC="$CC_BACKUP -arch host"
            AC_RUN_IFELSE(
              [AC_LANG_SOURCE([int main() { return 0; }])],
              [AC_MSG_RESULT(yes)]
              [CPU_BEST_FLAGS="-arch host $CPU_BEST_FLAGS"],
              [AC_MSG_RESULT(no)]
            )
           ]
         )
        ]
      )
     ]
   )
   CC="$CC_BACKUP"
fi

AC_MSG_CHECKING([for 32/64 bit])
# with_icc_asm
AS_IF([test x"$with_icc_asm" != "xno"],
[AC_RUN_IFELSE(
  [
  AC_LANG_SOURCE(
	[[extern void exit(int);
	int main() {
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
	[[extern void exit(int);
	int main() {
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

EXTRA_AS_FLAGS=
AC_MSG_CHECKING([for extra ASFLAGS])
CC="$CC_BACKUP"

AS_IF([echo "int long_ident;" > conftest.c && ${CC} -c conftest.c && strings - conftest.${OBJEXT} | ${GREP} _long_ident > conftest.out],
      [EXTRA_AS_FLAGS+=" -DUNDERSCORES"])

AC_RUN_IFELSE(
  [
  AC_LANG_SOURCE(
	[[extern void exit(int);
	int main() {
	#if defined(__APPLE__) && defined(__MACH__)
	exit(0);
	#endif
	exit(1);}]]
  )]
  ,[EXTRA_AS_FLAGS+=" -DBSD -DALIGN_LOG"])
AC_MSG_RESULT([$EXTRA_AS_FLAGS])
dnl
CC="$CC_BACKUP"])
