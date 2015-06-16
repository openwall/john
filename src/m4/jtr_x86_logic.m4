# JtR configure Intel-SIMD instruction active probe test
# Copyright (C) 2014 Jim Fougeron, for John Ripper project.
# This file put into public domain. unlimited permission to
# copy and/or distribute it, with or without modifications,
# as long as this notice is preserved.
dnl
dnl This program is distributed in the hope that it will be useful,
dnl but WITHOUT ANY WARRANTY, to the extent permitted by law; without
dnl even the implied warranty of MERCHANTABILITY or FITNESS FOR A
dnl PARTICULAR PURPOSE.
dnl
dnl this code will probe test many flavors of intel CPU's looking
dnl for different CPU instruction abilities. It does not use the
dnl CPUID instructions, instead actually issuing instructions that
dnl are known to be only processable by specific CPU types, and
dnl simply doing the instruction, and returning 0.  If the cpu
dnl instruction can NOT be done, then the test will CORE, and
dnl we know that those CPU instructions are NOT handled.  Once
dnl we hit a bad test, we are done, since the CPU will not have
dnl instructions above that level.  The exception is XOP vs AVX.
dnl there may not always be a 100% follow through on those types,
dnl since one of them was built by Intel, the other by AMD. When
dnl we detect SSE4, we simply perform the final tests, without
dnl worrying about failed results.  But if we had failed at SSE4
dnl then we would know the CPU has SSE3 (or SSSE3), and nothing
dnl further. If there is no SSE4, then there will never be a need
dnl to test for AVX or XOP.  This CPU simply does not have them.
dnl
dnl
dnl TODO: We should move the SIMD_COEF_32 and *_PARA shite into this file and
dnl ifdef it out from the arch.h
dnl
dnl TODO: Ultimately we should not depend on any predefined stuff in arch.h
dnl at all
dnl
AC_DEFUN([JTR_X86_SPECIAL_LOGIC], [
CC_BACKUP=$CC
CFLAGS_BACKUP=$CFLAGS
dnl
#############################################################################
# Intel Active CPU probe test.  Start with SSE2, then SSSE3, then SSE4, until failure
# whatever the last one is, we use it.  NOTE, if AVX fails we still DO test XOP
# since one is intel, one is AMD.  At the very end of configure, we set gcc
# back to whatever the 'best' was.  During running in configure, $CC gets reset
# so the results of our tests must be remembered, and reset just before exit.
# Config probe test code copyright 2014, Jim Fougeron.  Placed into public domain.
#############################################################################
dnl
CFLAGS="$CFLAGS -O0"

  AS_CASE([$host_os], [darwin*],
    [CC="$CC_BACKUP -mavx"
    AC_MSG_CHECKING([whether OS X 'as' needs -q option])
    AC_LINK_IFELSE(
      [
      AC_LANG_SOURCE(
        [[#include <immintrin.h>
          #include <stdio.h>
          extern void exit(int);
          int main(){__m256d t;*((long long*)&t)=1;t=_mm256_movedup_pd(t);if((*(long long*)&t)==88)printf(".");exit(0);}]]
      )]
      ,[AC_MSG_RESULT([no])]
      ,[OSX_AS_CLANG="-Wa,-q"]
       [CC="$CC_BACKUP -mavx $OSX_AS_CLANG"][
       AC_LINK_IFELSE(
         [
         AC_LANG_SOURCE(
           [[#include <immintrin.h>
             #include <stdio.h>
             extern void exit(int);
             int main(){__m256d t;*((long long*)&t)=1;t=_mm256_movedup_pd(t);if((*(long long*)&t)==88)printf(".");exit(0);}]]
         )]
         ,[AC_MSG_RESULT([yes])]
         ,[AC_MSG_RESULT([no])]
      )]
    )
    AS_IF([test x$OSX_AS_CLANG != x],
      [CC_BACKUP="$CC_BACKUP $OSX_AS_CLANG"]
      [AS="$AS $OSX_AS_CLANG"]
    )
    [CC="$CC_BACKUP"]]
  )

if test "x$enable_native_tests" != xno; then
  CPU_NOTFOUND=0
  AC_MSG_NOTICE([Testing build host's native CPU features])
  CC="$CC_BACKUP -mmmx"
  AC_MSG_CHECKING([for MMX])
  AC_RUN_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <mmintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m64 t;*((long long*)&t)=1;t=_mm_set1_pi32(7);if((*(unsigned*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mmmx"] dnl
     [CPU_STR="MMX"]
     [AS_IF([test y$ARCH_LINK = yx86-any.h], [ARCH_LINK=x86-mmx.h])]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT(no)]
  )
  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
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
     [AS_IF([test y$ARCH_LINK = yx86-mmx.h], [ARCH_LINK=x86-sse.h])]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT(no)]
  )
  ])
  AS_IF([test "x$CPU_NOTFOUND" = x0],
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
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
    )
  ]
  )
  AS_IF([test "x$CPU_NOTFOUND" = x0],
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
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
    )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
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
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
    )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CC="$CC_BACKUP -mxop"
  AC_MSG_CHECKING([for XOP])
  AC_RUN_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <x86intrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m128i t;*((long long*)&t)=1;t=_mm_roti_epi32(t,5);if((*(long long*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mxop"]dnl
     [CPU_STR="XOP"]
     [AC_MSG_RESULT([yes])]
    ,[AC_MSG_RESULT([no])]
    )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CC="$CC_BACKUP -mavx2"
  AC_MSG_CHECKING([for AVX2])
  AC_RUN_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <immintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m256i t, t1;*((long long*)&t)=1;t1=t;t=_mm256_mul_epi32(t1,t);if((*(long long*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mavx2"]dnl
     [CPU_STR="AVX2"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
    )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CC="$CC_BACKUP -mavx512f"
  AC_MSG_CHECKING([for AVX512F])
  AC_RUN_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <immintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m512i t, t1;*((long long*)&t)=1;t1=t;t=_mm512_mul_epi32(t1,t);if((*(long long*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mavx512f"]dnl
     [CPU_STR="AVX512F"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
    )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CC="$CC_BACKUP -mavx512bw"
  AC_MSG_CHECKING([for AVX512BW])
  AC_RUN_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <immintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m512i t, t1;*((long long*)&t)=1;t1=t;t=_mm512_slli_epi16(t1,t);if((*(long long*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mavx512bw"]dnl
     [CPU_STR="AVX512BW"]
     [AC_MSG_RESULT([yes])]
    ,[AC_MSG_RESULT([no])]
    )
  ]
  )

else
  ##########################################
  # cross-compile versions of the same tests
  ##########################################
  CPU_NOTFOUND=0
  AC_MSG_NOTICE([Testing tool-chain's CPU features])
  AC_MSG_CHECKING([for MMX])
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <mmintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m64 t;*((long long*)&t)=1;t=_mm_set1_pi32(7);if((*(unsigned*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mmmx"] dnl
     [CPU_STR="MMX"]
     [AS_IF([test y$ARCH_LINK = yx86-any.h], [ARCH_LINK=x86-mmx.h])]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT(no)]
  )
  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  AC_MSG_CHECKING([for SSE2])
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <emmintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m128i t;*((long long*)&t)=1;t=_mm_slli_si128(t,7);if((*(unsigned*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-msse2"] dnl
     [CPU_STR="SSE2"]
     [AS_IF([test y$ARCH_LINK = yx86-mmx.h], [ARCH_LINK=x86-sse.h])]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT(no)]
  )
  ])
  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CPU_NOTFOUND=0
  AC_MSG_CHECKING([for SSSE3])
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <tmmintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m128i t;*((long long*)&t)=1;t=_mm_shuffle_epi8(t,t);if((*(unsigned*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mssse3"]dnl
     [CPU_STR="SSSE3"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
    )
  ]
  )
  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CPU_NOTFOUND=0
  AC_MSG_CHECKING([for SSE4.1])
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <smmintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m128d t;*((long long*)&t)=1;t=_mm_round_pd(t,1);if((*(long long*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-msse4.1"]dnl
     [CPU_STR="SSE4.1"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
    )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  AC_MSG_CHECKING([for AVX])
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <immintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m256d t;*((long long*)&t)=1;t=_mm256_movedup_pd(t);if((*(long long*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mavx"]dnl
     [CPU_STR="AVX"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
    )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  AC_MSG_CHECKING([for XOP])
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <x86intrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m128i t;*((long long*)&t)=1;t=_mm_roti_epi32(t,5);if((*(long long*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mxop"]dnl
     [CPU_STR="XOP"]
     [AC_MSG_RESULT([yes])]
    ,[AC_MSG_RESULT([no])]
    )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  AC_MSG_CHECKING([for AVX2])
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <immintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m256i t, t1;*((long long*)&t)=1;t1=t;t=_mm256_mul_epi32(t1,t);if((*(long long*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mavx2"]dnl
     [CPU_STR="AVX2"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
    )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  AC_MSG_CHECKING([for AVX512F])
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <immintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m512i t, t1;*((long long*)&t)=1;t1=t;t=_mm512_mul_epi32(t1,t);if((*(long long*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mavx512f"]dnl
     [CPU_STR="AVX512F"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
    )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  AC_MSG_CHECKING([for AVX512BW])
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <immintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m512i t, t1;*((long long*)&t)=1;t1=t;t=_mm512_slli_epi16(t1,t);if((*(long long*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mavx512bw"]dnl
     [CPU_STR="AVX512BW"]
     [AC_MSG_RESULT([yes])]
    ,[AC_MSG_RESULT([no])]
    )
  ]
  )
fi

CC="$CC_BACKUP"
CFLAGS="$CFLAGS_BACKUP"
])
