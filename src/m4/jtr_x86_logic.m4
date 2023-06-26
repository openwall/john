dnl JtR configure Intel-SIMD instruction active probe test
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

dnl ======================================================================
dnl               Intel Active CPU probe test of build-host.
dnl ======================================================================

  AS_CASE([$host_os], [darwin*],
    [CC="$CC_BACKUP"
    CFLAGS="-mavx"
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
      [CFLAGS="$CFLAGS_BACKUP"]
    )
    [CC="$CC_BACKUP"]
    [CFLAGS="$CFLAGS_BACKUP"]]
  )
CFLAGS="$CFLAGS $SIMD_FLAGS -O0"

if test "x$simd" != xno; then
 if test "x$enable_native_tests" != xno && test "x$simd" = xyes; then
  AC_MSG_NOTICE([Testing build host's native CPU features])
  CPU_NOTFOUND=0
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
    ,[CPU_BEST_FLAGS="-mmmx"]
     [SIMD_NAME="MMX"]
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
    ,[CPU_BEST_FLAGS="-msse2"]
     [SIMD_NAME="SSE2"]
     [AS_IF([test y$ARCH_LINK = yx86-mmx.h], [ARCH_LINK=x86-sse.h])]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT(no)]
  )
  ])

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CC="$CC_BACKUP"
  if test $host_cpu = "x86_64"; then
    CPUID_ASM="x86-64.S"
    CPUID_FILE="x86-64.h"
  else
    CPUID_ASM="x86.S"
    CPUID_FILE="x86-sse.h"
  fi

  CFLAGS="$CFLAGS_BACKUP -mssse3 -P $EXTRA_AS_FLAGS $CPPFLAGS $CFLAGS_EXTRA $CPUID_ASM"

  ln -fs $CPUID_FILE arch.h

  AC_MSG_CHECKING([for SSSE3])
  AC_RUN_IFELSE([AC_LANG_SOURCE(
    [[extern int CPU_detect(void); extern char CPU_req_name[];
      unsigned int nt_buffer8x[4], output8x[4];
      int main(int argc, char **argv) { return !CPU_detect(); }
    ]])],
     [CPU_BEST_FLAGS="-mssse3"]
     [SIMD_NAME="SSSE3"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT([no])]
  )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CFLAGS="$CFLAGS_BACKUP -msse4.1 -P $EXTRA_AS_FLAGS $CPPFLAGS $CFLAGS_EXTRA $CPUID_ASM"

  AC_MSG_CHECKING([for SSE4.1])
  AC_RUN_IFELSE([AC_LANG_SOURCE(
    [[extern int CPU_detect(void); extern char CPU_req_name[];
      unsigned int nt_buffer8x[4], output8x[4];
      int main(int argc, char **argv) { return !CPU_detect(); }
    ]])],
     [CPU_BEST_FLAGS="-msse4.1"]
     [SIMD_NAME="SSE4.1"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT([no])]
  )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CFLAGS="$CFLAGS_BACKUP -msse4.2 -P $EXTRA_AS_FLAGS $CPPFLAGS $CFLAGS_EXTRA $CPUID_ASM"

  AC_MSG_CHECKING([for SSE4.2])
  AC_RUN_IFELSE([AC_LANG_SOURCE(
    [[extern int CPU_detect(void); extern char CPU_req_name[];
      unsigned int nt_buffer8x[4], output8x[4];
      int main(int argc, char **argv) { return !CPU_detect(); }
    ]])],
     [CPU_BEST_FLAGS="-msse4.2"]
     [SIMD_NAME="SSE4.2"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT([no])]
  )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CFLAGS="$CFLAGS_BACKUP -mavx -P $EXTRA_AS_FLAGS $CPPFLAGS $CFLAGS_EXTRA $CPUID_ASM"

  AC_MSG_CHECKING([for AVX])
  AC_RUN_IFELSE([AC_LANG_SOURCE(
    [[extern int CPU_detect(void); extern char CPU_req_name[];
      unsigned int nt_buffer8x[4], output8x[4];
      int main(int argc, char **argv) { return !CPU_detect(); }
    ]])],
     [CPU_BEST_FLAGS="-mavx"]
     [SIMD_NAME="AVX"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT([no])]
  )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CFLAGS="$CFLAGS_BACKUP -mxop -P $EXTRA_AS_FLAGS $CPPFLAGS $CFLAGS_EXTRA $CPUID_ASM"

  AC_MSG_CHECKING([for XOP])
  AC_RUN_IFELSE([AC_LANG_SOURCE(
    [[extern int CPU_detect(void); extern char CPU_req_name[];
      unsigned int nt_buffer8x[4], output8x[4];
      int main(int argc, char **argv) { return !CPU_detect(); }
    ]])],
     [CPU_BEST_FLAGS="-mxop"]
     [SIMD_NAME="XOP"]
     [AC_MSG_RESULT([yes])]
    ,
     [AC_MSG_RESULT([no])]
  )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CFLAGS="$CFLAGS_BACKUP -mavx2 -P $EXTRA_AS_FLAGS $CPPFLAGS $CFLAGS_EXTRA $CPUID_ASM"

  AC_MSG_CHECKING([for AVX2])
  AC_RUN_IFELSE([AC_LANG_SOURCE(
    [[extern int CPU_detect(void); extern char CPU_req_name[];
      unsigned int nt_buffer8x[4], output8x[4];
      int main(int argc, char **argv) { return !CPU_detect(); }
    ]])],
     [CPU_BEST_FLAGS="-mavx2"]
     [SIMD_NAME="AVX2"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
  )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CFLAGS="$CFLAGS_BACKUP -mavx512f -P $EXTRA_AS_FLAGS $CPPFLAGS $CFLAGS_EXTRA $CPUID_ASM"

  AC_MSG_CHECKING([for AVX512F])
  AC_RUN_IFELSE([AC_LANG_SOURCE(
    [[extern int CPU_detect(void); extern char CPU_req_name[];
      unsigned int nt_buffer8x[4], output8x[4];
      int main(int argc, char **argv) { return !CPU_detect(); }
    ]])],
     [CPU_BEST_FLAGS="-mavx512f"]
     [SIMD_NAME="AVX512F"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
    )
  ]
  )

  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  CFLAGS="$CFLAGS_BACKUP -mavx512bw -P $EXTRA_AS_FLAGS $CPPFLAGS $CFLAGS_EXTRA $CPUID_ASM"

  AC_MSG_CHECKING([for AVX512BW])
  AC_RUN_IFELSE([AC_LANG_SOURCE(
    [[extern int CPU_detect(void); extern char CPU_req_name[];
      unsigned int nt_buffer8x[4], output8x[4];
      int main(int argc, char **argv) { return !CPU_detect(); }
    ]])],
     [CPU_BEST_FLAGS="-mavx512bw"]
     [SIMD_NAME="AVX512BW"]
     [AC_MSG_RESULT([yes])]
    ,[AC_MSG_RESULT([no])]
    )
  ]
  )

 else

dnl ======================================================================
dnl               cross-compile versions of the same tests
dnl ======================================================================
  CPU_NOTFOUND=0
  AC_MSG_NOTICE([Testing tool-chain's CPU support with given options])
  AC_MSG_CHECKING([for MMX])
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <mmintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m64 t;*((long long*)&t)=1;t=_mm_set1_pi32(7);if((*(unsigned*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mmmx"]
     [SIMD_NAME="MMX"]
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
    ,[CPU_BEST_FLAGS="-msse2"]
     [SIMD_NAME="SSE2"]
     [AS_IF([test y$ARCH_LINK = yx86-mmx.h], [ARCH_LINK=x86-sse.h])]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT(no)]
  )
  ])
  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  AC_MSG_CHECKING([for SSSE3])
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <tmmintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m128i t;*((long long*)&t)=1;t=_mm_shuffle_epi8(t,t);if((*(unsigned*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-mssse3"]
     [SIMD_NAME="SSSE3"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
    )
  ]
  )
  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  AC_MSG_CHECKING([for SSE4.1])
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <smmintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){__m128d t;*((long long*)&t)=1;t=_mm_round_pd(t,1);if((*(long long*)&t)==88)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-msse4.1"]
     [SIMD_NAME="SSE4.1"]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND=1]
     [AC_MSG_RESULT([no])]
    )
  ]
  )
  AS_IF([test "x$CPU_NOTFOUND" = x0],
  [
  AC_MSG_CHECKING([for SSE4.2])
  AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <nmmintrin.h>
        #include <stdio.h>
        extern void exit(int);
        int main(){unsigned int t=_mm_crc32_u8(0xffffffff,(unsigned char)'a');if(t==0x3e2fbccf)printf(".");exit(0);}]]
    )]
    ,[CPU_BEST_FLAGS="-msse4.2"]
     [SIMD_NAME="SSE4.2"]
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
    ,[CPU_BEST_FLAGS="-mavx"]
     [SIMD_NAME="AVX"]
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
    ,[CPU_BEST_FLAGS="-mxop"]
     [SIMD_NAME="XOP"]
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
    ,[CPU_BEST_FLAGS="-mavx2"]
     [SIMD_NAME="AVX2"]
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
    ,[CPU_BEST_FLAGS="-mavx512f"]
     [SIMD_NAME="AVX512F"]
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
        int main(){__m512i t=_mm512_slli_epi16(_mm512_set1_epi16(1),1);exit(!(_mm_cvtsi128_si64x(_mm512_extracti32x4_epi32(t,0))==0x2000200020002ULL));}]]
    )]
    ,[CPU_BEST_FLAGS="-mavx512bw"]
     [SIMD_NAME="AVX512BW"]
     [AC_MSG_RESULT([yes])]
    ,[AC_MSG_RESULT([no])]
    )
  ]
  )
 fi
fi

if test $simd != yes; then
  if test $simd = no; then
    SIMD_NAME="(SIMD disabled)"
  else
    CPU_BEST_FLAGS=$SIMD_FLAGS
  fi
fi

CC="$CC_BACKUP"
CFLAGS="$CFLAGS_BACKUP"

])
