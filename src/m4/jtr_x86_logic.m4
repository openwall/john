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

# TODO: We should move the MMX_COEF and *_PARA shite into this file and
# ifdef it out from the arch.h

# TODO: Ultimately we should not depend on any predefined stuff in arch.h
# at all

AC_DEFUN([JTR_X86_SPECIAL_LOGIC], [
CC_BACKUP=$CC
CFLAGS_BACKUP=$CFLAGS

#############################################################################
# CPU test code.  We start with SSE2, then SSSE3, then SSE4, ... until we fail
# whatever the last one is, we use it.  NOTE, if AVX fails we still DO test XOP
# since one is intel, one is AMD.  At the very end of configure, we set gcc
# back to whatever the 'best' was.  During running in configure, $CC gets reset
# so the results of our tests must be remembered, and reset just before exit.
#############################################################################
CFLAGS="$CFLAGS -O0"
if test "x$enable_native_tests" = xyes; then
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
    ,[AC_MSG_RESULT([no])]
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

  AS_CASE([$host_os], [darwin*], [AS_IF([test "x$CPU_STR" = "xSSE4.1"],
    [AC_PATH_PROGS([jtr_as], [as])]
    [AS_IF([test "x$jtr_as" = "x/usr/bin/as"],
      [AC_MSG_CHECKING([that 'as' works for AVX])]
      [AC_LINK_IFELSE(
         [AC_LANG_SOURCE(
            [extern void exit(int);
            int main() {
            #if defined(__AVX__)
                exit(0);}
            #else
                BORK!
            #endif
            ]
         )]
        ,[AC_MSG_RESULT([no])]
         [osx_assembler_warn=yes]
        ,[AC_MSG_RESULT(yes)]
      )]
    )]
  )])

else

  ##########################################
  # cross-compile versions of the same tests
  ##########################################
  CC="$CC_BACKUP"
  CPU_NOTFOUND=0
  AC_MSG_NOTICE([Checking enabled ${host_cpu} host CPU features])
  AC_MSG_CHECKING([for MMX])
  AC_LINK_IFELSE(
     [AC_LANG_SOURCE(
	[extern void exit(int);
	int main() {
	#if defined(__MMX__)
	    exit(0);}
	#else
	    BORK!
	#endif
	]
     )]
    ,[CPU_BEST_FLAGS="-mmmx"] dnl
     [CPU_STR="MMX"]
     [AS_IF([test y$ARCH_LINK = yx86-any.h], [ARCH_LINK=x86-mmx.h])]
     [AC_MSG_RESULT([yes])]
    ,[CPU_NOTFOUND="1"]
     [AC_MSG_RESULT(no)]
  )
  if test "x$CPU_NOTFOUND" = x0; then
    AC_MSG_CHECKING([for SSE2])
    AC_LINK_IFELSE(
       [AC_LANG_SOURCE(
	  [extern void exit(int);
	  int main() {
	  #if defined(__SSE2__)
	      exit(0);}
	  #else
	      BORK!
	  #endif
	  ]
       )]
      ,[CPU_BEST_FLAGS="-msse2"] dnl
       [CPU_STR="SSE2"]
       [AS_IF([test y$ARCH_LINK = yx86-mmx.h], [ARCH_LINK=x86-sse.h])]
       [AC_MSG_RESULT([yes])]
      ,[CPU_NOTFOUND="1"]
       [AC_MSG_RESULT(no)]
    )
  fi
  if test "x$CPU_NOTFOUND" = x0; then
    AC_MSG_CHECKING([for SSSE3])
    AC_LINK_IFELSE(
       [AC_LANG_SOURCE(
	  [extern void exit(int);
	  int main() {
	  #if defined(__SSSE3__)
	      exit(0);}
	  #else
	      BORK!
	  #endif
	  ]
       )]
      ,[CPU_BEST_FLAGS="-mssse3"] dnl
       [CPU_STR="SSSE3"]
       [AC_MSG_RESULT([yes])]
      ,[CPU_NOTFOUND="1"]
       [AC_MSG_RESULT(no)]
    )
  fi
  if test "x$CPU_NOTFOUND" = x0; then
    AC_MSG_CHECKING([for SSE4.1])
    AC_LINK_IFELSE(
       [AC_LANG_SOURCE(
	  [extern void exit(int);
	  int main() {
	  #if defined(__SSE4_1__)
	      exit(0);}
	  #else
	      BORK!
	  #endif
	  ]
       )]
      ,[CPU_BEST_FLAGS="-msse4.1"] dnl
       [CPU_STR="SSE4.1"]
       [AC_MSG_RESULT([yes])]
      ,[CPU_NOTFOUND="1"]
       [AC_MSG_RESULT(no)]
    )
  fi
  if test "x$CPU_NOTFOUND" = x0; then
    AC_MSG_CHECKING([for AVX])
    AC_LINK_IFELSE(
       [AC_LANG_SOURCE(
	  [extern void exit(int);
	  int main() {
	  #if defined(__AVX__)
	      exit(0);}
	  #else
	      BORK!
	  #endif
	  ]
       )]
      ,[CPU_BEST_FLAGS="-mavx"] dnl
       [CPU_STR="AVX"]
       [AC_MSG_RESULT([yes])]
      ,[CPU_NOTFOUND="1"]
       [AC_MSG_RESULT(no)]
    )
  fi
  if test "x$CPU_NOTFOUND" = x0; then
    AC_MSG_CHECKING([for AVX2])
    AC_LINK_IFELSE(
       [AC_LANG_SOURCE(
	  [extern void exit(int);
	  int main() {
	  #if defined(__AVX2__)
	      exit(0);}
	  #else
	      BORK!
	  #endif
	  ]
       )]
      ,[CPU_BEST_FLAGS="-mavx2"] dnl
       [CPU_STR="AVX2"]
       [AC_MSG_RESULT([yes])]
      ,[AC_MSG_RESULT(no)]
    )
  fi
  if test "x$CPU_NOTFOUND" = x0; then
    AC_MSG_CHECKING([for XOP])
    AC_LINK_IFELSE(
       [AC_LANG_SOURCE(
	  [extern void exit(int);
	  int main() {
	  #if defined(__XOP__)
	      exit(0);}
	  #else
	      BORK!
	  #endif
	  ]
       )]
      ,[CPU_BEST_FLAGS="-mxop"] dnl
       [CPU_STR="XOP"]
       [AC_MSG_RESULT([yes])]
      ,[AC_MSG_RESULT(no)]
    )
  fi

  AS_CASE([$host_os], [darwin*], [AS_IF([test "x$CPU_NOTFOUND" = x0],[
    CC="$CC_BACKUP -mavx"
    AC_MSG_CHECKING([that 'as' works for AVX])
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
       [AC_MSG_ERROR(['as' can't assemble AVX instructions. See last section of doc/INSTALL])]
      )
    ])]
  )

fi

CC="$CC_BACKUP"
CFLAGS="$CFLAGS_BACKUP"
])
