dnl This file is Copyright (C) 2014 JimF,
dnl and is hereby released to the general public under the following terms:
dnl Redistribution and use in source and binary forms, with or without
dnl modifications, are permitted.
dnl
dnl All tests in this file are supposed to be cross compile compliant
dnl
AC_DEFUN([JTR_SYSTEMS_SPECIFIC_LOGIC], [
CC_BACKUP=$CC
CFLAGS_BACKUP="$CFLAGS"

case "$host_os" in
dnl ======================================================================
dnl check for using .exe or -ln -s for cygwin/mingw builds only.  Default
dnl uses symlink.c and exe. cygwin can use --enable-ln-s to override this
dnl with ln -s
dnl ======================================================================
  cygwin*)
    AC_MSG_CHECKING([for *2john helper type])
    AS_IF([test "x$enable_ln_s" != xno], [AC_MSG_RESULT([ln -s])], [AC_SUBST([EXE_EXT], [.exe])] [AC_MSG_RESULT([.exe (symlink.c)])])
    AC_CHECK_FUNCS([_get_osfhandle])
    dnl check for GetFileSizeEx was more of a bioch. I had to revert
    dnl to doing a build/link probe. I could not find a way to do it with
    dnl AC_CHECK_FUNCS, or AC_CHECK_LIB or AC_SEARCH_LIBS. Things just failed.
    AC_MSG_CHECKING([for GetFileSizeEx])
    AC_LINK_IFELSE(
    [
    AC_LANG_SOURCE(
      [[#include <windows.h>
        #include <io.h>
        extern void exit(int);
        int main(){long long l; GetFileSizeEx(0,&l); exit(0);}]]
    )]
    ,AC_DEFINE([HAVE_GETFILESIZEEX], 1, ["Enable if GetFileSizeEx function is available"])
     [AC_MSG_RESULT([yes])]
    ,[AC_MSG_RESULT(no)]
    )
    ;;
  mingw*)
     AC_SUBST([EXE_EXT], [.exe])
     AC_MSG_CHECKING([for *2john helper type])
     AC_MSG_RESULT([.exe (symlink.c)])
     dnl From legacy Makefile's mingw targets
     AX_PTHREAD
     AC_CHECK_LIB([wsock32],[main])
     AC_CHECK_LIB([ws2_32],[main])
     AC_CHECK_LIB([wst],[main])
     ;;

  solaris*)
     dnl From legacy Makefile's LDFLAGS_SOLARIS
     AC_CHECK_LIB([nsl],[main])
     AC_CHECK_LIB([rt],[main])
     AC_CHECK_LIB([socket],[main])
     ;;
esac

dnl ======================================================================
dnl From this point, we accumlate all set vars
dnl into the jtr_list_add_result var, and later
dnl output what vars were added (or none)
dnl ======================================================================
jtr_list_add_result=""
AC_MSG_CHECKING([for OS-specific feature macros needed])

case "$host_os" in
  freebsd*)
    dnl From legacy Makefile's FreeBSD targets
    JTR_LIST_ADD(CFLAGS_EXTRA, [-D__BSD_VISIBLE])
    AS_IF([test "x$CPU_BIT_STR" = x32], ASFLAGS="$ASFLAGS -DBSD")
    ;;

  linux*)
    dnl For exposing fileno()
    JTR_LIST_ADD(CFLAGS_EXTRA, [-D_POSIX_SOURCE])
    dnl For exposing memmem()
    AS_IF([test "x$ac_cv_func_memmem" = xyes], [JTR_LIST_ADD(CFLAGS_EXTRA, [-D_GNU_SOURCE])])
    dnl For exposing aligned_alloc
    AS_IF([test "x$ac_cv_func_aligned_alloc" = xyes], [JTR_LIST_ADD(CFLAGS_EXTRA, [-D_ISOC11_SOURCE])],
        dnl For exposing posix_memalign()
        [AS_IF([test "x$ac_cv_func_posix_memalign" = xyes], [JTR_LIST_ADD(CFLAGS_EXTRA, [-D_XOPEN_SOURCE=600])])]
    )
    ;;

  cygwin*)
    dnl For exposing fileno().  NOTE, build fails if both _POSIX_SOURCE and
    dnl _GNU_SOURCE used at same time.
    dnl JTR_LIST_ADD(CFLAGS_EXTRA, [-D_POSIX_SOURCE])
    dnl For exposing memmem()
    AS_IF([test "x$ac_cv_func_memmem" = xyes], [JTR_LIST_ADD(CFLAGS_EXTRA, [-D_GNU_SOURCE])])
    ;;

  mingw*)
    dnl For understanding really basic things like printf("%zu", ...)
    JTR_LIST_ADD(CFLAGS_EXTRA, [-D__USE_MINGW_ANSI_STDIO])
    ;;
esac

dnl ======================================================================
dnl Add large file support - typically requires a feature macro on 32-bit.
dnl ======================================================================
case "$host" in
  *linux*|arm*|alpha*|powerpcle|powerpc*)
    AS_IF([test x${CPU_BIT_STR} = x32 && test "x$ac_cv_func_lseek64" = xyes], [JTR_LIST_ADD(CFLAGS_EXTRA, [-D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE])])
    ;;
  i?86*darwin*)
    AS_IF([test "x$ac_cv_func_fseeko" = xyes], [JTR_LIST_ADD(CFLAGS_EXTRA, [-D_DARWIN_C_SOURCE])])
    ;;
  x86_64*cygwin*)
    ax_intel_x32=no
    EXTRA_AS_FLAGS="$EXTRA_AS_FLAGS -D__CYGWIN64__ -D__CYGWIN32__"
    JTR_LIST_ADD(CFLAGS_EXTRA, ["-D__CYGWIN64__ -D__CYGWIN32__"])
    ;;
  sparc*solaris*)
    AS_IF([test "x$ac_cv_func_fseeko64" = xyes && test x${CPU_BIT_STR} = x32], [JTR_LIST_ADD(CFLAGS_EXTRA, [-D__EXTENSIONS__ -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64])])
    ;;
esac

dnl ======================================================================
dnl   Now output the result of what we accumlated in jtr_list_add_result
dnl ======================================================================
JTR_LIST_ADD_RESULT

CC="$CC_BACKUP"
CFLAGS="$CFLAGS_BACKUP"
])
