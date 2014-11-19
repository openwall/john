# This file is Copyright (C) 2014 JimF,
# and is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modifications, are permitted.
#
# All tests in this file are supposed to be cross compile compliant
#
AC_DEFUN([JTR_SYSTEMS_SPECIFIC_LOGIC], [
CC_BACKUP=$CC
CFLAGS_BACKUP="$CFLAGS"

case "$host_os" in
#############################################################################
# check for using .exe or -ln -s for cygwin/mingw builds only.  Default uses
# symlink.c and exe. cygwin can use --enable-ln-s to override this with ln -s
#############################################################################
  cygwin*)
    AC_MSG_CHECKING([for *2john helper type])
    AS_IF([test "x$enable_ln_s" != xno], [AC_MSG_RESULT([ln -s])], [AC_SUBST([EXE_EXT], [.exe])] [AC_MSG_RESULT([.exe (symlink.c)])])
	;;
  mingw*)
     AC_SUBST([EXE_EXT], [.exe])
     AC_MSG_CHECKING([for *2john helper type])
     AC_MSG_RESULT([.exe (symlink.c)])
     # From legacy Makefile's mingw targets
     AX_PTHREAD
     AC_CHECK_LIB([wsock32],[main])
     AC_CHECK_LIB([ws2_32],[main])
     AC_CHECK_LIB([wst],[main])
     ;;

  solaris*)
     # From legacy Makefile's LDFLAGS_SOLARIS
     AC_CHECK_LIB([nsl],[main])
     AC_CHECK_LIB([rt],[main])
     AC_CHECK_LIB([socket],[main])
     ;;
esac

#############################################
# From this point, we accumlate all set vars
# into the jtr_list_add_result var, and later
# output what vars were added (or none)
#############################################
jtr_list_add_result=""
AC_MSG_CHECKING([for OS-specific feature macros needed])

case "$host_os" in
  freebsd*)
    # From legacy Makefile's FreeBSD targets
    JTR_LIST_ADD(CFLAGS_EXTRA, [-D__BSD_VISIBLE])
    ;;

  linux*|cygwin*)
    # For exposing memmem()
    AS_IF([test "x$ac_cv_func_memmem" = xyes], [JTR_LIST_ADD(CFLAGS_EXTRA, [-D_GNU_SOURCE])])
    ;;
esac

#############################################################################
# Add large file support - this typically requires a feature macro on 32-bit.
#############################################################################
case "$host" in
  i?86*linux*)
    AS_IF([test "x$ac_cv_func_lseek64" = xyes], [JTR_LIST_ADD(CFLAGS_EXTRA, [-D_FILE_OFFSET_BITS=64 -D_LARGEFILE64_SOURCE])])
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

#########################################
# Now output the result of what we
# accumlated in jtr_list_add_result
#########################################
JTR_LIST_ADD_RESULT

CC="$CC_BACKUP"
CFLAGS="$CFLAGS_BACKUP"
])
