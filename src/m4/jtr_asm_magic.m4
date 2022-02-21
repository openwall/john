dnl This file is Copyright (C) 2014-2017 magnum & JimF,
dnl and is hereby released to the general public under the following terms:
dnl Redistribution and use in source and binary forms, with or without
dnl modifications, are permitted.
dnl
dnl All tests in this file are supposed to be cross compile compliant
dnl
AC_DEFUN([JTR_ASM_MAGIC], [
CC_BACKUP=$CC
CFLAGS_BACKUP=$CFLAGS

dnl ======================================================================
dnl ASM_MAGIC code.  Here we add certain 'magic' values. Things like
dnl  -DUNDERSCORES -DBSD -DALIGN_LOG   (for macosx-x86-*)
dnl  -DUNDERSCORES -DALIGN_LOG for (dos-djgpp-x86-*)
dnl  -DUNDERSCORES for cygwin / MinGW / VC
dnl ======================================================================
EXTRA_AS_FLAGS=
AC_MSG_CHECKING([for extra ASFLAGS])
CC="$CC_BACKUP"
CFLAGS="$CFLAGS -O0"
AS_IF([echo "int long_ident;" > conftest.c && ${CC} -c conftest.c && ${STRINGS} - conftest.${OBJEXT} | ${GREP} _long_ident > conftest.out],
      [JTR_LIST_ADD(EXTRA_AS_FLAGS, [-DUNDERSCORES])])

AC_LINK_IFELSE([AC_LANG_SOURCE(
  [[extern void exit(int);
  int main() {
  #if defined(__APPLE__) && defined(__MACH__)
    exit(0);
  #else
    BORK!
  #endif
  }]])]
  ,[JTR_LIST_ADD(EXTRA_AS_FLAGS, [-DBSD -DALIGN_LOG])])

AS_IF([test "x$EXTRA_AS_FLAGS" = x],[AC_MSG_RESULT([None needed])],[AC_MSG_RESULT([${EXTRA_AS_FLAGS}])])

dnl ======================================================================
dnl Extra code for X32 ABI test.  We need this for dynamic AES-NI support.
dnl ======================================================================
AS_IF([test "x$cpu_family" = xintel -a "x$ax_intel_x32" != xno],
AC_MSG_CHECKING([for X32 ABI])
[AC_LINK_IFELSE(
  [AC_LANG_SOURCE(
    [[extern void exit(int);
     int main() {
     #if defined(__x86_64__) && defined(__ILP32__)
       exit(0);}
     #else
       BORK!
     #endif
     ]]
   )]
   ,[AC_MSG_RESULT([yes])]
   [ax_intel_x32=yes]
   ,[AC_MSG_RESULT([no])]
)])

CC="$CC_BACKUP"
CFLAGS="$CFLAGS_BACKUP"
])
