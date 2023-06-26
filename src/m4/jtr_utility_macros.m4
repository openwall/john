dnl This file is Copyright (C) 2014 JimF, and magnum
dnl and is hereby released to the general public under the following terms:
dnl Redistribution and use in source and binary forms, with or without
dnl modifications, are permitted.
dnl
dnl Here are contained numerous utility macros

dnl JTR_LIST_ADD(variable, value(s))
dnl Add space separated value(s) to variable unless already present.
AC_DEFUN([JTR_LIST_ADD], [
   for i in $2; do
      jtr_list_add_dupe=0
      for j in $$1; do
         if test "x$i" = "x$j"; then
            jtr_list_add_dupe=1
            break
         fi
      done
      if test $jtr_list_add_dupe = 0; then
         $1="$$1 $i"
         jtr_list_add_result="$jtr_list_add_result $i"
      fi
   done
])

AC_DEFUN([JTR_LIST_ADD_RESULT], [
   AS_IF([test -z "$jtr_list_add_result"],AC_MSG_RESULT([none]),AC_MSG_RESULT([$jtr_list_add_result]))
   jtr_list_add_result=""
])

dnl @synopsis JTR_FLAG_CHECK([compiler flags], flags)
dnl @summary check whether compiler supports given options or not.
dnl CFLAGS_EX is appended with each 'valid' command.
dnl
dnl If a second argument is 0, don't show progress
dnl If a second argument is 1, show progress
dnl If a second argument is 2, bails if not supported
AC_DEFUN([JTR_FLAG_CHECK],
 [AS_IF([test $2 -gt 0], [AC_MSG_CHECKING([if $CC supports $1])])
  AC_LANG_PUSH([C])
  ac_saved_cflags="$CFLAGS"
  CFLAGS="-Werror $1"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
    [AS_IF([test "$2" -gt 0], [AC_MSG_RESULT([yes])])]
      [CFLAGS_EX="$CFLAGS_EX $1"]
    ,[AS_IF([test $2 -gt 0], [AC_MSG_RESULT([no])])]
    [AS_IF([test "$2" = 2], [AC_MSG_ERROR([Not supported by compiler])])]
  )
  CFLAGS="$ac_saved_cflags"
  AC_LANG_POP([C])
])

dnl @synopsis JTR_NOWARN_CHECK([specific-warning], flags)
dnl @summary check whether compiler supports -Wspecific-warning and if
dnl it does, CFLAGS_EX is appended with -Wno-specific-warning
dnl
dnl The reason is we can test for -Wfoo but not -Wno-foo (soft fail by design)
dnl
dnl If a second argument is 0, don't show progress
dnl If a second argument is 1, show progress
dnl If a second argument is 2, bails if not supported
AC_DEFUN([JTR_NOWARN_CHECK],
 warn="-W$1"
 nowarn="-Wno-$1"
 [AS_IF([test $2 -gt 0], [AC_MSG_CHECKING([if $CC supports $nowarn])])
  AC_LANG_PUSH([C])
  ac_saved_cflags="$CFLAGS"
  CFLAGS="-Werror $warn"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
    [AS_IF([test "$2" -gt 0], [AC_MSG_RESULT([yes])])]
      [CFLAGS_EX="$CFLAGS_EX $nowarn"]
    ,[AS_IF([test $2 -gt 0], [AC_MSG_RESULT([no])])]
    [AS_IF([test "$2" = 2], [AC_MSG_ERROR([Not supported by compiler])])]
  )
  CFLAGS="$ac_saved_cflags"
  AC_LANG_POP([C])
])

dnl @synopsis JTR_FLAG_CHECK_LINK(compiler flags[, flags])
dnl @summary check whether compiler and linker supports given options or not.
dnl CFLAGS_EX is appended with each 'valid' command.
dnl
dnl If a second argument is 0, don't show progress
dnl If a second argument is 1, show progress
dnl If a second argument is 2, bails if not supported
AC_DEFUN([JTR_FLAG_CHECK_LINK],
 [AS_IF([test $2 -gt 0], [AC_MSG_CHECKING([if $CC supports $1 w/ linking])])
  AC_LANG_PUSH([C])
  ac_saved_cflags="$CFLAGS"
  CFLAGS="-Werror $1"
  AC_LINK_IFELSE([AC_LANG_PROGRAM([])],
    [AS_IF([test "$2" -gt 0], [AC_MSG_RESULT([yes])])]
      [CFLAGS_EX="$CFLAGS_EX $1"]
    ,[AS_IF([test $2 -gt 0], [AC_MSG_RESULT([no])])]
    [AS_IF([test "$2" = 2], [AC_MSG_ERROR([Not supported by compiler/linker])])]
  )
  CFLAGS="$ac_saved_cflags"
  AC_LANG_POP([C])
])

dnl @synopsis SET_NORMAL_INCLUDES
dnl @summary check and set many normal include paths
dnl This might be a Bad Idea[tm] if cross compiling.
AC_DEFUN([JTR_SET_NORMAL_INCLUDES],
[
  AC_MSG_CHECKING([additional paths])
  ADD_LDFLAGS=""
  ADD_CFLAGS=""
if test -d /usr/local/lib; then
   ADD_LDFLAGS="$ADD_LDFLAGS -L/usr/local/lib"
fi
if test -d /usr/local/include; then
   ADD_CFLAGS="$ADD_CFLAGS -I/usr/local/include"
fi
dnl macOS MacPorts paths.
if test -d /opt/local/lib; then
   ADD_LDFLAGS="$ADD_LDFLAGS -L/opt/local/lib"
fi
if test -d /opt/local/include; then
   ADD_CFLAGS="$ADD_CFLAGS -I/opt/local/include"
fi
dnl macOS Homebrew paths if now defined by OPENSSL_LIBS and OPENSSL_CFLAGS.
if test -z "$OPENSSL_LIBS"; then
  if test -d /usr/local/opt/openssl/lib; then
     ADD_LDFLAGS="$ADD_LDFLAGS -L/usr/local/opt/openssl/lib"
  fi
fi
if test -z "$OPENSSL_CFLAGS"; then
  if test -d /usr/local/opt/openssl/include; then
     ADD_CFLAGS="$ADD_CFLAGS -I/usr/local/opt/openssl/include"
  fi
fi
JTR_LIST_ADD(CPPFLAGS, [$ADD_CFLAGS]) # no typo here
jtr_list_add_result=""
JTR_LIST_ADD(LDFLAGS, [$ADD_LDFLAGS])
JTR_LIST_ADD(CFLAGS, [$ADD_CFLAGS])
JTR_LIST_ADD_RESULT
])

dnl @synopsis SET_64_INCLUDES
dnl @summary check and set some 64 bit includes
dnl This might be a Bad Idea[tm] if cross compiling.
AC_DEFUN([JTR_SET_64_INCLUDES],
[
  AC_MSG_CHECKING([additional paths (64 bit)])
  ADD_LDFLAGS=""
  ADD_CFLAGS=""
if test -d /usr/local/lib64; then
   ADD_LDFLAGS="$ADD_LDFLAGS -L/usr/local/lib64"
fi
if test -d /usr/lib64; then
   ADD_LDFLAGS="$ADD_LDFLAGS -L/usr/lib64"
fi
if test -d /lib64; then
   ADD_LDFLAGS="$ADD_LDFLAGS -L/lib64"
fi
JTR_LIST_ADD(CPPFLAGS, [$ADD_CFLAGS]) # no typo here
jtr_list_add_result=""
JTR_LIST_ADD(LDFLAGS, [$ADD_LDFLAGS])
JTR_LIST_ADD(CFLAGS, [$ADD_CFLAGS])
JTR_LIST_ADD_RESULT
])


dnl @synopsis SET_NORMAL_SSL_INCLUDES(base path)
dnl @summary check and set include/library paths for OpenSSL
dnl This might be a Bad Idea[tm] if cross compiling.
AC_DEFUN([JTR_SET_NORMAL_SSL_INCLUDES],
[
  AC_MSG_CHECKING([additional paths for OpenSSL])
  ADD_LDFLAGS=""
  ADD_CFLAGS=""
if test -d $1/lib; then
   ADD_LDFLAGS="$ADD_LDFLAGS -L$1/lib"
fi
if test -d $1/include; then
   ADD_CFLAGS="$ADD_CFLAGS -I$1/include"
fi
JTR_LIST_ADD(CPPFLAGS, [$ADD_CFLAGS]) # no typo here
jtr_list_add_result=""
JTR_LIST_ADD(LDFLAGS, [$ADD_LDFLAGS])
JTR_LIST_ADD(CFLAGS, [$ADD_CFLAGS])
JTR_LIST_ADD_RESULT
])

dnl JTR_MSG_RESULT_FAILIF_FORCED(success, forced, forced_fail_msg)
dnl success and forced should be xvar data, "x$enable_foobar", so they
dnl will be xno, xyes, xauto, etc.  forced_fail_msg is a message that
dnl will be output, and the script will abort, IF forced is xyes which
dnl means the user used --enable-foobar
AC_DEFUN([JTR_MSG_RESULT_FAILIF_FORCED], [
  if test "$1" = xyes; then
    AC_MSG_RESULT([yes])
  else
    AC_MSG_RESULT([no])
    if test "$2" = xyes; then
      AC_MSG_FAILURE([$3])
    fi
  fi
])

dnl JTR_MSG_CHECKING_AND_RESULT_FAILIF_FORCED(chk_msg, success, forced, forced_fail_msg)
dnl will output a checking 'chk_msg', then calls JTR_MSG_RESULT_FAILIF_FORCED
AC_DEFUN([JTR_MSG_CHECKING_AND_RESULT_FAILIF_FORCED], [
  AC_MSG_CHECKING([$1])
  JTR_MSG_RESULT_FAILIF_FORCED($2,$3,$4)
])

dnl @synopsis JTR_SET_OPENCL_INCLUDES
dnl @summary check and set many normal include paths
AC_DEFUN([JTR_SET_OPENCL_INCLUDES],
[
   AC_MSG_CHECKING([additional paths for OpenCL])
   ADD_LDFLAGS=""
   ADD_CFLAGS=""
   if test -n "$AMDAPPSDKROOT"; then
      if test -d "$AMDAPPSDKROOT/include"; then
         ADD_CFLAGS="$ADD_CFLAGS -I$AMDAPPSDKROOT/include"
      fi
      if test $CPU_BIT_STR = 64 -a -d "$AMDAPPSDKROOT/lib/x86_64" ; then
         ADD_LDFLAGS="$ADD_LDFLAGS -L$AMDAPPSDKROOT/lib/x86_64"
      elif test  $CPU_BIT_STR = 32 -a -d "$AMDAPPSDKROOT/lib/x86" ; then
         ADD_LDFLAGS="$ADD_LDFLAGS -L$AMDAPPSDKROOT/lib/x86"
      elif test -d "$AMDAPPSDKROOT/lib"; then
         ADD_LDFLAGS="$ADD_LDFLAGS -L$AMDAPPSDKROOT/lib"
      fi
   fi
   if test -n "$ATISTREAMSDKROOT"; then
      if test -d "$ATISTREAMSDKROOT/include"; then
         ADD_CFLAGS="$ADD_CFLAGS -I$ATISTREAMSDKROOT/include"
      fi
      if test $CPU_BIT_STR = 64 -a -d "$ATISTREAMSDKROOT/lib/x86_64" ; then
         ADD_LDFLAGS="$ADD_LDFLAGS -L$ATISTREAMSDKROOT/lib/x86_64"
      elif test  $CPU_BIT_STR = 32 -a -d "$ATISTREAMSDKROOT/lib/x86" ; then
         ADD_LDFLAGS="$ADD_LDFLAGS -L$ATISTREAMSDKROOT/lib/x86"
      elif test -d "$ATISTREAMSDKROOT/lib"; then
         ADD_LDFLAGS="$ADD_LDFLAGS -L$ATISTREAMSDKROOT/lib"
      fi
   fi
   JTR_LIST_ADD(CPPFLAGS, [$ADD_CFLAGS]) # no typo here
   jtr_list_add_result=""
   JTR_LIST_ADD(LDFLAGS, [$ADD_LDFLAGS])
   JTR_LIST_ADD(CFLAGS, [$ADD_CFLAGS])
   JTR_LIST_ADD_RESULT
])

dnl @synopsis ACX_HEADER_STRING
dnl @summary See whether we can include both string.h and strings.h.
dnl @usage:
dnl #if STRING_WITH_STRINGS
dnl #include <string.h>
dnl #include <strings.h>
dnl #elif HAVE_STRING_H
dnl #include <string.h>
dnl #elif HAVE_STRINGS_H
dnl #include <strings.h>
dnl #endif
AC_DEFUN([ACX_HEADER_STRING],
[AC_CACHE_CHECK([whether string.h and strings.h may both be included],
  gcc_cv_header_string,
[AC_TRY_COMPILE([#include <string.h>
#include <strings.h>], , gcc_cv_header_string=yes, gcc_cv_header_string=no)])
if test $gcc_cv_header_string = yes; then
  AC_DEFINE(STRING_WITH_STRINGS, 1, [Define if you can safely include both <string.h> and <strings.h>.])
fi
])
