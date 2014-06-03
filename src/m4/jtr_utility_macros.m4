# This file is Copyright (C) 2014 JimF, and magnum
# and is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modifications, are permitted.
#
# Here are contained numerous utility macros

# JTR_LIST_ADD(variable, value(s))
# Add space separated value(s) to variable unless already present.
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

# @synopsis JTR_FLAG_CHECK [compiler flags]
# @summary check whether compiler supports given
#          C flags or not. The var CFLAGS_EX is
#          added to with each 'valid' command.
AC_DEFUN([JTR_FLAG_CHECK],
[dnl
  AS_IF([test "$2" = 1], [AC_MSG_CHECKING([if $CC supports $1])])
  AC_LANG_PUSH([C])
  ac_saved_cflags="$CFLAGS"
  CFLAGS="-Werror $1"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
    [AS_IF([test "$2" = 1], [AC_MSG_RESULT([yes])])]
      [CFLAGS_EX="$CFLAGS_EX $1"]
    ,[AS_IF([test "$2" = 1], [AC_MSG_RESULT([no])])]
  )
  CFLAGS="$ac_saved_cflags"
  AC_LANG_POP([C])
])

# @synopsis SET_NORMAL_INCLUDES
# @summary check and set many normal include paths
# This might be a Bad Idea[tm] if cross compiling.
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
JTR_LIST_ADD(CPPFLAGS, [$ADD_CFLAGS]) # no typo here
jtr_list_add_result=""
JTR_LIST_ADD(LDFLAGS, [$ADD_LDFLAGS])
JTR_LIST_ADD(CFLAGS, [$ADD_CFLAGS])
JTR_LIST_ADD_RESULT
])

# @synopsis SET_NORMAL_SSL_INCLUDES(base path)
# @summary check and set include/library paths for OpenSSL
# This might be a Bad Idea[tm] if cross compiling.
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

# @synopsis JTR_SET_CUDA_INCLUDES
# @summary check and set many normal include paths
AC_DEFUN([JTR_SET_CUDA_INCLUDES],
[
   AC_ARG_VAR([NVIDIA_CUDA], [base path of CUDA installation])
   AC_MSG_CHECKING([additional paths for CUDA])
   ADD_LDFLAGS=""
   ADD_CFLAGS=""
   if test -n "$NVIDIA_CUDA"; then
      CUDAPATH="$NVIDIA_CUDA"
   else
      CUDAPATH=/usr/local/cuda
   fi
   AC_SUBST([NVIDIA_CUDA],["$CUDAPATH"])
   if test -d "$CUDAPATH/include"; then
      ADD_CFLAGS="$ADD_CFLAGS -I$CUDAPATH/include"
   fi
   if test $CPU_BIT_STR = 64 -a -d "$CUDAPATH/lib64"; then
      ADD_LDFLAGS="$ADD_LDFLAGS -L$CUDAPATH/lib64"
   elif test -d "$CUDAPATH/lib"; then
      ADD_LDFLAGS="$ADD_LDFLAGS -L$CUDAPATH/lib"
   fi
   JTR_LIST_ADD(CPPFLAGS, [$ADD_CFLAGS]) # no typo here
   jtr_list_add_result=""
   JTR_LIST_ADD(LDFLAGS, [$ADD_LDFLAGS])
   JTR_LIST_ADD(CFLAGS, [$ADD_CFLAGS])
   JTR_LIST_ADD_RESULT
])

AC_DEFUN([JTR_CUDA],
[
  AC_ARG_VAR([NVCC], [full pathname of CUDA compiler])
  AC_ARG_VAR([NVCC_GCC], [full pathname of CUDA compiler's gcc backend])
  using_cuda=no
  if test "x$enable_cuda" != xno; then
     AS_IF([test "x$cross_compiling" = xno], [JTR_SET_CUDA_INCLUDES])
     AC_PATH_PROG([NVCC], [nvcc], [], [$PATH$PATH_SEPARATOR$CUDAPATH])
     AS_IF([test "x$NVCC" != "x"],
        [AC_PATH_PROGS([NVCC_GCC],[llvm-gcc-4.2 gcc-4.6 gcc-4.5 gcc-4.4 gcc-4.3 gcc-4.2], [], [$PATH$PATH_SEPARATOR$CUDAPATH])]
	[AC_CHECK_HEADER([cuda.h], [AC_CHECK_LIB([cudart],[cudaGetDeviceCount],
				   [using_cuda=yes]
				   [AC_SUBST([HAVE_CUDA],[-DHAVE_CUDA])]
				   [AC_SUBST(CUDA_LIBS, [-lcudart])])
				   ])]
     )
     if test "x$using_cuda" != xyes -a "x$enable_cuda" = xyes; then
	AC_MSG_FAILURE([Could not find all required CUDA components])
     fi
  fi
])

# @synopsis JTR_SET_OPENCL_INCLUDES
# @summary check and set many normal include paths
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
