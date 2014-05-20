# This file is Copyright (C) 2014 JimF, and magnum
# and is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modifications, are permitted.
#
# Here are contained numerous utility macros
#


# JTR_LIST_ADD(variable, value(s))
# Add space separated value(s) to variable unless already present.
AC_DEFUN([JTR_LIST_ADD], [
   if test "x$$1" = "x"; then
      $1="$(echo $2)"
   elif test -n "$(echo $2)"; then
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
         fi
      done
   fi
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
	[CFLAGS_EX+=" $1"]
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
   ADD_LDFLAGS+=" -L/usr/local/lib"
fi
if test -d /usr/local/include; then
   ADD_CFLAGS+=" -I/usr/local/include"
fi
if test -d /usr/local/ssl/lib; then
   ADD_LDFLAGS+=" -L/usr/local/ssl/lib"
fi
if test -d /usr/local/ssl/include; then
   ADD_CFLAGS+=" -I/usr/local/ssl/include"
fi
case "x${ADD_CFLAGS}x${ADD_LDFLAGS}" in
     "xx") cond_and="no" ;;
     "xx*") cond_and="" ;;
     "x*x") cond_and="" ;;
     *) cond_and=" and" ;;
esac
AC_MSG_RESULT([${ADD_CFLAGS}${cond_and}${ADD_LDFLAGS}])
JTR_LIST_ADD(LDFLAGS, "$ADD_LDFLAGS")
JTR_LIST_ADD(CFLAGS, "$ADD_CFLAGS")
JTR_LIST_ADD(CPPFLAGS, "$ADD_CFLAGS")dnl  NOT a typo
])

# @synopsis JTR_SET_CUDA_INCLUDES
# @summary check and set many normal include paths
AC_DEFUN([JTR_SET_CUDA_INCLUDES],
[
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
   ADD_CFLAGS+=" -I$CUDAPATH/include"
fi
if test $CPU_BIT_STR = 64 -a -d "$CUDAPATH/lib64"; then
   ADD_LDFLAGS+=" -L$CUDAPATH/lib64"
elif test -d "$CUDAPATH/lib"; then
   ADD_LDFLAGS+=" -L$CUDAPATH/lib"
fi
case "x${ADD_CFLAGS}x${ADD_LDFLAGS}" in
     "xx") cond_and="no" ;;
     "xx*") cond_and="" ;;
     "x*x") cond_and="" ;;
     *) cond_and=" and" ;;
esac
AC_MSG_RESULT([${ADD_CFLAGS}${cond_and}${ADD_LDFLAGS}])
JTR_LIST_ADD(LDFLAGS, "$ADD_LDFLAGS")
JTR_LIST_ADD(CFLAGS, "$ADD_CFLAGS")
JTR_LIST_ADD(CPPFLAGS, "$ADD_CFLAGS")dnl  NOT a typo
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
      ADD_CFLAGS+=" -I$AMDAPPSDKROOT/include"
   fi
   if test $CPU_BIT_STR = 64 -a -d "$AMDAPPSDKROOT/lib/x86_64" ; then
      ADD_LDFLAGS+=" -L$AMDAPPSDKROOT/lib/x86_64"
   elif test  $CPU_BIT_STR = 32 -a -d "$AMDAPPSDKROOT/lib/x86" ; then
      ADD_LDFLAGS+=" -L$AMDAPPSDKROOT/lib/x86"
   elif test -d "$AMDAPPSDKROOT/lib"; then
      ADD_LDFLAGS+=" -L$AMDAPPSDKROOT/lib"
   fi
fi
if test -n "$ATISTREAMSDKROOT"; then
   if test -d "$ATISTREAMSDKROOT/include"; then
      ADD_CFLAGS+=" -I$ATISTREAMSDKROOT/include"
   fi
   if test $CPU_BIT_STR = 64 -a -d "$ATISTREAMSDKROOT/lib/x86_64" ; then
      ADD_LDFLAGS+=" -L$ATISTREAMSDKROOT/lib/x86_64"
   elif test  $CPU_BIT_STR = 32 -a -d "$ATISTREAMSDKROOT/lib/x86" ; then
      ADD_LDFLAGS+=" -L$ATISTREAMSDKROOT/lib/x86"
   elif test -d "$ATISTREAMSDKROOT/lib"; then
      ADD_LDFLAGS+=" -L$ATISTREAMSDKROOT/lib"
   fi
fi
case "x${ADD_CFLAGS}x${ADD_LDFLAGS}" in
     "xx") cond_and="no" ;;
     "xx*") cond_and="" ;;
     "x*x") cond_and="" ;;
     *) cond_and=" and" ;;
esac
AC_MSG_RESULT([${ADD_CFLAGS}${cond_and}${ADD_LDFLAGS}])
JTR_LIST_ADD(LDFLAGS, "$ADD_LDFLAGS")
JTR_LIST_ADD(CFLAGS, "$ADD_CFLAGS")
JTR_LIST_ADD(CPPFLAGS, "$ADD_CFLAGS")dnl  NOT a typo
])
