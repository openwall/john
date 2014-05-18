# This file is Copyright (C) 2014 JimF, and magnum
# and is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modifications, are permitted.
#
# Here are contained numerous utility macros
#


# @synopsis AC_JTR_FLAG_CHECK [compiler flags]
# @summary check whether compiler supports given
#          C flags or not. The var CFLAGS_EX is
#          added to with each 'valid' command.
AC_DEFUN([AC_JTR_FLAG_CHECK],
[dnl
  AC_MSG_CHECKING([if $CC supports $1])
  AC_LANG_PUSH([C])
  ac_saved_cflags="$CFLAGS"
  CFLAGS="-Werror $1"
  AC_COMPILE_IFELSE([AC_LANG_PROGRAM([])],
    [AC_MSG_RESULT([yes])]
	[CFLAGS_EX+=" $1"]
    ,[AC_MSG_ERROR([no])]
  )
  CFLAGS="$ac_saved_cflags"
  AC_LANG_POP([C])
])

# @synopsis SET_NORMAL_INCLUDES
# @summary check and set many normal include paths
AC_DEFUN([AC_JTR_SET_NORMAL_INCLUDES],
[[
if test -d /usr/local/lib; then
   LDFLAGS+=" -L/usr/local/lib"
fi
if test -d /usr/local/include; then
   CFLAGS+=" -I/usr/local/include"
fi
if test -d /usr/local/ssl/lib; then
   LDFLAGS+=" -L/usr/local/ssl/lib"
fi
if test -d /usr/local/ssl/include; then
   CFLAGS+=" -I/usr/local/ssl/include"
fi
]])

# @synopsis AC_JTR_SET_CUDA_INCLUDES
# @summary check and set many normal include paths
AC_DEFUN([AC_JTR_SET_CUDA_INCLUDES],
[[
if test -z "$NVIDIA_CUDA"; then
   NVIDIA_CUDA=/usr/local/cuda
fi
if test -d "$NVIDIA_CUDA/include"; then
   CFLAGS+=" -I$NVIDIA_CUDA/include"
fi
if test $CPU_BIT_STR = 64 -a -d "$NVIDIA_CUDA/lib64"; then
   LDFLAGS+=" -L$NVIDIA_CUDA/lib64"
elif test -d "$NVIDIA_CUDA/lib"; then
   LDFLAGS+=" -L$NVIDIA_CUDA/lib"
fi
]])

# @synopsis AC_JTR_SET_OPENCL_INCLUDES
# @summary check and set many normal include paths
AC_DEFUN([AC_JTR_SET_OPENCL_INCLUDES],
[[
if test -n "$AMDAPPSDKROOT"; then
   if test -d "$AMDAPPSDKROOT/include"; then
      CFLAGS+=" -I$AMDAPPSDKROOT/include"
   fi
   if test $CPU_BIT_STR = 64 -a -d "$AMDAPPSDKROOT/lib/x86_64" ; then
      LDFLAGS+=" -L$AMDAPPSDKROOT/lib/x86_64"
   elif test  $CPU_BIT_STR = 32 -a -d "$AMDAPPSDKROOT/lib/x86" ; then
      LDFLAGS+=" -L$AMDAPPSDKROOT/lib/x86"
   elif test -d "$AMDAPPSDKROOT/lib"; then
      LDFLAGS+=" -L$AMDAPPSDKROOT/lib"
   fi
fi
if test -n "$ATISTREAMSDKROOT"; then
   if test -d "$ATISTREAMSDKROOT/include"; then
      CFLAGS+=" -I$ATISTREAMSDKROOT/include"
   fi
   if test $CPU_BIT_STR = 64 -a -d "$ATISTREAMSDKROOT/lib/x86_64" ; then
      LDFLAGS+=" -L$ATISTREAMSDKROOT/lib/x86_64"
   elif test  $CPU_BIT_STR = 32 -a -d "$ATISTREAMSDKROOT/lib/x86" ; then
      LDFLAGS+=" -L$ATISTREAMSDKROOT/lib/x86"
   elif test -d "$ATISTREAMSDKROOT/lib"; then
      LDFLAGS+=" -L$ATISTREAMSDKROOT/lib"
   fi
fi
]])
