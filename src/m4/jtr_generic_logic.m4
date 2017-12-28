dnl This file is Copyright (C) 2014 magnum,
dnl and is hereby released to the general public under the following terms:
dnl Redistribution and use in source and binary forms, with or without
dnl modifications, are permitted.
dnl
dnl All tests in this file are supposed to be cross compile compliant
dnl
AC_DEFUN([JTR_GENERIC_LOGIC], [
CC_BACKUP=$CC

dnl Check for -march=native and add it to CPU_BEST_FLAGS
if test "x$enable_native_march" != xno -a "x$osx_assembler_warn" != xyes; then
  AC_MSG_CHECKING([whether compiler understands -march=native])
  CC="$CC_BACKUP -march=native"
  AC_LINK_IFELSE(
    [AC_LANG_SOURCE([int main() { return 0; }])],
    [AC_MSG_RESULT(yes)]
    [CPU_BEST_FLAGS="-march=native $CPU_BEST_FLAGS"],
    [AC_MSG_RESULT(no)]
    dnl or -xarch=native64
    [AC_MSG_CHECKING([whether compiler understands -xarch=native64])
     CC="$CC_BACKUP -xarch=native64"
     AC_LINK_IFELSE(
       [AC_LANG_SOURCE([int main() { return 0; }])],
       [AC_MSG_RESULT(yes)]
       [CPU_BEST_FLAGS="-xarch=native64 $CPU_BEST_FLAGS"],
       [AC_MSG_RESULT(no)]
       dnl or -xarch=native
       [AC_MSG_CHECKING([whether compiler understands -xarch=native])
  CC="$CC_BACKUP -xarch=native"
  AC_LINK_IFELSE(
    [AC_LANG_SOURCE([int main() { return 0; }])],
    [AC_MSG_RESULT(yes)]
    [CPU_BEST_FLAGS="-xarch=native $CPU_BEST_FLAGS"],
    [AC_MSG_RESULT(no)]
    dnl or "-arch host"
    [AC_MSG_CHECKING([whether compiler understands -arch host])
     CC="$CC_BACKUP -arch host"
     AC_LINK_IFELSE(
       [AC_LANG_SOURCE([int main() { return 0; }])],
       [AC_MSG_RESULT(yes)]
       [CPU_BEST_FLAGS="-arch host $CPU_BEST_FLAGS"],
       [AC_MSG_RESULT(no)]
     )
    ]
  )
       ]
     )
    ]
  )
  CC="$CC_BACKUP"
fi

dnl At this point we know the arch and CPU width so we can pick details. Most
dnl "special stuff" from old fat Makefile should go here.
case "${host_cpu}_${CFLAGS}" in
   x86_64_*)
      case "${CPPFLAGS}_${CFLAGS}" in
        *-mno-sse2*) ;;
        *-mno-mmx*) ;;
        *)
          AS_IF([test -n "$SIMD_NAME" -o $simd != no],
            [CC_ASM_OBJS="x86-64.o simd-intrinsics.o"])
          ;;
      esac
   ;;
   i?86_*)
      if test "y$ARCH_LINK" = "yx86-any.h"; then
        [CC_ASM_OBJS="x86.o"]
      elif test "y$ARCH_LINK" = "yx86-mmx.h"; then
        [CC_ASM_OBJS="x86.o x86-mmx.o"]
      else
        [CC_ASM_OBJS="x86.o x86-sse.o simd-intrinsics.o"]
      fi
   ;;
   mic*|powerpc*|arm*|aarch64*)
      AS_IF([test -n "$SIMD_NAME" -o $simd != no],
        [CC_ASM_OBJS="simd-intrinsics.o"])
      ;;
   alpha*dec*)
      [CC_ASM_OBJS="digipaq-alpha.o"]
      ;;
   alpha*)
      [CC_ASM_OBJS="alpha.o"]
      ;;
esac

CC="$CC_BACKUP"
CFLAGS="$CFLAGS_BACKUP"
])
