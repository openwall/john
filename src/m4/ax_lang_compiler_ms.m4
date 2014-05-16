# And one inline. This one is needed by ax_opencl.m4 but has been replaced by
# generic macros. Rather than hack ax_opencl.m4 we include this here (the
# original has been obsoleted by AX_COMPILER_VENDOR or something like that)
AC_DEFUN([AX_LANG_COMPILER_MS],
[AC_CACHE_CHECK([whether we are using the Microsoft _AC_LANG compiler],
                [ax_cv_[]_AC_LANG_ABBREV[]_compiler_ms],
[AC_COMPILE_IFELSE([AC_LANG_PROGRAM([], [[#ifndef _MSC_VER
       choke me
#endif
]])],
                   [ax_compiler_ms=yes],
                   [ax_compiler_ms=no])
ax_cv_[]_AC_LANG_ABBREV[]_compiler_ms=$ax_compiler_ms
])])