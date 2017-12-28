dnl Redistribution and use in source or binary forms, with or without
dnl modification, are permitted.
dnl
dnl This file contains compiler flags specifically for MIC.

AC_DEFUN([JTR_MIC_SPECIAL_LOGIC], [
  CPU_BEST_FLAGS="-no-opt-prefetch $CPU_BEST_FLAGS"
])
