dnl Redistribution and use in source or binary forms, with or without
dnl modification, are permitted.
dnl
dnl This file contains compiler and linker flags specifically for MIC.

AC_DEFUN([JTR_MIC_SPECIAL_LOGIC], [
# missing flags when configuring for MIC
LIBS="-lssl -lcrypto $LIBS"

# specific optimization flags for MIC
CPU_BEST_FLAGS="-no-opt-prefetch $CPU_BEST_FLAGS"
])
