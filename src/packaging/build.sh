######################################################################
# Copyright (c) 2019 Claudio André <claudioandre.br at gmail.com>
#
# This program comes with ABSOLUTELY NO WARRANTY; express or implied.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, as expressed in version 2, seen at
# http://www.gnu.org/licenses/gpl-2.0.html
######################################################################

#!/usr/bin/bash

# Build options (system wide, disable checks, etc.)
SYSTEM_WIDE='--with-systemwide --enable-rexgen'
X86_REGULAR="--disable-native-tests --disable-opencl $SYSTEM_WIDE"
X86_NO_OPENMP="--disable-native-tests --disable-opencl $SYSTEM_WIDE --disable-openmp"

OTHER_REGULAR="$SYSTEM_WIDE"
OTHER_NO_OPENMP="$SYSTEM_WIDE --disable-openmp"

# Build helper
function do_build () {
    set -e

    if [[ -n "$1" ]]; then
        make -s clean && make -sj4 && mv ../run/john "$1"
    else
        make -s clean && make -sj4
    fi
    set +e
}

#if (Build); then
    echo ""
    echo "---------------------------- BUILDING -----------------------------"

    if [[ "$(uname -m)" == "x86_64" || "$(uname -m)" == "i386" || "$(uname -m)" == "i686" ]]; then
        # CPU (OMP and extensions fallback)
        ./configure $X86_NO_OPENMP CPPFLAGS="-D_BOXED" && do_build ../run/john-sse2-non-omp
        ./configure $X86_REGULAR   CPPFLAGS="-D_BOXED -DOMP_FALLBACK -DOMP_FALLBACK_BINARY=\"\\\"john-sse2-non-omp\\\"\"" && do_build ../run/john-sse2
        ./configure $X86_NO_OPENMP CPPFLAGS="-D_BOXED -mavx" && do_build ../run/john-avx-non-omp
        ./configure $X86_REGULAR   CPPFLAGS="-D_BOXED -mavx -DOMP_FALLBACK -DOMP_FALLBACK_BINARY=\"\\\"john-avx-non-omp\\\"\" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY=\"\\\"john-sse2\\\"\"" && do_build ../run/john-avx
        ./configure $X86_NO_OPENMP CPPFLAGS="-D_BOXED -mxop" && do_build ../run/john-xop-non-omp
        ./configure $X86_REGULAR   CPPFLAGS="-D_BOXED -mxop -DOMP_FALLBACK -DOMP_FALLBACK_BINARY=\"\\\"john-xop-non-omp\\\"\" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY=\"\\\"john-avx\\\"\"" && do_build ../run/john-xop
        ./configure $X86_NO_OPENMP CPPFLAGS="-D_BOXED -mavx2" && do_build ../run/john-non-omp
        ./configure $X86_REGULAR   CPPFLAGS="-D_BOXED -mavx2 -DOMP_FALLBACK -DOMP_FALLBACK_BINARY=\"\\\"john-non-omp\\\"\" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY=\"\\\"john-xop\\\"\"" && do_build
    else
        # Non X86 CPU
        ./configure $OTHER_NO_OPENMP CPPFLAGS="-D_BOXED" && do_build ../run/john-non-omp
        ./configure $OTHER_REGULAR   CPPFLAGS="-D_BOXED -DOMP_FALLBACK -DOMP_FALLBACK_BINARY=\"\\\"john-non-omp\\\"\"" && do_build
    fi
#Done
# Remove unused stuff
rm -rf ../run/ztex
