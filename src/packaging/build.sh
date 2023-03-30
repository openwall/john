######################################################################
# Copyright (c) 2019-2023 Claudio André <claudioandre.br at gmail.com>
#
# This program comes with ABSOLUTELY NO WARRANTY; express or implied.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, as expressed in version 2, seen at
# http://www.gnu.org/licenses/gpl-2.0.html
######################################################################

#!/bin/bash

# Build options (system wide, disable checks, etc.)
SYSTEM_WIDE='--with-systemwide --enable-rexgen'
X86_REGULAR="--disable-native-tests --disable-opencl $SYSTEM_WIDE"
X86_NO_OPENMP="--disable-native-tests --disable-opencl $SYSTEM_WIDE --disable-openmp"

OTHER_REGULAR="$SYSTEM_WIDE"
OTHER_NO_OPENMP="$SYSTEM_WIDE --disable-openmp"

arch=$(uname -m)

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

    # For all intents and purposes, 32 bits X86 is deprecated these days
    if [[ "$arch" == "x86_64" || "$arch" == "i386" || "$arch" == "i686" ]]; then
        # x86_64 CPU (OMP and SIMD fallback)
        ./configure $X86_NO_OPENMP --enable-simd=sse2   CPPFLAGS="-D_BOXED" && do_build ../run/john-sse2
        ./configure $X86_REGULAR   --enable-simd=sse2   CPPFLAGS="-D_BOXED -DOMP_FALLBACK -DOMP_FALLBACK_BINARY=\"\\\"john-sse2\\\"\"" && do_build ../run/john-sse2-omp
        ./configure $X86_NO_OPENMP --enable-simd=avx    CPPFLAGS="-D_BOXED" && do_build ../run/john-avx
        ./configure $X86_REGULAR   --enable-simd=avx    CPPFLAGS="-D_BOXED -DOMP_FALLBACK -DOMP_FALLBACK_BINARY=\"\\\"john-avx\\\"\" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY=\"\\\"john-sse2-omp\\\"\"" && do_build ../run/john-avx-omp
        ./configure $X86_NO_OPENMP --enable-simd=xop    CPPFLAGS="-D_BOXED" && do_build ../run/john-xop
        ./configure $X86_REGULAR   --enable-simd=xop    CPPFLAGS="-D_BOXED -DOMP_FALLBACK -DOMP_FALLBACK_BINARY=\"\\\"john-xop\\\"\" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY=\"\\\"john-avx-omp\\\"\"" && do_build ../run/john-xop-omp
        ./configure $X86_NO_OPENMP --enable-simd=avx2   CPPFLAGS="-D_BOXED" && do_build ../run/john-avx2
        ./configure $X86_REGULAR   --enable-simd=avx2   CPPFLAGS="-D_BOXED -DOMP_FALLBACK -DOMP_FALLBACK_BINARY=\"\\\"john-avx2\\\"\" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY=\"\\\"john-xop-omp\\\"\"" && do_build ../run/john-avx2-omp
        ./configure $X86_NO_OPENMP --enable-simd=avx512f  CPPFLAGS="-D_BOXED" && do_build ../run/john-avx512f
        ./configure $X86_REGULAR   --enable-simd=avx512f  CPPFLAGS="-D_BOXED -DOMP_FALLBACK -DOMP_FALLBACK_BINARY=\"\\\"john-avx512f\\\"\" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY=\"\\\"john-avx2-omp\\\"\"" && do_build ../run/john-avx512f-omp
        ./configure $X86_NO_OPENMP --enable-simd=avx512bw CPPFLAGS="-D_BOXED" && do_build ../run/john-avx512bw
        ./configure $X86_REGULAR   --enable-simd=avx512bw CPPFLAGS="-D_BOXED -DOMP_FALLBACK -DOMP_FALLBACK_BINARY=\"\\\"john-avx512bw\\\"\" -DCPU_FALLBACK -DCPU_FALLBACK_BINARY=\"\\\"john-avx512f-omp\\\"\"" && do_build ../run/john-avx512bw-omp

        #Create a 'john' executable
        ln -s ../run/john-avx512bw-omp ../run/john
    else
        # Non X86 CPU (OMP fallback)
        # Use $arch in the name (avoid to use "no" as in "john-no-omp")
        # Note that "john" is an alias for john-omp
        ./configure $OTHER_NO_OPENMP   CPPFLAGS="-D_BOXED" && do_build "../run/john-$arch"
        ./configure $OTHER_REGULAR     CPPFLAGS="-D_BOXED -DOMP_FALLBACK -DOMP_FALLBACK_BINARY=\"\\\"john-$arch\\\"\"" && do_build ../run/john-omp

        #Create a 'john' executable
        ln -s ../run/john-omp ../run/john
    fi
#Done
# Remove unused stuff
rm -rf ../run/ztex

# Save information about how the binaries were built
# Everything that is not enabled by default in the list below must be appended
#  to the binary name
echo "[Build Configuration]" > ../run/Defaults
echo "Architecture=$arch" >> ../run/Defaults
echo "OpenMP=No" >> ../run/Defaults
echo "OpenCL=?" >> ../run/Defaults                # Nice to be available by default
echo "Optional Libraries=Yes" >> ../run/Defaults  # Important to be enabled by default
echo "Regex=?" >> ../run/Defaults
echo "OpenMPI=No" >> ../run/Defaults                   # Probably a bad idea in a general purpose package
echo "Experimental Code, ZTEX=No" >> ../run/Defaults   # Probably a bad idea in a general purpose package
