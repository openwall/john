#!/bin/bash -e

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

function do_Copy_Dlls(){
    echo
    echo '-- Copying Dlls --'

    basepath="/usr/$TARGET_ARCH-w64-mingw32/sys-root/mingw/bin"

    cp "$basepath"/libgomp-1.dll ../run
    cp "$basepath"/libgmp-10.dll ../run
    cp "$basepath"/libbz2-1.dll ../run
    cp "$basepath"/libwinpthread-1.dll ../run
    cp "$basepath"/zlib1.dll ../run
    cp "$basepath"/libcrypto-1*.dll ../run
    cp "$basepath"/libssl-1*.dll ../run
    cp "$basepath"/libgcc_s_seh-1.dll ../run
    echo '-- Done --'
}

# ----------- BUILD -----------
cd src

# Setup testing environment
JTR=../run/john

# Control System Information presentation
if [[ $2 == "TEST" ]]; then
    MUTE_SYS_INFO="Yes"
fi
TASK_RUNNING="$2"
wget https://raw.githubusercontent.com/claudioandre-br/JtR-CI/master/tests/show_info.sh
source show_info.sh

# Build and testing
if [[ $2 == "BUILD" ]]; then

    if [[ -n $WINE ]]; then
        do_Copy_Dlls
        export WINEDEBUG=-all
    fi

    if [[ $TARGET_ARCH == "x86_64" ]]; then
        ./configure --host=x86_64-w64-mingw32 --build=x86_64-redhat-linux-gnu --target=x86_64-w64-mingw64 CPPFLAGS="-g -gdwarf-2"
    fi

    if [[ $TARGET_ARCH == *"NIX"* || $TARGET_ARCH == *"ARM"* ]]; then
        ./configure $ASAN $BUILD_OPTS #TODO re-enable wError ./configure --enable-werror $ASAN $BUILD_OPTS
    fi

    if [[ $TARGET_ARCH == "x86_64" || $TARGET_ARCH == *"NIX"* ]]; then
        # Build
        make -sj4

        echo
        echo '-- Build Info --'
        $WINE $JTR --list=build-info
    fi

elif [[ $2 == "TEST" ]]; then

    if [[ -n $WINE ]]; then
        do_Copy_Dlls
        export WINEDEBUG=-all
    fi
    # Required defines
    TEST=";$EXTRA;" # Controls how the test will happen
    arch=$(uname -m)
    JTR_BIN="$WINE $JTR"
    JTR_CL=""

    if [[ $TARGET_ARCH == "DOCKER" ]]; then
        JTR_BIN="/john/run/john-sse2"
    fi

    wget https://raw.githubusercontent.com/claudioandre-br/JtR-CI/master/tests/run_tests.sh
    source run_tests.sh
fi

