#!/bin/bash -e

function do_Copy_Dlls(){
    echo
    echo '-- Copying Dlls --'

    basepath="/usr/$TARGET_ARCH-w64-mingw32/sys-root/mingw/bin"

    cp "$basepath/libgomp-1.dll" ../run
    cp "$basepath/libgmp-10.dll" ../run
    cp "$basepath/libbz2-1.dll" ../run
    cp "$basepath/libwinpthread-1.dll" ../run
    cp "$basepath/zlib1.dll" ../run
    cp "$basepath/libcrypto-10.dll" ../run
    cp "$basepath/libssl-10.dll" ../run

    if [[ "$TARGET_ARCH" == "x86_64" ]]; then
        cp "$basepath/libgcc_s_seh-1.dll" ../run
    fi

    if [[ "$TARGET_ARCH" == "i686" ]]; then
        cp "$basepath/libgcc_s_sjlj-1.dll" ../run
    fi
    echo '-- Done --'
}

# ----------- BUILD -----------
cd src

# Setup testing environment
JTR=../run/john

# Build and testing
if [[ $1 == "BUILD" ]]; then

    if [[ -n $WINE ]]; then
        do_Copy_Dlls
        export WINEDEBUG=-all
    fi
env
    if [[ "$TARGET_ARCH" == "i686" ]]; then
        ./configure --host=i686-w64-mingw32 --build=i686-redhat-linux-gnu --target=i686-w64-mingw32
    fi

    if [[ "$TARGET_ARCH" == "x86_64" ]]; then
        ./configure --host=x86_64-w64-mingw32 --build=x86_64-redhat-linux-gnu --target=x86_64-w64-mingw64
    fi

    if [[ -z "$WINE" ]]; then
        ./configure --enable-werror $BUILD_OPTS
    fi
    # Build
    make -sj4

    echo
    echo '-- Build Info --'
    $WINE $JTR --list=build-info

elif [[ $1 == "TEST" && -n "$WINE" ]]; then
    echo '-- Build Info --'
    $WINE $JTR --list=build-info

    if [[ -n $WINE ]]; then
        do_Copy_Dlls
        export WINEDEBUG=-all
    fi
    echo
    echo '-- Testing JtR --test=0 --'
    $WINE $JTR --test=0

elif [[ $1 == "TEST" && -n "$ENCODING_TEST" ]]; then
    echo "-- Testing JTR -test-full=0 $ENCODING_TEST '--encoding=utf8' --"
    $JTR -test-full=0 --format="$ENCODING_TEST" --encoding=utf8

    echo
    echo "-- Testing JTR -test-full=0 $ENCODING_TEST '--encoding=cp737' --"
    $JTR -test-full=0 --format="$ENCODING_TEST" --encoding=cp737

elif [[ $1 == "TEST" && -n "$ASAN_TEST" ]]; then
    echo "-- Testing JTR -test-full=0 --"
    $JTR -test-full=0
fi

