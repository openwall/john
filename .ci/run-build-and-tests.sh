#!/bin/sh -ex
#
# Copyright (c) 2018-2020 The strace developers.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later

case "${TARGET-}" in
	x32)
		CC="$CC -mx32"
		;;
	x86)
		CC="$CC -m32"
		;;
esac

echo 'BEGIN OF BUILD ENVIRONMENT INFORMATION'
uname -a |head -1
libc="$(ldd /bin/sh |sed -n 's|^[^/]*\(/[^ ]*/libc\.so[^ ]*\).*|\1|p' |head -1)"
$libc |head -1
file -L /bin/sh
$CC --version |head -1
$CC -print-multi-lib ||:
make --version |head -1
kver="$(printf '%s\n%s\n' '#include <linux/version.h>' 'LINUX_VERSION_CODE' | $CC $CPPFLAGS -E -P -)"
printf 'kernel-headers %s.%s.%s\n' $(($kver/65536)) $(($kver/256%256)) $(($kver%256))
echo 'END OF BUILD ENVIRONMENT INFORMATION'

nproc="$(nproc)" || nproc=1
j="-j$nproc"

if [ $nproc -gt 2 ]; then
	export OMP_NUM_THREADS=2
fi

cd src
time ./configure $*
time make $j
time make $j check
if [ "$1" = "--enable-fuzz" ]; then
	time ../run/john --fuzz=500
fi

if git status --porcelain |grep ^.; then
	echo >&2 'git status reported uncleanness'
	exit 1
fi
