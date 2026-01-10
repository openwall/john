#!/bin/sh -ex
#
# Copyright (c) 2018-2020 The strace developers.
# All rights reserved.
#
# SPDX-License-Identifier: GPL-2.0-or-later

j=-j`nproc` || j=
type sudo >/dev/null 2>&1 && sudo=sudo || sudo=
common_packages='make libssl-dev libpcap-dev'

retry_if_failed()
{
	for i in `seq 0 99`; do
		"$@" && i= && break || sleep 1
	done
	[ -z "$i" ]
}

updated=
apt_get_install()
{
	[ -n "$updated" ] || {
		retry_if_failed $sudo apt-get -qq update
		updated=1
	}
	retry_if_failed $sudo \
		apt-get -qq --no-install-suggests --no-install-recommends \
		install -y "$@"
}

git_installed=
clone_repo()
{
	local src dst branch
	src="$1"; shift
	dst="$1"; shift
	branch="${1-}"

	[ -n "$git_installed" ] || {
		apt_get_install git ca-certificates
		git_installed=1
	}

	case "$src" in
		*://*)	;;
		*)	local url path
			url="$(git config remote.origin.url)"
			path="${url#*://*/}"
			src="${url%$path}$src"
			;;
	esac

	retry_if_failed \
		git clone --depth=1 ${branch:+--branch $branch} "$src" "$dst"
}

case "$TARGET" in
	x32|x86)
		packages="$common_packages gcc-multilib"
		;;
	*)
		packages="$common_packages gcc"
		;;
esac

case "$CC" in
	gcc-*)
		retry_if_failed \
			$sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
		case "$TARGET" in
			x32|x86)
				apt_get_install $packages "$CC"-multilib "$CC"
				;;
			*)
				apt_get_install $packages "$CC"
				;;
		esac
		;;
	clang*)
		apt_get_install $packages "$CC"
		;;
	*)
		apt_get_install $packages
		;;
esac
