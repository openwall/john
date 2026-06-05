# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# There's ABSOLUTELY NO WARRANTY, express or implied.
# -------------------------------------------------------------------------------
# Nix shells are used create development environments which provide the necessary
# tools/dependencies to develop/build software. The environment is typically
# declared in a shell.nix file in the softwares root directory.
#
# To create the nix-shell, run: `nix-shell ./shell.nix`.
#
# This will place you in a development shell with the minimum required dependencies
# to build openwall/john with opencl support.
#
# NOTE: the 'Official OpenCL runtime for Intel CPUs' is unfree software and
# therefore, when invoking this shell, nix will require the $NIXPKGS_ALLOW_UNFREE=1
# environment variable to be set. If you wish to create your shell with it,
# then you can add 'intel-ocl' entry to 'nativeBuildInputs' below.
#
# Add 'rocm-opencl-runtime' entry to 'nativeBuildInputs' below for AMD GPU support.
# The 'ocl-icd' entry is used by default and should suffice in most cases.
#
# More information about Nixos: https://nixos.org/
# More information about nix-shell: https://nixos.org/manual/nix/stable/command-ref/nix-shell.html
#
# Copyright Jack Bizzell (lambdajack) 2023

{ pkgs ? import <nixpkgs> {} }:
let
	perlEnv = pkgs.perl.withPackages (p: with p; [
		CompressRawLzma
		DigestMD4
		DigestSHA1
		GetoptLong
		perlldap
	]);
	pythonEnv = pkgs.python3.withPackages(p: with p; [
		dpkt
		scapy
		lxml
		wrapPython
		olefile
	]);
in
pkgs.mkShell {
    LD_LIBRARY_PATH= pkgs.lib.makeLibraryPath [
      pkgs.ocl-icd
    ];
	nativeBuildInputs = with pkgs.buildPackages;
		[
			openssl libzip opencl-headers ocl-icd clinfo
			bzip2 libpcap libgmpris libxcrypt gmp
			gcc zlib nss nspr libkrb5 re2 makeWrapper
			perlEnv pythonEnv
		];
	shellHook = ''
		export AS=$CC
		export LD=$CC
	'';
}
