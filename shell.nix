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
# environment variable to be set. If you wish to create your shell with free software
# only, then you can remove 'intel-ocl' entry from 'nativeBuildInputs' below. Please
# note however if you are running and intel based system and remove intel-ocl then
# you will not have opencl support when building openwall/john. For the avoidance of
# doubt, this file does not contain any unfree software.
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
	]);
in
pkgs.mkShell {
	nativeBuildInputs = with pkgs.buildPackages;
		[
			openssl libzip rocm-opencl-runtime opencl-headers
			bzip2 libpcap libgmpris libxcrypt gmp intel-ocl
			gcc zlib nss nspr libkrb5 re2 makeWrapper
			perlEnv pythonEnv
		];
	shellHook = ''
		export AS=$CC
		export LD=$CC
	'';
}

