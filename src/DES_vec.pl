#!/usr/bin/perl
#
# This file is part of John the Ripper password cracker,
# Copyright (c) 2005,2010 by Solar Designer
#
# This script has been used to convert Matthew Kwan's sboxes.c and nonstd.c
# files to use cpp macros instead of explicit C operators for bitwise ops.
# This allows DES_bs_b.c to use compiler intrinsics for SIMD bitwise ops.
#

%vec_ops = ("&", "and", "|", "or", "^", "xor");

while (<>) {
	s/unsigned long/vtype/;
	($r, $a, $op, $n, $b) =
		/^\t*([\w\d]+) *= *([\w\d]+) *([&|^]) *\(*(~*)([\w\d]+)\)*;$/;
	if (!$r) {
		($a, $op, $b) = /^\t*(\*[\w\d]+) *(\^)= *([\w\d]+);$/;
		$r = $a;
		undef $n;
	}
	if (!$r) {
		($r, $n, $a) = /^\t*([\w\d]+) *= *(~*)([\w\d]+);$/;
	}
	$op = $vec_ops{$op};
	if ($n && !$op) {
		$_ = "\tvnot($r, $a);\n"
	} elsif ($n && $op eq "and") {
		$op = "andn";
	} elsif ($n && $op eq "xor") {
		$op = "xorn";
	} elsif ($n) {
		die;
	}
	$_ = "\tv" . $op . "($r, $a, $b);\n"
		if ($r && $a && $op && $b);
	print;
}
