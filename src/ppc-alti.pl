#!/usr/bin/perl
#
# This file is part of John the Ripper password cracker,
# Copyright (c) 2005 by Solar Designer
#

%vec_ops = ("&", "and", "|", "or", "^", "xor");

while (<>) {
	s/unsigned long/altivec/;
	($r, $a, $op, $n, $b) =
		/^\t([\w\d]+) = ([\w\d]+) ([&|^]) (~*)([\w\d]+);$/;
	if (!$r) {
		($a, $op, $b) = /^\t(\*[\w\d]+) (\^)= ([\w\d]+);$/;
		$r = $a;
		undef $n;
	}
	$op = $vec_ops{$op};
	if ($n && $op eq "and") {
		$op = "andc";
	} elsif ($n && $op eq "xor") {
#		$b = "vec_nor($b, $b)";
		print "\t$r = vec_xor($a, $b);\n";
		$op = "nor";
		$a = $b = $r;
	} elsif ($n) {
		die;
	}
	$_ = "\t$r = vec_" . $op . "($a, $b);\n"
		if ($r && $a && $op && $b);
	print;
}
