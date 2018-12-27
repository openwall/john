#!/usr/bin/env perl
#
# Evaluate truth table for _mm512_ternarylogic_epi32 or LOP3.LUT
#
# Copyright (c) 2015, magnum
# This software is hereby released to the general public under
# the following terms: Redistribution and use in source and binary
# forms, with or without modification, are permitted.
#
# Example:
# $ ./truth.pl '((x | ~y) ^ z)'
# lut3(x, y, z, 0x59)  ==  ((x | ~y) ^ z)

use warnings;
use strict;

my $f;

if (defined($ARGV[0]) && $#ARGV == 0 && !($ARGV[0] =~ m/a-wA-Z/) &&
	$ARGV[0] =~ m/x/ && $ARGV[0] =~ m/y/ && $ARGV[0] =~ m/z/) {
	$f = $ARGV[0];
} else {
	print "\nEvaluate truth table for eg. _mm512_ternarylogic_epi32 or LOP3.LUT\n\n";
	die "Usage: $0 <formula written with x, y and z>\n\nExample:\n$0 '(x & y ^ z)'\n";
}

my $orig_f = $f;
$f = "(" . $f . ")";
$f =~ s/ //g;
$f =~ s/([^\$])([xyz])/$1\$$2/g;
$f =~ s/~(\([^\)]*\))/(~$1 & 1)/g;
$f =~ s/~(\$[xyz])/((~$1) & 1)/g;

my $r = 0;
foreach my $i (0..7) {
	my $x = ($i >> 2) & 0x1;
	my $y = ($i >> 1) & 0x1;
	my $z = ($i >> 0) & 0x1;
	#print "$x $y $z = ", eval($f), "\n";
	$r |= eval($f) << $i;
}
printf("lut3(x, y, z, 0x%02x)  ==  %s\n", $r, $orig_f);

if (1) {
	print "\nAlternatives (different order of operands):\n";
	$r = 0;
	foreach my $i (0..7) {
		my $x = ($i >> 2) & 0x1;
		my $z = ($i >> 1) & 0x1;
		my $y = ($i >> 0) & 0x1;
		#print "$x $y $z = ", eval($f), "\n";
		$r |= eval($f) << $i;
	}
	printf("lut3(x, z, y, 0x%02x)\n", $r);

	$r = 0;
	foreach my $i (0..7) {
		my $y = ($i >> 2) & 0x1;
		my $x = ($i >> 1) & 0x1;
		my $z = ($i >> 0) & 0x1;
		#print "$x $y $z = ", eval($f), "\n";
		$r |= eval($f) << $i;
	}
	printf("lut3(y, x, z, 0x%02x)\n", $r);

	$r = 0;
	foreach my $i (0..7) {
		my $y = ($i >> 2) & 0x1;
		my $z = ($i >> 1) & 0x1;
		my $x = ($i >> 0) & 0x1;
		#print "$x $y $z = ", eval($f), "\n";
		$r |= eval($f) << $i;
	}
	printf("lut3(y, z, x, 0x%02x)\n", $r);

	$r = 0;
	foreach my $i (0..7) {
		my $z = ($i >> 2) & 0x1;
		my $x = ($i >> 1) & 0x1;
		my $y = ($i >> 0) & 0x1;
		#print "$x $y $z = ", eval($f), "\n";
		$r |= eval($f) << $i;
	}
	printf("lut3(z, x, y, 0x%02x)\n", $r);

	$r = 0;
	foreach my $i (0..7) {
		my $z = ($i >> 2) & 0x1;
		my $y = ($i >> 1) & 0x1;
		my $x = ($i >> 0) & 0x1;
		#print "$x $y $z = ", eval($f), "\n";
		$r |= eval($f) << $i;
	}
	printf("lut3(z, y, x, 0x%02x)\n", $r);
}
