#!/usr/bin/perl -w
#
# This software is Copyright (c) 2012 magnum, and it is hereby
# released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

use strict;

die unless $#ARGV == 4;
my ($cc, $make, $depend, $extra_cflags, $arch_size) = @ARGV;

my %res;
my $time;

if ($^O eq 'MSWin32') {
    $time = 5;	# Windows has lousy timer resolution
    $extra_cflags .= " -DUNDERSCORES";
} else {
    $time = 1
}

my %formNum;
$formNum{"md5c"} = 2;
$formNum{"md4"} = 4;
$formNum{"md5"} = 5;
$formNum{"sha1"} = 6;

if ($arch_size eq "32") {
    `rm -f $depend para-bench`;
    print STDERR "\nCompiling assembler (4x) benchmarks\n";
    `JOHN_CFLAGS="$extra_cflags -DJOHN_DISABLE_INTRINSICS" $make >/dev/null para-bench${arch_size}`;
    foreach my $format (qw(md4 md5 md5c sha1)) {
	$res{$format}{"asm 4x80"} = `./para-bench $formNum{$format} $time`;
    }
}

foreach my $format (qw(md4 md5 sha1)) {
    if ($format eq "sha1") {
	foreach my $shabuf (16,80) {
	    my $para = 0;
	    do {
		my $sha1p = ++$para;
		`rm -f $depend para-bench`;
		printf STDERR "\nCompiling $format [${shabuf}x4] intrinsics benchmarks with PARA %u (%ux)\n", $para, $para * 4;
		`JOHN_CFLAGS="$extra_cflags -DMD4_SSE_PARA=1 -DMD5_SSE_PARA=1 -DSHA1_SSE_PARA=$sha1p -DSHA_BUF_SIZ=$shabuf" $make >/dev/null para-bench${arch_size}`;
		$res{$format}{"para_".$para." 4x".$shabuf} = `./para-bench $formNum{$format} $time`;
	    } while (($para < 2) || $res{$format}{"para_".$para." 4x".$shabuf} > $res{$format}{"para_".($para-1)." 4x".$shabuf});
	    delete $res{$format}{"para_".$para." 4x".$shabuf};
	}
    } else {
	my $para = 0;
	do {
	    `rm -f $depend para-bench`;
	    printf STDERR "\nCompiling $format intrinsics benchmarks with PARA %u (%ux)\n", ++$para, $para * 4;
	    if ($format eq "md4") {
		`JOHN_CFLAGS="$extra_cflags -DMD4_SSE_PARA=$para -DMD5_SSE_PARA=1 -DSHA1_SSE_PARA=1 -DSHA_BUF_SIZ=16" $make >/dev/null para-bench${arch_size}`;
	    } else {
		`JOHN_CFLAGS="$extra_cflags -DMD4_SSE_PARA=1 -DMD5_SSE_PARA=$para -DSHA1_SSE_PARA=1 -DSHA_BUF_SIZ=16" $make >/dev/null para-bench${arch_size}`;
	    }
	    $res{$format}{"para_".$para} = `./para-bench $formNum{$format} $time`;
	    if ($format eq "md5") {
		$res{"md5c"}{"para_".$para} = `./para-bench $formNum{"md5c"} $time`;
	    }
	} while (($para < 2) || $res{$format}{"para_".$para} > $res{$format}{"para_".($para-1)});
	delete $res{$format}{"para_".$para};
    }
}

sub pretty {
    my $in = shift;
    if ($in > 1000000) {
	return sprintf("%uK c/s", $in/10000);
    } elsif ($in > 1000) {
	return sprintf("%u c/s", $in/10);
    }
    return sprintf("%f c/s", $in/10);
}

print "======================================================\n";
if ( -f "/proc/cpuinfo" ) {
    print `grep -m1 "^model name" /proc/cpuinfo`;
}
print "gcc \"$cc\" version: ", `$cc -v 2>&1 | grep -m1 \"version \"`;
print "Best -m$arch_size paras:\n";
foreach my $f (qw(md4 md5 md5c sha1)) {
    print uc($f), ":\t";
    foreach my $p (sort {$res{$f}{$b} <=> $res{$f}{$a}} keys %{ $res{$f} }) {
	printf "%s %s\t", $p, pretty($res{$f}{$p});
    }
    print "\n";
}
print "\n";
