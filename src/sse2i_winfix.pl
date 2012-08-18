#!/usr/bin/perl -w
use strict;

####################################################################
# This script will modify any .S file built with icc-32 bit, so that
# it can be compiled properly with cygwin. We have to comment out
# several lines, and we also have to add a block of #defines, for
# the modification of the 'NEEDSUNDERSCORE' building.
#
# Based on a script by Jim Fougeron that was specific to a certain
# source file.
#
# This software is Copyright (c) 2012 magnum, and it is hereby
# released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
####################################################################

my ($infile, $outfile) = (@ARGV);

sub usage {
    print STDERR "\nUsage: $0 <infile> <outfile>\n\n";
    exit 0;
}

if ($#ARGV != 1) {
    usage();
}

unless (open INPUT,  "<", $infile) {
    print STDERR "ERROR: Infile $infile does not exist: $!\n";
    usage();
}

open OUTPUT, ">", $outfile or die $!;

# find all functions that (may) need underscoring. We will probably do
# a few not needed, but hey, no harm done!
my %functions;
while (<INPUT>) {
    if (m/^\s+\.type\s+([^,]+?),\@function/ || m/^\s+call\s+([^\.]+?)$/) {
	$functions{$1} = $1;
    }
}

# wind it back
seek(INPUT, 0, 0);

# copy the .file line
my $line = <INPUT>;
print OUTPUT $line;

# add underscore macros
print OUTPUT "\n#ifdef UNDERSCORES\n";
foreach (keys %functions) {
    printf OUTPUT "#define %-16s_%s\n", $_, $_;
}
print OUTPUT "#endif\n\n";

# copy most of the rest
while (<INPUT>) {
	next if (/^\t\.type\t/);
	next if (/^\t\.size\t/);
	next if (/^\t\.section \.rodata\./);
	next if (/^\t\.section \.note\./);
	print OUTPUT;
}

close OUTPUT;
close INPUT;
