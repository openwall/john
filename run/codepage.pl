#!/usr/bin/perl
# This software is Copyright (c) 2015 magnum and it is hereby released to
# the general public under the following terms:  Redistribution and use in
# source and binary forms, with or without modification, are permitted.

use warnings;
use strict;
use Encode;

binmode(STDIN, ':utf8');
binmode(STDOUT,':raw');

my $encoding = "iso-8859-1";

sub usage {
	print STDERR "Usage: $0 [-t <encoding>]\n";
	print STDERR "Reads UTF-8 from stdin, writes <encoding> to stdout, skipping pure ASCII\n";
	exit 1;
}

if (defined $ARGV[0] && shift @ARGV eq "-t") {
	if (!defined $ARGV[0]) {
		usage();
	} else {
		$encoding = shift @ARGV;
	}
}

my $enc = find_encoding($encoding) or die "$0: Unknown encoding\n";
my $out;

while (<>) {
	# Skip ASCII
	next unless /[\x80-\xff]/;

	# Try encoding, print if it worked
	eval { $out = $enc->encode($_, Encode::FB_CROAK); };
	print $out unless $@;
}
