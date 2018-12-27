#!/usr/bin/env perl
#
# Copyright (c) 2011 Solar Designer
# Copyright (c) 2011 Jim Fougeron
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.  (This is a heavily cut-down "BSD license".)

use warnings;
use strict;

die "Usage: $0 PLIST-FILES > PASSWORD-FILE\n" if ($#ARGV lt 0);

my $file;
foreach $file (@ARGV) {
	my ($hash, $user);

	unless (open(F, "< $file")) {
		print STDERR "Could not open file: $file ($!)\n";
		next;
	}
	unless (read(F, $_, 1000000)) {
		print STDERR "Could not read file: $file\n";
		close(F);
		next;
	}
	close(F);

	($hash) = /bplist00\xd1\x01\x02\x5dSALTED-SHA512\x4f\x10\x44([\x00-\xff]{68})/;
	if (!$hash) {
		print STDERR "Could not find a Mac OS X 10.7 Lion salted SHA-512 hash in file: $file\n";
		next;
	}

	($user) = /\x3a\x53\x48\x41\x31\x2e[\x00-\xff]{40}([\x20-\x39\x3b-\x7e\xa0-\xff]{1,64})\xa1\x35\x4f\x10/;

	$user = "UNKNOWN_USERNAME" unless ($user);

	print $user, ":", unpack('H*', $hash), "\n";
}
