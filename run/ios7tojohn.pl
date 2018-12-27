#!/usr/bin/env perl
#
# This software is Copyright (c) 2014 magnum
# and it is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

use warnings;
use strict;
use MIME::Base64;
use File::Basename;

# Example input (from com.apple.restrictionspassword.plist):
#    <key>RestrictionsPasswordKey</key>
#    <data>
#    J94ZcXHm1J/F9Vye8GwNh1HNclA=
#    </data>
#    <key>RestrictionsPasswordSalt</key>
#    <data>
#    /RHN4A==
#    </data>
#
# Example output:
# $pbkdf2-hmac-sha1$1000.fd11cde0.27de197171e6d49fc5f55c9ef06c0d8751cd7250

die "Usage: $0 [file [file...]]\n" if ($#ARGV < 0);

my ($type, $key, $salt) = ();

while(<>) {
	s/\r//g; # Drop Redmond Garbage[tm]
	if (m#^\s*<key>(.*)Key</key>\s*$#) {
		$type = $1;
		next;
	}
	# Single line
	if ($type && m#^\s*<data>([0-9a-zA-Z/.=]+)</data>\s*$#) {
		my $data = $1;
		if (!$key) {
			$key = $data;
		} elsif (!$salt) {
			$salt = $data;
			print "$type:\$pbkdf2-hmac-sha1\$1000.${salt}.${key}:::", basename($ARGV, ".plist"), "::${ARGV}\n";
			$type = $key = $salt = undef;
			next;
		} else {
			die "Error parsing file ${ARGV} line $.\n";
		}
	}
	# Multi line (but all data on one line)
	elsif ($type && m#^\s*<data>\s*$#) {
		my $data = unpack("H*", decode_base64(<ARGV>));
		if (!$key) {
			$key = $data;
		} elsif (!$salt) {
			$salt = $data;
			print "$type:\$pbkdf2-hmac-sha1\$1000.${salt}.${key}:::", basename($ARGV, ".plist"), "::${ARGV}\n";
			$type = $key = $salt = undef;
			next;
		} else {
			die "Error parsing file ${ARGV} line $.\n";
		}
	}
}
