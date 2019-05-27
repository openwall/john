#!/usr/bin/perl
#
# Copyright (c) 2019 Solar Designer
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.  (This is a heavily cut-down "BSD license".)

use MIME::Base64;

while (<>) {
	chomp;
	($user, $delim, $pass) = /^([^:]*)(:){SSHA256}([^:]*)$/;
	($pass) = /^{SSHA256}([^:]*)$/ if (!defined($pass));
	next if (!defined($pass));
	($bin_hash, $bin_salt) = unpack('a32 a*', decode_base64($pass));
	$new = '$dynamic_62$' . unpack('H*', $bin_hash) . '$HEX$' . unpack('H*', $bin_salt);
	if (defined($user)) {
		print "$user:$new\n";
	} else {
		print "$new\n";
	}
}
