#!/usr/bin/env perl
#############################################################################
# vdi2john.   This will convert *.vbox files (which list the encryption
# information about the associated *.vdi file) into the proper format for
# jtr to process.
#
# Placed in public domain.  JimF.  2015.
#############################################################################

use warnings;
use strict;
use MIME::Base64;

my $line;
while ($line = <STDIN>) {
	chomp $line;
	if (index($line, "<Property name=\"CRYPT/KeyId") != -1) {
		my $name = get_value_fld($line);
		$line = <STDIN>;
		my $s = get_value_fld($line);
		$s =~ s/&#13;&#10;//g;
		$s = decode_base64($s);
		if (substr($s, 0, 4) eq "SCNE" && to_int(substr($s,4,2)) == 0x100) {
			$s = substr($s, 6);
			my $algo = substr($s, 0, 32);  $s = substr($s, 32);
			my $kdf = substr($s, 0, 32);   $s = substr($s, 32);
			my $gen_keylen = to_int(substr($s, 0, 4));   $s = substr($s, 4);
			my $final = substr($s, 0, 32); $s = substr($s, 32);
			my $keylen = to_int(substr($s, 0, 4));       $s = substr($s, 4);
			my $salt2 = substr($s, 0, 32); $s = substr($s, 32);
			my $salt2_iter = to_int(substr($s, 0, 4));   $s = substr($s, 4);
			my $salt1 = substr($s, 0, 32); $s = substr($s, 32);
			my $salt1_iter = to_int(substr($s, 0, 4));   $s = substr($s, 4);
			my $evp_len = to_int(substr($s, 0, 4));      $s = substr($s, 4);
			my $enc_pass = substr($s, 0, $evp_len);
			if ( ($algo eq 'AES-XTS128-PLAIN64'."\0"x14 || $algo eq 'AES-XTS256-PLAIN64'."\0"x14) && $kdf eq 'PBKDF2-SHA256'."\0"x19) {
				print "$name:\$vdi\$";
				print substr(lc $algo, 0, 10).'$' . substr(lc $kdf, 7, 6).'$';
				print "$salt1_iter\$$salt2_iter\$$gen_keylen\$$keylen\$";
				print lc unpack("H*",$salt1) . '$' . lc unpack("H*",$salt2) . '$';
				print lc unpack("H*",$enc_pass) . '$'. lc unpack("H*",$final) . "\n";
			}
		}
	}
}

sub get_value_fld {
	my $s = $_[0];
	my $pos = index($s, "value=\"");
	$s = substr($s, $pos+7);
	$pos = index($s, "\"/>");
	return substr($s, 0, $pos);
}

sub to_int {
	my $i = 0;
	my $s = $_[0];
	while (length($s)) {
		my $c = substr($s, length($s)-1, 1);
		$i *= 256;
		$i += ord($c);
		if (length($s) == 1) {
			return $i;
		}
		$s = substr($s,0,length($s)-1);
	}
	return 0;
}
