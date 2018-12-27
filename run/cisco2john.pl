#!/usr/bin/env perl
#
# Basic Cisco type 4 - password decoder by Kost, Dhiru
# and magnum
#
# Usage Examples:
#
#   $ ./cisco2john.pl cisco.config >cisco.in
#   #!comment: Found type 7 passwords:
#   companysecret
#   test
#
# (because of that output, we re-run it and save stderr to its own file)
#   $ ./cisco2john.pl cisco.conf >cisco.in 2>cisco.seed
#
#   $ cat cisco.in
#   enable_secret_level_2:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
#   enable_secret:$1$4C5N$JCdhRhHmlH4kdmLz.vsyq0
#
#   $ ./john -wo:cisco.seed -rules cisco.in
#
# Credits:
#
# magnum : Change cisco2john.pl so it reads a Cisco config file and outputs
# any clear-text or deobfuscated passwords, and outputs hashes in JtR format.
#
# Base64 custom decoder taken from VOMS::Lite::Base64
# This module was originally designed for the JISC funded SARoNGS project at developed at
#
# The University of Manchester.
# http://www.rcs.manchester.ac.uk/projects/sarongs/
#
# Mike Jones <mike.jones@manchester.ac.uk>
#
# Copyright (C) 2010 by Mike Jones
#
# This library is free software; you can redistribute it and/or modify
# it under the same terms as Perl itself, either Perl version 5.8.3 or,
# at your option, any later version of Perl 5 you may have available.

use warnings;
use strict;
use File::Basename;

my $seedNotice = 1;
my %Alphabets = (
	CISCO => "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	);

sub usage {
    my $dn = $0; $dn =~ s/(.*)\/cisco2john.pl/$1/;
    print "Usage:\t$0 [cisco config file(s)] >>hashfile 2>>seed.txt\n";
    print "\t${dn}/john -format:md5 -wordlist:seed.txt -rules hashfile\n\n";
    exit 1;
}

sub Decode {
  my $data = shift;
  my $str = shift;  # Can supply custom Base64
  my $pad="=";

  my $type;
  if ( defined $str && ! defined $Alphabets{$str} )  { $type = 'USER'; }
  elsif ( defined $str && defined $Alphabets{$str} ) { $type = $str; }
  #Try to guess
  elsif ( $data =~ /[\.\/]/s && $data !~ /[+\/_-]/ ) { $type = 'CISCO'; }
  else                                               { $type = 'CISCO'; } # Assume Standard Base64 if
  if ( $type eq "USER" )                             { $Alphabets{'USER'} = $str; }

  #strip non-base64 chars
  my $estr;
  if ( $Alphabets{$type} =~ /^(.{64})(.?)$/s ) { $str=$1; $estr=quotemeta($1); $pad=$2; } else { return undef; }
  $data =~ s/[^$estr]//gs;

  # Force Padding
  $data .= $pad x (3-(((length($data)+3) % 4)));
  $data=~s|(.)(.)(.?)(.?)|
              chr(((index($str,$1)<<2)&252)+((index($str,$2)>>4)&3)).                      #six bits from first with two bits from the second
              (($3 ne $pad)?chr(((index($str,$2)<<4)&240)+((index($str,$3)>>2)&15)):"").   #last 4 bits from second with four bits from third unless third is pad
              (($4 ne $pad)?chr(((index($str,$3)<<6)&192)+((index($str,$4))&63)):"")       #last 2 bits from third with six bits from the forth unless forth is pad
              |ge;
  return $data;
}

my %uniq;
sub unique
{
    my ($input) = @_;
    return !$uniq{$input}++;
}

# Credits for original code and description hobbit@avian.org,
# SPHiXe, .mudge et al. and for John Bashinski
# for Cisco IOS password encryption facts.
#
# Use of this code for any malicious or illegal purposes is strictly prohibited!
#
sub deobfuscate
{
    my @xlat = ( 0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41,
		 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c,
		 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53 , 0x55, 0x42 );
    my ($ep) = @_;
    my $dp = "";

    if (!(length($ep) & 1)) {
	    my ($s, $e) = ($ep =~ /^(..)(.+)/);
	    $s = hex($s);
	    for (my $i = 0; $i < length($e); $i += 2) {
		    $dp .= sprintf "%c", hex(substr($e, $i, 2)) ^
		      $xlat[$s++ % 26];
	    }
	    if ($dp =~ m/[\x00-\x19]/) {
		    $dp = unpack("H*", $dp);
	    }
	    return $dp;
    }
}

sub notice
{
    if ($seedNotice) {
	$seedNotice = 0;
	print STDERR "#!comment: Found recoverable or clear-text passwords, or other seed:\n";
    }
}

if ($ARGV[0] =~ /-h/) { usage() }

my $ssid = "";
while (<>) {
    chomp;
    s/[\r\n]//g;
    my $filename = ($ARGV ne "-") ? ":" . basename($ARGV) : "";
    #print "in: $_\n";

    # WPA-PSK
    if ($ssid && m/hex 0 ([\dA-F]+)/) {
	my $output = "$ssid:\$pbkdf2-hmac-sha1\$4096\$" . unpack("H*", $ssid) . '$' . $1 . $filename;
	if (unique($output)) {
	    print $output, "\n";
	}
    } elsif ($ssid && m/hex 7 ([\dA-F]+)/) {
	#print "in: $_\nhex: $1\n";
	my $hex = deobfuscate($1);
	my $output = "$ssid:\$pbkdf2-hmac-sha1\$4096\$" . unpack("H*", $ssid) . '$' . $hex . $filename;
	if ($hex && unique($output)) {
	    print $output, "\n";
	}
    # password 0 <cleartext>
    } elsif (m/(?:password|md5|secret|ascii|hex) 0 /) {
	#print "in1: $_\n";
	notice();
	s/\s+privilege [0-9]+ *$//;
	s/[ :]+/_/g;
	m/^.{1,}_0_(.*)/;
	if (unique($1)) {
	    print STDERR $1, "\n";
	}
    # password 7 <obfuscated>
    } elsif (m/(?:password|md5|ascii|key|hex|encryption .*) 7 ([\dA-F]+)/) {
	#print "in2: $_\n";
	notice();
	my $pw = deobfuscate($1);
	if (unique($pw)) {
	    print STDERR $pw, "\n";
	}
    # secret 5 <crypt-md5-hash>
    } elsif (m/ (\$1\$[\$\.\/0-9A-Za-z]{27,31})(?: |$)/) {
	#print "in3: $_\n";
	my $hash = $1;
	s/[ :]+/_/g;
	m/^(.{1,})_5_\$1\$.*/;
	my $output = $1 . ":" . $hash . $filename;
	if (unique($output)) {
	    print $output, "\n";
	}
    # secret 4 <sha-256 hash>
    } elsif (m/ 4 ([\$\.\/0-9A-Za-z]{43})(?: |$)/) {
	#print "in4: $_\n";
	my $hash = $1;
	s/[\s:]+/_/g;
	m/^(.{1,})_4_[\$\.\/0-9A-Za-z]{43}/;
	my $output = $1 . ':$SHA256$';
	my $binhash = Decode($hash, 'CISCO');
	$output .= join("", map { sprintf("%02x", ord($_)) } split(//, join("", $binhash))) . $filename;
	if (unique($output)) {
	    print $output, "\n";
	}
    # SSIDs
    } elsif (m/(?:\bssid) ([^\s]+)/) {
	#print "in5: $_\n";
	$ssid = $1;
	notice();
	if (unique($1)) {
	    print STDERR $1, "\n";
	}
    # Hostnames, SSIDs and SNMP communities - add to seeds
    } elsif (m/\b(?:hostname|snmp-server community|ssid) ([^\s]+)/) {
	#print "in5: $_\n";
	notice();
	if (unique($1)) {
	    print STDERR $1, "\n";
	}
    # password <cleartext> (may produce false hits but what the heck)
    } elsif (m/^(username|enable|wpapsk).*(password|md5|secret|ascii) / ||
	     m/^ (password|md5|secret|ascii) /) {
	#print "in6: $_\n";
	notice();
	s/ privilege [0-9] *$//;
	s/[ :]+/_/g;
	m/^((?:.*)(?:password|md5|secret))_(.*)/;
	if (unique($2)) {
	    print STDERR $2, "\n";
	}
    }
}

if (keys(%uniq) == 0) {
    usage();
}
