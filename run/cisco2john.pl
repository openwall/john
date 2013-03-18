#!/usr/bin/perl

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

use strict;

die "Usage: $0 [cisco config file] [...]\n" if ($ARGV[0] =~ /-h/);

my $seedNotice = 1;

my %Alphabets = (
	CISCO => "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
	);

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
    my ($ep) = @_;
    my @xlat = ( 0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41,
		 0x2c, 0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c,
		 0x64, 0x4a, 0x4b, 0x44, 0x48, 0x53 , 0x55, 0x42 );
    my $dp = "";
    my ($s, $e) = ($2 =~ /^(..)(.+)/o);
    for (my $i = 0; $i < length($e); $i+=2) {
	$dp .= sprintf "%c",hex(substr($e,$i,2))^$xlat[$s++];
    }
    return $dp;
}

sub notice
{
    if ($seedNotice) {
	$seedNotice = 0;
	print STDERR "#!comment: Found recoverable or clear-text passwords:\n";
    }
}

foreach (<>) {
    s/[\r\n]//g;
    if (/(password|md5|secret)\s+0\s/) {
	notice();
	s/\s+privilege\s+[0-9]+\s*$//;
	s/[ :]+/_/g;
	m/^.{1,}_0_(.*)/;
	if (unique($1)) {
	    print STDERR $1, "\n";
	}
    } elsif (/(password|md5)\s+7\s+([\da-f]+)/io) {
	notice();
	my $pw = deobfuscate($1);
	if (unique($pw)) {
	    print STDERR $pw, "\n";
	}
    } elsif (m/(\$1\$[\$\.\/0-9A-Za-z]{27,31})/) {
	my $hash = $1;
	s/[ :]+/_/g;
	m/^(.{1,})_5_\$1\$.*/;
	print $1, ":", $hash, "\n";
    } elsif (m/([\$\.\/0-9A-Za-z]{43})/) {
	my $hash = $1;
	s/[ :]+/_/g;
	m/^(.{1,})_4_[\$\.\/0-9A-Za-z]{43}/;
	print $1, ":";
	my $binhash = Decode($hash, 'CISCO');
	print join("", map { sprintf("%02x", ord($_)) } split(//, join("", $binhash))), "\n";
    } elsif (/(password|md5|secret)\s+[^045]/) {
	notice();
	s/\s+privilege\s+[0-9]+\s*$//;
	s/[ :]+/_/g;
	m/^((?:.*)(?:password|md5|secret))_(.*)/;
	if (unique($2)) {
	    print STDERR $2, "\n";
	}
    }
}
