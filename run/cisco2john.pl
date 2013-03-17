#!/usr/bin/perl

# Basic Cisco type 4 - password encoder / decoder by Kost, Dhiru
# and magnum
#
# Usage Examples:
#
# $ echo "LcV6aBcc/53FoCJjXQMd7rBUDEpeevrK8V5jQVoJEhU" | cisco2john.pl
# 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
#
# $ cat hashes
# enable:LcV6aBcc/53FoCJjXQMd7rBUDEpeevrK8V5jQVoJEhU:::172.16.17.18:comments
#
# $ cisco2john.pl hashes
# enable:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8:::172.16.17.18:comment
#
# Credits:
#
# magnum : Change cisco2john.pl so it supports file[s] (or stdin) as
# input and preserves any login/additional fields.
#
# Base64 custom encoder / decoder taken from VOMS::Lite::Base64
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

die "Usage: $0 <Cisco type-4 hashes>\n" if ($ARGV[0] =~ /-h/);

my %Alphabets = ( VOMS => "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789[]",
                  RFC3548 => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",
                  RFC3548URL => "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-=",
                  CISCO => "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",                );

sub Encode{
  my $data = shift;
  my $str = shift;  # Can supply custom Base64
  my $pad="";
  if ( defined $str ) {
    $str = $Alphabets{$str} if ($Alphabets{$str});
    if ( $str =~ /^(.{64})(.?)$/s ) { $str=$1; $pad="$2"; }
    else { return undef; }
  }
  else { $str = $Alphabets{'CISCO'}; }
  $data=~s|(.)(.?)(.?)| substr($str,((ord($1)&252)>>2),1).
                        substr($str,((ord($1)&3)<<4)+((ord($2)&240)>>4),1).
                        ((length($2))?substr($str,((ord($2)&15)<<2)+((ord($3)&192)>>6),1):$pad).
                        ((length($3))?substr($str,(ord($3)&63),1):$pad)|gse;
  return $data;
}

sub Decode {
  my $data = shift;
  my $str = shift;  # Can supply custom Base64
  my $pad="=";

  my $type;
  if ( defined $str && ! defined $Alphabets{$str} )  { $type = 'USER'; }
  elsif ( defined $str && defined $Alphabets{$str} ) { $type = $str; }
  #Try to guess
  elsif ( $data =~ /[\[\]]/s && $data !~ /[+\/_-]/ ) { $type = 'VOMS'; }
  elsif ( $data =~ /[_-]/s && $data !~ /[\[\]+\/]/)  { $type = 'RFC3548URL'; }
  else                                               { $type = 'RFC3548'; } # Assume Standard Base64 if
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

foreach my $line (<>) {
    chomp $line;
    my @fields = split(/:/, $line);
    if (defined($fields[1])) {
	print shift(@fields), ":";
    }
    my $hash = shift(@fields);
    my $binhash = Decode($hash, 'CISCO');

    print join("", map { sprintf("%02x", ord($_)) } split(//, join("", $binhash)));
    print $#fields >= 0 ? ":" : "", join(':', @fields), "\n";
}
