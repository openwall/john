#!/usr/bin/perl

####
# This script converts an Apple OS X Lion plist file
# into a John the Ripper compatible "shadow" format.
# v0.1
#
# Copyright (c) 2011 Jean-Michel Picod <jean-michel.picod at cassidian.com>
# Redistribution and use in source and binary form, with or without
# modification, are permitted. (This is a heavily cut-down "BSD licence".)
####

use warnings;
use strict;
use Data::Plist;
use Data::Plist::BinaryReader;

sub usage {
  print "Usage: $0 <plist file> ...\n";
  exit(1);
}

usage() unless ($#ARGV >= 0);

while (my $f = shift @ARGV) {
  my $reader = new Data::Plist::BinaryReader;
  my $plist = $reader->open_file($f);
  my $data = $plist->collapse($plist->raw_data);
  my $user = $data->{'name'}[0];
  my $hash = $plist->collapse($data->{'ShadowHashData'}[0]->raw_data);

  print "$user:", (unpack("H*", $hash->{'SALTED-SHA512'})), "\n";
}

0;
