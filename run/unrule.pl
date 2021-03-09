#!/usr/bin/perl
#
# Extract basewords from list of plains. Based on an embryo from epixoip.
# Feel free to enhance this script!
#
# Example:
# ./unrule.pl < rockyou.lst > basewords.lst
#
# TODO:
# The "leetspeak substitution" will currently replace '1' with 'i' but never
# with 'l', and so on. It should be improved somehow.
#

use warnings;
use strict;

my %line;
my $lines = 0;

sub hashValueDescendingNum {
    $line{$b} <=> $line{$a};
}

while (<>) {
	$lines++;
	next if length > 64;    # lines this long are probably noise
	tr/A-Z/a-z/;            # lowercase
	s/^[^a-z]+//;           # drop leading non-letters
	s/[^a-z]+$//;           # ...and trailing ones
	y/112345677890@\$\!\#/ilzeasbzvbgoasih/; # leetspeak substitution
	s/[^a-z]//g;            # drop any words that still contain non-letters
	next if /^$/;           # Suppress (now) empty lines
	$line{$_}++;
}

my $num = scalar keys(%line);
print STDERR "$0: File read ($lines lines reduced to $num), now sorting by count...\n";

foreach my $key (sort hashValueDescendingNum (keys(%line))) {
	printf("%s\n", $key);
}
