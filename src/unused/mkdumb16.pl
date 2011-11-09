#!/usr/bin/perl -w
use strict;
use Switch;

my @alloced; my @desc;
while (<>) {
	if (/^([0-9A-F]{4,5});/) {
		my $this = $1;
		if (!/<control>/ && !/surrogate/i && !/private use/i) {
			my @data = split(';', $_);
			push @alloced, hex($this);
			$desc[hex($this)] = $data[1];
		}
	}
}
my $first = 0; my $last = 0; my $inrange = 0;
foreach my $entry (@alloced) {
	if (!($desc[$entry] =~ /, First/) && $entry == $last+1 || $desc[$entry] =~ /, Last/) {
		if (!$inrange) {
			$first = $last;
		}
		$inrange = 1;
		$last = $entry;
	} else {
		if ($inrange) {
			if ($last-$first > 2) {
				printf "\tc = 0x%x;\t\t// from %s\n", $first, $desc[$first];
				printf "\twhile (c < 0x%x)\t// ..to %s\n", $last+1, $desc[$last];
				print "\t\tcharset[i++] = c++;\n";
			} else {
				printf "\tcharset[i++] = 0x%x;\t// %s\n", $first, $desc[$first];
				if ($last != $first) {
					printf "\tcharset[i++] = 0x%x;\t// %s\n", $last, $desc[$last];
				}
			}
			$inrange = 0;
		}
		$last = $entry;
	}
}
