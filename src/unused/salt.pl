#!/usr/bin/perl -w
#
# Verify formats that should set Raw benchmark or not (see GitHub #3795)
#
# Run a benchmark with BenchmarkMany = Y set under [Debug] section in
# john.conf, and | tee file.txt
#
# Then process file.txt with this script

use warnings;
use strict;

my $format = "";
my $many = 0;
my $one = 0;
my $perc = 0;
my $costs = 0;

while (<>) {
	if (m/^Benchmarking:\s*([^, ]+)/) {
		$format = $1;
		$many = 0;
		$one = 0;
	}
	if (m/^Speed for cost .* and /) {
		$costs = 1;
	}
	if (m/^Many salts:\s*([0-9\.]+)([KMG])?/) {
		$many = $1;
		if (defined $2) {
			$many *= 1000 if $2 eq "K";
			$many *= 1000000 if $2 eq "M";
			$many *= 1000000000 if $2 eq "G";
		}
	} elsif (m/^Only one salt:\s*([0-9\.]+)([KMG])?/) {
		$one = $1;
		if (defined $2) {
			$one *= 1000 if $2 eq "K";
			$one *= 1000000 if $2 eq "M";
			$one *= 1000000000 if $2 eq "G";
		}
		my $cur = `../run/john -form=$format -list=format-details 2>/dev/null | cut -f 10`;
		next if !$cur; # dynamic
		chomp $cur;
		$cur = hex($cur);
		$perc = $many * 100 / $one;
		my $cs = $costs ? " (different costs)" : "";
		if (($cur & 0x400) && !$costs) {
			printf("%s set to 0x400 although not having different costs, change to 0x%x\n", $format, $cur & ~0x400);
			$cur &= ~0x400;
		}
		if ($many < $one && !($cur & 0x500)) {
			$cur |= 0x100;
			if ($costs) {
				$cur |= 0x400;
			}
			printf("%s has slower many-salts%s! %s vs. %s, change to 0x%x\n", $format, $cs, $many, $one, $cur);
		} elsif (($perc < 102) && !($cur & 0x100)) {
			$cur |= 0x100;
			if ($costs) {
				$cur |= 0x400;
			}
			printf("%s has insufficient boost%s: %.1f%%, change to 0x%x\n", $format, $cs, $perc, $cur);
		} elsif (!$costs && ($perc >= 102) && ($cur & 0x100) && !($cur & 0x400)) {
			$cur &= ~0x500;
			if ($cur < 0x100) {
				printf("%s has sufficient boost%s: %.1f%%, change to %d\n", $format, $cs, $perc, $cur);
			} else {
				printf("%s has sufficient boost%s: %.1f%%, change to 0x%x\n", $format, $cs, $perc, $cur);
			}
		}
		$format = "";
		$many = $one = $perc = $costs = 0;
	}
}
