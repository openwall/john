#!/usr/bin/perl -w
use strict;

foreach my $format (@ARGV) {
	next unless $format =~ m/_plug\.c$/;
	my $object = $format;
	my $deps = "";
	$object =~ s/\.c$/.o/;
	open FILE, "<", $format or die $!;
	while (<FILE>) {
		if (/^\s*#\s*include\s+"([^"]+)"/) {
			if ($1 eq "arch.h" || -f $1) {
				$deps .= " " . $1;
			} else {
				print STDERR "Warning: " . $format . " includes \"" . $1 . "\" but that file is not found.\n";
			}
		}
	}
	print $object . ":" . "\t" . $format . $deps . "\n\n";
	#print "\t" . '$(CC) $(CFLAGS) ' . $format . " -o " . $object . "\n\n";
}
