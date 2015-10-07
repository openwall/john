#!/usr/bin/perl -w
use strict;

sub find_deps {
	my ($src_file, $uniq_ref) = @_;
	my $deps = "";

	open my $fh, "<", $src_file or die $!;
	while (<$fh>) {
		if (/^\s*#\s*include\s+"([^"]+)"/) {
			if ($1 eq "arch.h" || $1 eq "autoconfig.h" || -f $1) {
				if (!($uniq_ref->{$1}++)) {
					$deps .= " " . $1;
					# Recurse!
					$deps .= find_deps($1, $uniq_ref);
				}
			} else {
				print STDERR "Warning: " . $src_file . " includes \"" . $1 . "\" but that file is not found.\n";
			}
		}
	}
	close($fh);

	return $deps;
}

foreach my $src_file (@ARGV) {
	my $object = $src_file;
	my $type = "c";
	my %uniqdeps;

	if ($object =~ /\.c$/) {
		$object =~ s/\.c$/.o/;
	} elsif ($object =~ /\.cl$/) {
		$object =~ s/^opencl\//..\/run\/kernels\//;
		$type = "cl";
	}
	my $deps = find_deps($src_file, \%uniqdeps);
	print $object . ":" . "\t" . $src_file . $deps . "\n";
	if ($type eq "c") {
		#print "\t" . '$(CC) $(CFLAGS) ' . $src_file . " -o " . $object . "\n";
	} elsif ($type eq "cl") {
		#print "\t" . '$(CP) $? ' . "../run/kernels\n";
	}
	print "\n";
}
