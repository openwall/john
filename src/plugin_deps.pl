#!/usr/bin/perl
#
# Warning: Trying to understand this script will make your brain bleed.

use warnings;
use strict;

sub find_deps {
	my ($src_file, $uniqobj_ref, $uniqdep_ref) = @_;
	my $deps = "";
	my $base_dir = "";

	if ($src_file =~ m/(.*\/)/) {
		$base_dir = $1;
	}

	if ($src_file eq "arch.h" || $src_file eq "autoconfig.h") {
		return "";
	}

	#print "find_deps processing $src_file\n";
	open my $fh, "<", $src_file or die "$src_file: $!";
	binmode $fh, ":raw";

	while (<$fh>) {
		if (/^\s*#\s*include\s+"([^"]+)"/) {
			my $object = $base_dir . $1;
			while ($object =~ s/([^\/]+)\/..\///g) {}
			if ($object eq "arch.h" || $object eq "autoconfig.h" || -f $object) {
				if (!($uniqdep_ref->{$object}++)) {
					#print "src $src_file obj $object\n";
					$deps .= " " . $object;
					# Recurse!
					$deps .= find_deps($object, $uniqobj_ref, $uniqdep_ref);
				}
			} else {
				print STDERR "Warning: " . $src_file . " includes \"" . $1 . "\" but that file is not found.\n";
			}
		}
	}
	close($fh);

	return $deps;
}

sub proc_file {
	my ($src_file, $uniqobj_ref) = @_;
	my $object = $src_file;
	my $type = "";
	my %uniqdeps;

	#print "proc_file processing $src_file\n";
	if ($object =~ /^..\/run\/opencl\/opencl_.*\.h$/) {
		$type = "oclh";
	}
	if (!$uniqobj_ref->{$src_file}++) {
		if ($object =~ /\.[cS]$/) {
			$object =~ s/\.[cS]$/.o/;
			$type = "c";
		} elsif ($object =~ /\.cl$/) {
			$type = "cl";
		}
		if ($type) {
			my $deps = find_deps($src_file, $uniqobj_ref, \%uniqdeps);
			print $object . ":" . "\t" . $src_file . $deps . "\n";
			if ($type eq "c") {
				#print "\t" . '$(CC) $(CFLAGS) ' . $src_file . " -o " . $object . "\n";
			}
			print "\n";
		}
	}
}

my %uniqobjs;

foreach my $src_file (@ARGV) {
	#print "outer loop processing $src_file\n";
	proc_file($src_file, \%uniqobjs);
}
