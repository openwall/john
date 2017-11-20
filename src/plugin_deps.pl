#!/usr/bin/perl -w
#
# Warning: Trying to understand this script will make your brain bleed.
#
use strict;
use Cwd;
use File::Basename;

sub find_deps {
	my ($src_file, $cwd, $uniqobj_ref, $uniqdep_ref) = @_;
	my $deps = "";
	my $base_dir = "";

	if ($src_file =~ m/(.*\/)/ && $1 ne "opencl/") {
		$base_dir = $1;
	}

	if ($src_file eq "arch.h" || $src_file eq "autoconfig.h") {
		return "";
	}

	#print "find_deps processing $src_file\n";
	open my $fh, "<", $src_file or die "$src_file: $!";
	while (<$fh>) {
		if (/^\s*#\s*include\s+"([^"]+)"/) {
			my $object = $base_dir . $1;
			my $file = $1;
			my $tmp = "";

			if (! -f $object) {
				$tmp = $file;
				if (-f $tmp) {
					$object = $tmp
				} elsif ($file =~ /\.c$/) {
					$tmp = "jumbo/" . $file;
					if (-f $tmp) {
						$object = $tmp
					}
					$tmp = "jumbo/opencl/" . $file;
					if (-f $tmp) {
						$object = $tmp
					}
				} elsif ($file =~ /\.h$/) {
					$tmp = "jumbo/include/" . $file;
					if (-f $tmp) {
						$object = $tmp
					}
					$tmp = "jumbo/opencl/include/" . $file;
					if (-f $tmp) {
						$object = $tmp
					}
					$tmp = "include/" . $file;
					if (-f $tmp) {
						$object = $tmp
					}
				}
			}
			while ($object =~ s/([^\/]+)\/..\///g) {}
			if ($object =~ /arch.h$/ && $object ne "arch.h" || $object =~ /autoconfig.h$/ && $object ne "autoconfig.h") {
				$object = $file;
			}
			if ($object eq "arch.h" || $object eq "autoconfig.h" || -f $object) {
				if (!($uniqdep_ref->{$object}++)) {
					#print "src $src_file obj $object\n";
					if (($src_file =~ /^jumbo\/opencl\// && $object =~ /opencl_.*\.h$/) ||
						($src_file =~ /^opencl_.*\.h$/ && $object =~ /opencl_.*\.(h|cl)$/)) {
						$object = "../run/kernels/" . basename($object);
						$deps .= " " . $object;
						# Recurse!
						proc_file($object, $uniqobj_ref);
					} else {
						$deps .= " " . $object;
						# Recurse!
						$deps .= find_deps($object, $cwd, $uniqobj_ref, $uniqdep_ref);
					}
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
	my ($src_file, $cwd, $uniqobj_ref) = @_;

	my $object = $src_file;
	my $type = "";
	my %uniqdeps;

	#print "proc_file processing $src_file\n";
	if ($object =~ /^..\/run\/kernels\/opencl_.*\.h$/) {
		$src_file =~ s/^..\/run\/kernels\//jumbo\/opencl\/include\//;
		$type = "oclh";
	}
	if (!$uniqobj_ref->{$src_file}++) {
		if ($object =~ /\.[cS]$/) {
			$object =~ s/\.[cS]$/.o/;
			$type = "c";
		} elsif ($object =~ /\.cl$/) {
			$object =~ s/^jumbo\/opencl\/kernels\//..\/run\/kernels\//;
			$type = "cl";
		}
		if ($type) {
			my $deps = find_deps($src_file, $cwd, $uniqobj_ref, \%uniqdeps);
			print $object . ":" . "\t" . $src_file . $deps . "\n";
			if ($type eq "c") {
				#print "\t" . '$(CC) $(CFLAGS) ' . $src_file . " -o " . $object . "\n";
			} elsif ($type eq "cl" || $type eq "oclh") {
				#print "\t" . '$(CP) $? ' . "../run/kernels\n";
			}
			print "\n";
		}
	}
}

my %uniqobjs;
my $cwd = cwd;

foreach my $src_file (@ARGV) {
	#print "outer loop processing $src_file\n";
	proc_file($src_file, $cwd, \%uniqobjs);
}
