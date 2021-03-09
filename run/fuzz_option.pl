#!/usr/bin/perl
#
# This file is part of John the Ripper password cracker,
# Copyright (c) 2015 by Solar Designer
#
# Fuzz john using --fuzz option by Kai Zhao
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# There's ABSOLUTELY NO WARRANTY, express or implied.
#

#
# How to run
#
# ./fuzz_option.pl /path/to/john format-name &> fuzz.log
#

use warnings;
use Errno;
use File::Copy;

# Processes per logical CPU
$factor = 4;


$ENV{'OMP_NUM_THREADS'} = '1';
setpriority(PRIO_PROCESS, 0, 19);

if (1 > $#ARGV || 2 < $#ARGV) {
	print "usage: ./fuzz.pl /path/to/john format-name [dictionary]\n";
	die;
}

$john_path = $ARGV[0];
$format_name = $ARGV[1];

#
# Get all formats name
#
open(FORMATS, "$john_path --list=formats --format=$format_name |") || die;
while (<FORMATS>) {
	($line) = /^([ ,\w\d-]+)/;
	@words = split(/, /, $line);
	for ($i = 0; $i <= $#words; $i++) {
		$formats[$#formats + 1] = $words[$i];
	}
}
close(FORMATS);

die unless ($#formats >= 0);

$cpus = `grep -c ^processor /proc/cpuinfo`;
chomp $cpus;
$cpus = 1 if (!$cpus);

print "$cpus CPUs\n";

$cpus *= $factor;

if ($#formats > $cpus) {
	for ($cpu = 0; $cpu < $cpus - 1; $cpu++) {
		last if (fork() == 0);
	}
	$from = int(($#formats + 1) * $cpu / $cpus);
	$to = int(($#formats + 1) * ($cpu + 1) / $cpus) - 1;
} else {
	$from = 0;
	$to = $#formats;
}

#
# Run john
#
for ($i = $from; $i <= $to; $i++) {

	#print "Fuzzing format:$formats[$i] \n";
	open(JOHN, "| $john_path --fuzz=fuzz.dic --format=$formats[$i] ") || die;
	close(JOHN);

	die if ($? == 2 || $? == 15); # INT or TERM

	if ($? == 256) {
		next;
	}

	if ($? != 0) {
		open(LOG, ">> fuzz_option_err.log") || die;
		print LOG "Fuzz formats=$formats[$i] WRONG.\n";
		close(LOG);

		Reproduce($formats[$i]);
	}
}

sub Reproduce {

	$err_folder = "err_pwfiles";

	die unless (mkdir($err_folder, 0700) || $!{EEXIST});

	my $filename = "fuzz_status/@_";
	$last_line = "";
	if (open(my $fh, $filename)) {
		while (my $line = <$fh>) {
			$last_line = $line;
		}
		close($fh);
	} else {
		$newfile = "$err_folder/pwfile.@_";
		open(my $fh, ">", $newfile) || die "Failed to open($newfile)";
		print $fh "Reproduce failed: failed to open($filename)\n";
		close($fh);
		return;
	}
	print "last_line=$last_line\n";

	$to_index = int($last_line) + 1;
	$from_index = $to_index - 1;

	$i = 1;
	while (1) {

		print "from_index=$from_index\n";
		print "to_index=$to_index\n";

		# Generate pwfile
		open(JOHN, "| $john_path --fuzz=fuzz.dic --fuzz-dump=$from_index,$to_index --format=@_ ") || die;
		close(JOHN);

		open(JOHN, "| $john_path pwfile.@_ --format=@_ --max-run-time=100") || die;
		close(JOHN);

		die if ($? == 2 || $? == 15); # INT or TERM

		if ($? != 256 && $? != 0) {
			# Reproduce succeed

			$oldfile = "pwfile.@_";
			$newfile = "$err_folder/$oldfile";
			move $oldfile, $newfile;
			unlink($oldfile);
			last;
		} else {
			# Reproduce failed

			if ($from_index <= 0) {
				# Give up

				$newfile = "$err_folder/pwfile.@_";
				open(my $fh, ">", $newfile) || die "Failed to open($newfile)";
				print $fh "Reproduce failed: index=$last_line\n";
				close($fh);

				last;
			} else {
				# Go on reducing $from_index

				# $i = 1, 2, 6, 42, 1806, ...
				$i = $i * ($i + 1);
				$from_index = $from_index - $i;
			}
		}
	}

}
