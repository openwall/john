#!/usr/bin/env perl
#
# potcheck.pl   This script is used to upgrade john's .pot file, to find
#               problems, and 'fix' them, and other things.
#
# 2016 by JimF for use in JohnRipper project.  Code placed in public domain.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted, as long an unmodified copy of this
# license/disclaimer accompanies the source.
#
# There's ABSOLUTELY NO WARRANTY, express or implied.
#

use warnings;
use strict;
use Getopt::Long;
use Digest::MD5 qw(md5_hex);

# NOTE, if this is changed in params.h, we need to update it here!
my $LINE_BUFFER_SIZE = 0x400;
my $PLAINTEXT_BUFFER_SIZE = 0x80;
my $MAX_CIPHERTEXT_SIZE = ($LINE_BUFFER_SIZE - $PLAINTEXT_BUFFER_SIZE);
my $POT_BUFFER_CT_TRIM_SIZE = ($MAX_CIPHERTEXT_SIZE - 13 - 32);

# options:
my $help = 0; my $quiet = 0; my $verbosity = 0; my $stop_on_error = 0;
my $canonize_fix = 0;   # canonize .pot lines, (i.e. $dyna_33$ -> $NT$ type stuff)
my $encode_fix  = 0;    # normalize to utf8 ?  (NOTE, this may be harder than hell)
my $longline_fix = 0;   # this will be done by default is ANY other 'fix' is selected.
my $validate = 0;       # silent. Only returns 0 or 1 (1 if there are ANY invalid lines).

my $line_buffer_size = 0x400;
my $plaintext_buffer_size = 0x100;
my $max_ciphertext_size = ($line_buffer_size - $plaintext_buffer_size);
my $pot_buffer_ct_trim_size = ($max_ciphertext_size - 13 - 32);

my $cato = 0;       # cato error.  If seen, return 1 and print explanation.
                    # Then ./configure will stop telling the user to first
                    # 'fix' his .pot file.
my $fix = 0;        # this will cause output in .pot format, fixing lines.
                    # if ANY of the *_fix vars get set, then we set this to true
my $line_no = 0;

parseArgs();

while (my $line = <STDIN>) {
	$line_no++;
	chomp $line;
	minimize($line);
}
exit (!!$cato);


sub usage {
	print "usage:  $0 [args]\n";
	print "\targs:\n";
	print "\t -? | -help    Provide this help screen\n";
#	print "\t -quiet        Less output (multiple -q allowed)\n";
	print "\t -verbose      More output\n";
	print "\t -validate     Returns 0 if .pot valid, or 1 if any lines are problems\n";
#	print "\t -stoponerror  If there is any fatal problem, stop\n";
#	print "\t -canonize_fix Apply canonizaton rules to convert formats\n";
#	print "\t -encode_fix   Fix encoding issues (cannonize to utf8)\n";
	print "\t -longline_fix Overlong lines are converted to short .pot format\n";
	print "\nThe program is a filter. stdin/stdout are used for input and output\n";
	exit (0);
}

sub parseArgs {
	my @passthru=();
	my $help = 0;
	my $err = GetOptions(
		'help|?'            => \$help,
	#	'quiet+'            => \$quiet,
		'verbose+'          => \$verbosity,
	#	'stoponerror!'      => \$stop_on_error,
		'validate!'         => \$validate,
	#	'canonize_fix!'     => \$canonize_fix,
	#	'encode_fix!'       => \$encode_fix,
		'longline_fix!'     => \$longline_fix,
		);
	if ($err == 0) { usage("exiting, due to invalid option"); }
	if ($help) { usage(); }
	#if ($canonize_fix || $encode_fix) { $longline_fix = 1; }
	$fix = $canonize_fix + $encode_fix + $longline_fix;
	if ($fix) { $verbosity += 1; }
	$verbosity -= $quiet;
	die "validate can not be used with some fixing function" if ($validate and $fix);
	die "validate or some fixing function(s) must be specified" if (!$validate and !$fix);
}

sub minimize {
	my $line = $_[0];
	$line=fixcanon($line)     if ($canonize_fix);
	$line=fixencode($line)    if ($encode_fix);
	$line=fixlongline($line)  if ($longline_fix or $validate);
	if ($validate == 0) { print "$line\n"; }
}

sub fixcanon {
	return 'canon '.$_[0];
}
sub fixencode {
	require Encode;
	return 'encode '.$_[0];
}
sub fixlongline {
	my $pos = index($_[0], ':');
	if ($pos <= $MAX_CIPHERTEXT_SIZE) { return $_[0]; }
	if ($verbosity > 1) {
		print STDERR sprintf("Long line %d: '%.50s(...)'\n", $line_no, $_[0])
	}
	$cato++;
	my $line = $_[0];
	my $pass = substr($line, $pos);
	my $hash = substr($line, 0, $pos);
	$line = substr($line, 0, $POT_BUFFER_CT_TRIM_SIZE) . '$SOURCE_HASH$';
	$line .= md5_hex($hash).$pass;
	return $line;
}
