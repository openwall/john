#!/usr/bin/perl
#
# Original code believed to be "(c) x7d8 sap loverz, public domain" (as noted in
# sapB_fmt_plug.c). Also Copyright (c) 2011, 2012 magnum, and hereby released to
# the general public under the following terms:  Redistribution and use in
# source and binary forms, with or without modification, are permitted.
#
# This perl script converts password hashes downloaded from SAP systems
# into a format suitable for John the Ripper (written to stdout).
#
# Usage: ./sap2john.pl <input-file> [A|B|D|E|F|H]
#
# To read from stdin instead, use: ./sap2john.pl - [A|B|D|E|F|H]
#
# To generate a suitable input file for this script, download
# the SAP hashes from one of the database tables USR02, USH02,
# or USRPWDHISTORY.
# Download the data as a spreadsheet using SAP transaction code SE16.
# Make sure to check the user settings: pick field names instead of
# field descriptions as column headings.
# If the SAP user names (which work as salts for CODVN A, B, D, E, F)
# contain non-ascii characters, please download the data using a
# single byte code page if you want to crack CODVN A or CODVN B hashes.
# Download the data using utf-8 (SAP code page 4110), if you want
# to crack CODVN F, CODVN E, or CODVN D hashes (or if you want to crack
# CODVN H hashes. (For CODVN H, the user name ist't used as a salt
# anymore.)
#
# CODVN G just means, the system computes and stores CODVN B and
# CODVN F hashes.
# (In this case, the script will create two lines of output.)
# CODVN I means, the system computes and stores CODVN B, CODVN F, and
# CODVN H hashes.
# (In this case, the script will create three lines of output.)
#
# If CODVN is empty (or the column is missing), but BCODE is filled,
# the script assumes that the corresponding hash is a CODVN B hash,
# but for very old USH02 records (created before around 1996)
# probably CODVN A was in use.
#
#
# If you omit the optional parameter, the script generates output
# for all codvn F and codvn H hashes, as well as for all the
# CODVN B hashes (including hashes where the script assumes CODVN B
# because the CODVN column is missing or empty).
# That means, the default implementation will mix up to 3 different
# hash formats into the output file, but since these formats
# are not ambiguous, that is not a problem.
# John the Ripper (jumbo) currently supports these SAP hash formats:
#         SAP CODVN B (--format=sapb)
#         SAP CODVN F (--format=sapg)
#         SAP CODVN H (--format=saph)
# John the Ripper (jumbo) doesn't support these SAP hash formats
#         SAP CODVN A (obsolete)
#         SAP CODVN D (obsolete)
#         SAP CODVN E (may still be used for older SAP releases)
#
# When running ./sap2john.pl with just a file name as a parameter,
# CODVN A, D, and E hashes will be skipped, because these hashes
# are currently not supported, and because these hashes would
# be considered as valid CODVN B hashes by the current sapB_fmt_plug.c
# implementation. (A format tag would need to be added to distinguish
# these hash formats).
#
# By specifying the optional parameter, you can decide which
# SAP hash format will be written to stdout instead of the default
# hash formats.
# So, running
#         ./sap2john.pl <input-file>
# is the same as running
#         ./sap2john.pl <input-file> BFH
# And
#         ./sap2john.pl <input-file> E
# would just extract the SAP CODVN E hashes.
#
#
# FIXME: should the script generate different lines of output
#        for the current password (e.g. uid=0, gid=$mandt[$i])
#        and for older passwords (ocod1-ocod5, or USH02
#        (column MODDA or MODTI exists) or USRPWDHISTORY
#        (column TIMESTAMP exists)

use warnings;

sub fill_field
{
	if ($_[0] == -1 || $_[0] > $#tmp) {
		$_[1] = "";
	}
	else {
		$_[1] = $tmp[$_[0]];
		$_[1] =~ s/\s*$//;
	}
}

sub write_pwdsaltedhash
{
	if ($hashtypes =~ /H/ && $pwdsaltedhash[$i] ne "") {
		print "$bname[$i]:$pwdsaltedhash[$i]\n";
	}
}

sub write_passcode
{
# FIXME: prefix hash with "sapF$", to avoid ambiguity with other hash formats?
	if ($hashtypes =~ /F/ && $passcode[$i] ne "0000000000000000000000000000000000000000") {
		print "$bname[$i]:$bname[$i]\$$passcode[$i]\n";
	}
}

sub write_bcode
{
# FIXME: prefix CODVN A/D/E(/B) hashes with "sap<CODVN>$"?
	$vn = $_[1];
	$bc = $_[0];
	if ($vn eq "" || $vn eq "G" or $vn eq "I") { $vn = "B" }
	if ($hashtypes =~ /$vn/) {
		if ($bc ne "" && $bc ne "0000000000000000") {
			print "$bname[$i]:$bname[$i]\$$bc\n";
		}
	}
}
if ($#ARGV < 0 || $#ARGV > 1) {
	die "Usage: $0 <input-file> [A|B|D|E|F|H]\n";
}

open INPUT_FILE, "$ARGV[0]" or die "Can't open input-file ($ARGV[0])\n";

if ($#ARGV == 1) {
	$hashtypes = $ARGV[1];
	if ($hashtypes =~ /^[^ABDEFH]$/) {
		die "invalid optional parameter: \"$hashtypes\"\n";
	}
}
else {
	$hashtypes = "";
}

$line = "";
$count = 0;

# USR01, USH02, USRPWDHISTORY
#$pos_mandt = -1;
$pos_bname = -1;
$pos_bcode = -1;
$pos_passcode = -1;
$pos_pwdsaltedhash = -1;

# USR02
$pos_codvn = -1;
$pos_ocod1 = -1;
$pos_codv1 = -1;
$pos_ocod2 = -1;
$pos_codv2 = -1;
$pos_ocod3 = -1;
$pos_codv3 = -1;
$pos_ocod4 = -1;
$pos_codv4 = -1;
$pos_ocod5 = -1;
$pos_codv5 = -1;

# USH02
#$pos_modda = -1;
#$pos_modti = -1;

# USRPWDHISTORY
#$pos_timestamp = -1;

until ($line =~ /\t/) {
	$line=<INPUT_FILE>;
	$count++;
}

chomp($line);
$line =~ s/\r//;

# column names can be either left-justified or right-justified,
# so let's remove spaces as well:
@tmp = split(/\s*\t\s*/, $line);

$columns = $#tmp;

for($i = 0; $i <= $columns; $i++) {
	if    ($tmp[$i] =~ /BNAME/) { $pos_bname = $i }
#	elsif ($tmp[$i] =~ /MANDT/) { $pos_mandt = $i }
	elsif ($tmp[$i] =~ /BCODE/) { $pos_bcode = $i }
	elsif ($tmp[$i] =~ /CODVN/) { $pos_codvn = $i }
	elsif ($tmp[$i] =~ /PASSCODE/) { $pos_passcode = $i }
	elsif ($tmp[$i] =~ /PWDSALTEDHASH/) { $pos_pwdsaltedhash = $i }
	elsif ($tmp[$i] =~ /OCOD1/) { $pos_ocod1 = $i }
	elsif ($tmp[$i] =~ /CODV1/) { $pos_codv1 = $i }
	elsif ($tmp[$i] =~ /OCOD2/) { $pos_ocod2 = $i }
	elsif ($tmp[$i] =~ /CODV2/) { $pos_codv2 = $i }
	elsif ($tmp[$i] =~ /OCOD3/) { $pos_ocod3 = $i }
	elsif ($tmp[$i] =~ /CODV3/) { $pos_codv3 = $i }
	elsif ($tmp[$i] =~ /OCOD4/) { $pos_ocod4 = $i }
	elsif ($tmp[$i] =~ /CODV4/) { $pos_codv4 = $i }
	elsif ($tmp[$i] =~ /OCOD5/) { $pos_ocod5 = $i }
	elsif ($tmp[$i] =~ /CODV5/) { $pos_codv5 = $i }
#	elsif ($tmp[$i] =~ /MODDA/) { $pos_modda = $i }
#	elsif ($tmp[$i] =~ /MODTI/) { $pos_modti = $i }
#	elsif ($tmp[$i] =~ /TIMESTAMP/) { $pos_timestamp = $i }
}

if (-1 == $pos_bcode &&
    -1 == $pos_ocod1 && -1 == $pos_ocod2 && -1 == $pos_ocod3 &&
    -1 == $pos_ocod4 && -1 == $pos_ocod5) {
	if (-1 == $pos_passcode && -1 == $pos_pwdsaltedhash) {
		die "no password hash columns found\n";
	}
	elsif ($hashtypes eq "B" || $hashtypes eq "E" ||
	       $hashtypes eq "D" || $hashtypes eq "A") {
		die "CODVN B, E, D, or A requested, but column BCODE/OCODV[1-5] not found\n";
	}
}

if (-1 == $pos_bname && -1 == $pos_pwdsaltedhash) {
	die "no BNAME column found, but required as salt for BCOCE and PASSCODE\n";
}

if (-1 == $pos_passcode && $hashtypes =~ /F/) {
	die "CODVN F requested, but column PASSCODE not found\n";
}

if (-1 == $pos_pwdsaltedhash && $hashtypes =~ /H/) {
	die "CODVN H requested, but column PWDSALTEDHASH not found\n";
}

if ($hashtypes eq "") {
# FIXME: Should I use ABDEFH as a default, and prefix
#        the hashes with sapA$, sapD$, sapD$ for codvn A/D/E?
#        OTOH, if user names contain non-ascii characters,
#        the JtR user might want to split formats requiring utf-8 input
#        and formats requiring iso-8859* input into different files
#        anyway.
	$hashtypes = "BFH";
}
if (-1 == $pos_bname) { $hashtypes =~ s/[ABDEF]//g }
if (-1 == $pos_pwdsaltedhash) { $hashtypes =~ s/H// }

if ($hashtypes eq "") {
	die "not all required columns for requested hash types found\n";
}

$rows = -1;
while ($line = <INPUT_FILE>) {
	$count++;
	chomp($line);
	$line =~ s/\r//;

	@tmp = split(/\t/, $line);
	if ($#tmp >= 0) {
		$rows++;
#		fill_field( $pos_mandt, $mandt[$rows]);
		fill_field( $pos_bname, $bname[$rows]);
		fill_field( $pos_codvn, $codvn[$rows]);
		fill_field( $pos_bcode, $bcode[$rows]);
		fill_field( $pos_passcode, $passcode[$rows]);
		fill_field( $pos_pwdsaltedhash, $pwdsaltedhash[$rows]);
		fill_field( $pos_ocod1, $ocod1[$rows]);
		fill_field( $pos_codv1, $codv1[$rows]);
		fill_field( $pos_ocod2, $ocod2[$rows]);
		fill_field( $pos_codv2, $codv2[$rows]);
		fill_field( $pos_ocod3, $ocod3[$rows]);
		fill_field( $pos_codv3, $codv3[$rows]);
		fill_field( $pos_ocod4, $ocod4[$rows]);
		fill_field( $pos_codv4, $codv4[$rows]);
		fill_field( $pos_ocod5, $ocod5[$rows]);
		fill_field( $pos_codv5, $codv5[$rows]);
#		fill_field( $pos_modda, $modda[$rows]);
#		fill_field( $pos_modti, $modti[$rows]);
#		fill_field( $pos_timestamp, $timestamp[$rows]);
	}
}

# Should the script count the number of valid hashes found/written to stdout,
# to write summary information to stderr?
#
#$codvn_a = 0;
#$codvn_b = 0;
#$codvn_d = 0;
#$codvn_e = 0;
#$codvn_f = 0;
#$codvn_h = 0;

for ($i=0; $i<=$rows; $i++) {
# write BCODE first, so that hopefully codvn B (the easiest to crack
# hash algorithm) will be detected first...
	write_bcode( $bcode[$i], $codvn[$i] );
	write_bcode( $ocod1[$i], $codv1[$i] );
	write_bcode( $ocod2[$i], $codv2[$i] );
	write_bcode( $ocod3[$i], $codv3[$i] );
	write_bcode( $ocod4[$i], $codv4[$i] );
	write_bcode( $ocod5[$i], $codv5[$i] );

	write_passcode( );
#	even if this format is currently not supported by JtR,
#	it might be in future:
	write_pwdsaltedhash( );
}
