#!/usr/bin/perl

use warnings;
use strict;
use Encode;
use Switch;
use Unicode::Normalize;
use utf8;  # This source file MUST be stored UTF-8 encoded

###############################################################################
# code page data builder, by magnum / JimF.   v1.2
# August 8, added parsing of ./UnicodeData.txt for building more macros
# Coded July-Aug 2011, as a tool to build codepage encoding data needed
# for John the Ripper code page conversions.  The data output from this file
# is made to be directly placed into the ./src/encoding_data.h file in john's
# source tree.
# UnicodeData.txt is an official Unicode definition file and can be found at
# ftp://ftp.unicode.org/Public/UNIDATA/UnicodeData.txt
# USAGE:  cmpt_cp.pl [-v] CODEPAGE
# cmpt_cp.pl run without any arguments will show a list of possible code pages.
###############################################################################

# This should set our output to your terminal settings
use open ':locale';

# Set to 1 to permanently enable Unicode comments
my $verbose = 1;
if ($ARGV[0] eq "-v") {
	$verbose++;
	shift;
}

my $enc;
if (@ARGV==1) {$enc=$ARGV[0];}
else {
	print "Supported encodings:\n", join(", ", Encode->encodings(":all")), "\n\n";
	exit(0);
}

my %cat;
my $filename = "UnicodeData.txt";
my @subdirs = qw(unused Unicode);
my $subdir = ".";
foreach my $sd (@subdirs) {
    if (-f "${sd}/${filename}" ) {
	$subdir = $sd;
    }
}
open FILE, "$subdir/$filename" or die $!;
while (my $line = <FILE>) {
	next if substr($line,0,1) eq "#";
	my @line = split(';', $line);
	$cat{hex($line[0])} = $line[2];
}

sub lookupCategory {
	my $c = shift;
	return $cat{$c};
}

sub printdef {
	my $param = shift;
	if (length($param)>80) {print" \\\n\t";}
	elsif (length($param)>0) {print" ";}
	if (length($param)>0)  {print "\"".$param."\"";}
}

sub printdef_null {
	my $param = shift;
	if (length($param)>80) {print" \\\n\t";}
	else {print" ";}
	print "\"".$param."\"";
}

my $to_unicode_high128="";
my $lower="";  my $upper="";  my $lowonly="";  my $uponly="";  my $specials = "";  my $punctuation = "";  my $alpha = "";  my $digits = "";  my $control = "";  my $invalid = ""; my $whitespace = ""; my $vowels = "\\x59\\x79"; my $consonants = ""; my $nocase = "";
my $clower=""; my $cupper=""; my $clowonly=""; my $cuponly=""; my $cspecials = ""; my $cpunctuation = ""; my $calpha = ""; my $cdigits = ""; my $cvowels = "Yy"; my $cconsonants = ""; my $cnocase = "";
my $encu = uc($enc);my $hs = "";
$encu =~ s/-/_/g;
#######################################
# first step, compute the unicode array
#######################################
foreach my $i (0x80..0xFF) {
	my $u = chr($i);
	$u = Encode::decode($enc, $u);
	$hs .= $u;
	if (ord($u) == 0xfffd) {
		$u = chr($i);
	}
	$to_unicode_high128 .= "0x" . sprintf "%04X", ord($u);
	if ($i % 16 == 15 && $i != 255) { $to_unicode_high128 .= ",\n"; }
	elsif ($i != 255) { $to_unicode_high128 .= ","; }
}
if ($verbose) {
	print "\n// "; foreach (8..9, 'A'..'F') { print $_, " "x15 };
	print "\n// "; foreach (8..9, 'A'..'F') { print '0'..'9','A'..'F' };
	print "\n// ", $hs, "\n";
}
print "\n// here is the $encu to Unicode conversion for $encu characters from 0x80 to 0xFF\n";
print "static const UTF16 ".$encu."_to_unicode_high128[] = {\n";
print $to_unicode_high128 . " };\n";

#################################
# Now build upcase/downcase data.
#################################
foreach my $i (0x80..0xFF) {
	my $c = chr($i);
	# converts $c into utf8, from $enc code page, and 'sets' the 'flag' in perl that $c IS a utf8 char.
	$c = Encode::decode($enc, $c);

	# upcase and low case the utf8 chars
	my $ulc = lc $c; my $uuc = uc $c;
	# reconvert the utf8 char's back into $enc code page.
	my $elc = Encode::encode($enc, $ulc); my $euc = Encode::encode($enc, $uuc);
	if ( (chr($i) eq $elc || chr($i) eq $euc) && $elc ne $euc) {
	    if (chr($i) ne $euc) {
			if (chr($i) ne $elc && chr($i) ne $euc) {
				no warnings;
				printf("// *** WARNING, char at 0x%X U+%04X (%s) needs to be looked into. Neither conversion gets back to original value!\n",$i,ord($c), $c);
			} elsif ( length($euc) > 1) {
				$lowonly .= sprintf("\\x%02X", ord($elc));
				$clowonly .= $c;
				printf("// *** WARNING, char at 0x%X U+%04X (%s -> %s) needs to be looked into.  Single to multi-byte conversion\n",$i,ord($c), $ulc, $uuc);
			} elsif ( length($elc) > 1) {
				$uponly .= sprintf("\\x%02X", ord($euc));
				$cuponly .= $c;
				printf("// *** WARNING, char at 0x%X U+%04X (%s -> %s) needs to be looked into.  Single to multi-byte conversion\n",$i,ord($c), $ulc, $uuc);
			} elsif ( ord($euc) < 0x80) {
				$lowonly .= sprintf("\\x%02X", ord($elc));
				$clowonly .= $c;
				if (ord($euc) != 0x3f) {
					printf("// *** WARNING, char at 0x%X -> U+%04X -> U+%04X -> 0x%X (%s -> %s) needs to be looked into.  Likely one way casing conversion\n",$i,ord($ulc),ord($uuc),ord($euc), $ulc, $uuc);
				}
			} elsif ( ord($elc) < 0x80) {
				$uponly .= sprintf("\\x%02X", ord($euc));
				$cuponly .= $c;
				if (ord($elc) != 0x3f) {
					printf("// *** WARNING, char at 0x%X -> U+%04X -> U+%04X -> 0x%X (%s -> %s) needs to be looked into.  Likely one way casing conversion\n",$i,ord($ulc),ord($uuc),ord($euc), $ulc, $uuc);
				}
			} else {
				$lower .= sprintf("\\x%02X", ord($elc));
				$clower .= lc($c);
				$upper .= sprintf("\\x%02X", ord($euc));
				$cupper .= uc($c);
			}
		}
	} else {
		# NOTE, we can have letters which fail above.  Examples are U+00AA, U+00BA.  These are letters, lower case only, and there IS no upper case.
		# this causes the original if to not find them. Thus, we 'look them up' here.
		my $cat = lookupCategory(ord($c));
		#printf STDERR "Category: $cat\n";
		switch ($cat) {
			case /^Ll/ { $lowonly .= sprintf("\\x%02X", ord($elc)); $clowonly .= $c; }
			case /^Lu/ { $uponly  .= sprintf("\\x%02X", ord($euc)); $cuponly  .= $c; }
			else {}
		}
	}

	if (ord($c) == 0xfffd) {
		$invalid .= sprintf("\\x%02X", $i);
	} else {
		my $cat = lookupCategory(ord($c));
		switch ($cat) {
			case /^Cf/ { $specials .= sprintf("\\x%02X", $i); $cspecials .= $c }
			case /^L[lotu]/ {
				$alpha .= sprintf("\\x%02X", $i);
				$calpha .= $c;
				if ($cat =~ /^Lo/) {
					$nocase .= sprintf("\\x%02X", $i); $cnocase .= $c
				}
				# best-effort vowel/consonant matching
				# We normalize to decomposed and match known vowels in lc
				my $nfd = substr(NFD($c), 0, 1);
				# Done: Latin, Nordic, Greek, Russian, Ukrainian, Turkish
				if ($nfd =~ m/[aoueiyœæøɪʏɛɔαεηιοωυаэыуояеюиєіı]/i) {
					$vowels .= sprintf("\\x%02X", $i);
					$cvowels .= $c;
					# Note, e.g., in English, y depends on situation
					# (yellow, happy). We set latin yY variants as both!
					if ($nfd =~ m/y/i) {
						$consonants .= sprintf("\\x%02X", $i);
						$cconsonants .= $c;
					}
				} else {
					$consonants .= sprintf("\\x%02X", $i);
					$cconsonants .= $c;
				}
			}
			case /^Lm/ { $specials .= sprintf("\\x%02X", $i); $cspecials .= $c }
			#case /^Ll/ { $lower .= sprintf("\\x%02X", $i); }
			#case /^L[tu]/ { $upper .= sprintf("\\x%02X", $i); }
			case /^M[cen]/ { $specials .= sprintf("\\x%02X", $i); $cspecials .= $c }
			case /^S[ckmo]/ { $specials .= sprintf("\\x%02X", $i); $cspecials .= $c }
			case /^N[dlo]/ { $digits .= sprintf("\\x%02X", $i); $cdigits .= $c }
			case /^P[cdefios]/ { $punctuation .= sprintf("\\x%02X", $i); $cpunctuation .= $c }
			case /^Z[lps]/ { $whitespace .= sprintf("\\x%02X", $i); }
			case /^C/ { $control .= sprintf("\\x%02X", $i); }
			else { print STDERR "*** Warning, $cat not handled\n"; }
		}
	}
}
print "\n// $clower\n" if $verbose;
print "#define CHARS_LOWER_".$encu;
printdef_null($lower);
print "\n";

print "\n// $clowonly\n" if $verbose;
print "#define CHARS_LOW_ONLY_".$encu;
printdef($lowonly);
print "\n";

print "\n// $cupper\n" if $verbose;
print "#define CHARS_UPPER_".$encu;
printdef_null($upper);
print "\n";

print "\n// $cuponly\n" if $verbose;
print "#define CHARS_UP_ONLY_".$encu;
printdef($uponly);
print "\n";

print "\n// $cnocase\n" if $verbose;
print "#define CHARS_NOCASE_".$encu;
printdef($nocase);
print "\n";

print "\n// $cdigits\n" if $verbose;
print "#define CHARS_DIGITS_".$encu;
printdef_null($digits);
print "\n";

print "\n// $cpunctuation\n" if $verbose;
print "#define CHARS_PUNCTUATION_".$encu;
printdef($punctuation);
print "\n";

print "\n// $cspecials\n" if $verbose;
print "#define CHARS_SPECIALS_".$encu;
printdef($specials);
print "\n";

print "\n// $calpha\n" if $verbose;
print "#define CHARS_ALPHA_".$encu;
printdef($alpha);
print "\n";

print "\n" if $verbose;
print "#define CHARS_WHITESPACE_".$encu;
printdef($whitespace);
print "\n";

print "\n" if $verbose;
print "#define CHARS_CONTROL_".$encu;
printdef($control);
print "\n";

print "\n" if $verbose;
print "#define CHARS_INVALID_".$encu;
printdef_null($invalid);
print "\n";

print "\n// $cvowels\n" if $verbose;
print "#define CHARS_VOWELS_".$encu;
printdef($vowels);
print "\n";

print "\n// $cconsonants\n" if $verbose;
print "#define CHARS_CONSONANTS_".$encu;
printdef($consonants);
print "\n";

####################################################################
# Ok, provide a check to see if any of the characters UNDER 0x80
# are non-standard.  At this time, there is no plan on HOW to handle
# this within john.  The information is simply listed at this time.
####################################################################
foreach my $i (0x20..0x7E) {
	my $u = chr($i);
	Encode::from_to($u, $enc, "utf8");
	my $str = sprintf "%04X", ord Encode::decode("UTF-8", $u);
	if ( hex($str) != $i) { printf("WARNING, low character %X maps into Unicode 0x%s\n", $i, $str);}
}
