#!/usr/bin/env perl
#
# this script will compare speed between a dynamic format using
# the dynamic_x and (same) format using the dynamic=expr(xxx)

use warnings;

if (scalar @ARGV != 2) { die( "error, usage: dyna-speed.pl dynamic_# dynamic=expr\n" ); }

my $first = `../run/john -test=3 -format=$ARGV[0]`;
my $second = `../run/john -test=3 -format=\'$ARGV[1]\'`;

# compute
my $percent=1; my $percent2=0;
if (index($first, "Raw:") != -1&&index($second, "Raw:") != -1) {
	my $p1 = substr($first, index($first, "Raw:")+5);
	my $p2 = substr($second, index($second, "Raw:")+5);
	$percent = $p1 / $p2;
}
if (index($first, "Many salts:")!=-1 && index($second, "Many salts:")!=-1) {
	my $p1 = substr($first, index($first, "Many salts:")+12);
	my $p2 = substr($second, index($second, "Many salts:")+12);
	$percent = $p1 / $p2;
}
if (index($first, "Only one salt:")!=-1 && index($second, "Only one salt:")!=-1) {
	my $p1 = substr($first, index($first, "Only one salt:")+15);
	my $p2 = substr($second, index($second, "Only one salt:")+15);
	$percent2 = $p1 / $p2;
}
$percent=substr($percent, 0, 5);

if ($percent2 > 0) { $percent2=substr($percent2, 0, 5); print "$ARGV[0] vs $ARGV[1] was $percent"." x  and $percent2". " x\n"; }
else { print "$ARGV[0] vs $ARGV[1] was $percent"." x\n"; }

#print "$first\n$second\n";
