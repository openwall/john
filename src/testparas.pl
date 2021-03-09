#!/usr/bin/perl
#
# Final output is a table in GitHub Markdown format
#
# Usage: ./testparas.pl [seconds] [num cpus (for -j)]
#
# ../run/john will run with -test=seconds or just -test depending
# upon whether the seconds parameter is provided or not.

use warnings;
use strict;

my $compiler = `gcc -v 2>&1 | tail -1` or die;
my $MAX_PARA = 5;
my ($i, $j, $k);
my ($out, $sp);
my %speed;
my %best;
my $test="-test";
my $john_build;
my $default_para = "";
my $gomp_stuff = "";
my $num_cpus = 8;

if (defined($ARGV[0]) && $ARGV[0] > 0) { $test="-test=$ARGV[0]"; }
if (defined($ARGV[1]) && $ARGV[1] > 0) { $num_cpus = $ARGV[1]; }

print "This will take a while.\n";
print "Initial configure...\n";
print `./configure --disable-opencl >/dev/null` or die;
print "Initial build...\n";
print `make -s clean && make -sj${num_cpus}` or die;
system ("../run/john >JohnUsage.Scr 2>&1");
open(FILE, "<JohnUsage.Scr") or die $!;
my @johnUsageScreen = <FILE>;
close(FILE);
unlink("JohnUsage.Scr");
$john_build = $johnUsageScreen[0];
$default_para = "Default paras: " . `../run/john --list=build-info | grep interl`;

if (defined $ENV{OMP_NUM_THREADS}) {
	$gomp_stuff .= "OMP_NUM_THREADS=" . $ENV{OMP_NUM_THREADS} . " ";
}
if (defined $ENV{GOMP_CPU_AFFINITY}) {
	$gomp_stuff .= "GOMP_CPU_AFFINITY=" . $ENV{GOMP_CPU_AFFINITY};
}

print "Here we go...\n";

foreach $i (1..$MAX_PARA)
{
	print `rm -f simd-intrinsics.o pbkdf2*fmt*o dynamic*o ../run/john` or die;
	my $CPPFLAGS="-DSIMD_PARA_MD4=$i -DSIMD_PARA_MD5=$i -DSIMD_PARA_SHA1=$i -DSIMD_PARA_SHA256=$i -DSIMD_PARA_SHA512=$i -DOMP_SCALE";
	print `make -sj${num_cpus} CPPFLAGS="$CPPFLAGS"` or die;
	print "\n== Speeds for ${i}x interleaving (OMP_SCALE 1): ==\n";
	foreach $j (qw(md4 md5 sha1 sha256 sha512))
	{
		$out = `../run/john $test -form:pbkdf2-hmac-$j` or die;
		print $out;
		$out =~ s/.*^Raw:\t(\d+K?).*/$1/ms;
		$speed{$j."-omp"}{$i} = $out;
		$sp = $out;
		$sp =~ s/K/000/;
		if (!defined $best{$j."-omp"}{"speed"} || ($best{$j."-omp"}{"speed"} < $sp))
		{
			$best{$j."-omp"}{"speed"} = $sp;
			$best{$j."-omp"}{"para"} = $i;
		}
	}
	print `rm pbkdf2*fmt*o ../run/john` or die;
	$CPPFLAGS="-DSIMD_PARA_MD4=$i -DSIMD_PARA_MD5=$i -DSIMD_PARA_SHA1=$i -DSIMD_PARA_SHA256=$i -DSIMD_PARA_SHA512=$i -U_OPENMP";
	print `make -sj${num_cpus} CPPFLAGS="$CPPFLAGS"` or die;
	print "\n===== Speeds for ${i}x interleaving (no OMP): =====\n";
	foreach $j (qw(md4 md5 sha1 sha256 sha512))
	{
		$out = `../run/john -test -form:pbkdf2-hmac-$j` or die;
		print $out;
		$out =~ s/.*^Raw:\t(\d+K?).*/$1/ms;
		$speed{$j}{$i} = $out;
		$sp = $out;
		$sp =~ s/K/000/;
		if (!defined $best{$j}{"speed"} || ($best{$j}{"speed"} < $sp))
		{
			$best{$j}{"speed"} = $sp;
			$best{$j}{"para"} = $i;
		}
	}
}
print `make -s clean`;

print "\n$compiler";
print $john_build;
print $default_para;
if ($test ne "-test") {
	print "running john with \'$test\' for each test\n";
}
if ($gomp_stuff) {
	print "$gomp_stuff\n";
}
printf "\n%-10s |  %6d  |  %6d  |  %6d  |  %6d  |  %6d  |\n", "hash\\para", 1, 2, 3, 4, 5;
print "-----------|----------|----------|----------|----------|----------|\n";
foreach $j (qw(md4 md5 sha1 sha256 sha512))
{
	foreach $k ("", "-omp")
	{
		printf "%-10s |", $j.$k;
		foreach $i (1..$MAX_PARA)
		{
			if ($best{$j.$k}{"para"} == $i)
			{
				$speed{$j.$k}{$i} = "**".$speed{$j.$k}{$i}."**";
				printf "%10s|", $speed{$j.$k}{$i};
			} else {
				printf "  %6s  |", $speed{$j.$k}{$i};
			}
		}
		print "\n";
	}
}
print "\n";
print "Suggested command line for configure:\n";
print "./configure CPPFLAGS=\"";
foreach $j (qw(md4 md5 sha1 sha256 sha512)) {
	print "-DSIMD_".uc($j)."_PARA=".$best{$j."-omp"}{"para"};
	print " " unless $j eq "sha512";
}
print "\"\n";
