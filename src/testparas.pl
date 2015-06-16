#!/usr/bin/perl -w
#
# Final output is a table in GitHub Markdown format
#
# Usage: ./testparas.pl [seconds]
#
# ../run/john will run with -test=seconds or just -test depending
# upon whether the seconds parameter is provided or not.
#
use strict;

my $compiler = `gcc -v 2>&1 | tail -1` or die;
print $compiler;

my ($i, $j, $k);
my ($out, $sp);
my %speed;
my %best;
my $test="first";
my $john_build;

print "This will take a while.\n";
print "Initial configure...\n";
print `./configure --disable-cuda --disable-opencl --enable-openmp-for-fast-formats >/dev/null` or die;
print `make -s clean` or die;
print "Initial build...\n";

foreach $i (1..5)
{
	print `rm -f sse-intrinsics.o nt2_fmt_plug.o MD5_*o pbkdf2*fmt*o dynamic*o ../run/john` or die;
	my $CPPFLAGS="-DSIMD_PARA_MD4=$i -DSIMD_PARA_MD5=$i -DSIMD_PARA_SHA1=$i -DSIMD_PARA_SHA256=$i -DSIMD_PARA_SHA512=$i";
	print `make -sj4 CPPFLAGS="$CPPFLAGS" nt2_fmt_plug.o` or die;
	$CPPFLAGS="-DSIMD_PARA_MD4=$i -DSIMD_PARA_MD5=$i -DSIMD_PARA_SHA1=$i -DSIMD_PARA_SHA256=$i -DSIMD_PARA_SHA512=$i -DOMP_SCALE=1";
	print `make -sj4 CPPFLAGS="$CPPFLAGS"` or die;
	if ($test eq "first") {
		system ("../run/john >JohnUsage.Scr 2>&1");
		open(FILE, "<JohnUsage.Scr") or die $!;
		my @johnUsageScreen = <FILE>;
		close(FILE);
		unlink("JohnUsage.Scr");
		$john_build = $johnUsageScreen[0];
		$test="-test";
		if ($ARGV[0] ne "") { $test="-test=$ARGV[0]"; }
	}
	print "\n== Speeds for ${i}x interleaving (OMP_SCALE 1 except NT): ==\n";
	foreach $j (qw(nt md5crypt pbkdf2-hmac-sha1 pbkdf2-hmac-sha256 pbkdf2-hmac-sha512))
	{
		$out = `../run/john $test -form:$j` or die;
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
	print `rm nt2_fmt_plug.o MD5_*o pbkdf2*fmt*o dynamic_fmt.o ../run/john` or die;
	$CPPFLAGS="-DSIMD_PARA_MD4=$i -DSIMD_PARA_MD5=$i -DSIMD_PARA_SHA1=$i -DSIMD_PARA_SHA256=$i -DSIMD_PARA_SHA512=$i -U_OPENMP";
	print `make -sj4 CPPFLAGS="$CPPFLAGS"` or die;
	print "\n===== Speeds for ${i}x interleaving (no OMP): =====\n";
	foreach $j (qw(nt md5crypt pbkdf2-hmac-sha1 pbkdf2-hmac-sha256 pbkdf2-hmac-sha512))
	{
		$out = `../run/john -test -form:$j` or die;
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

print "\n$compiler";
print "$john_build";
print "running john with \'$test\' for each test\n\n";
printf "%-22s |  %6d  |  %6d  |  %6d  |  %6d  |  %6d  |\n", "hash\\para", 1, 2, 3, 4, 5;
print "-----------------------|----------|----------|----------|----------|----------|\n";
foreach $j (qw(nt md5crypt pbkdf2-hmac-sha1 pbkdf2-hmac-sha256 pbkdf2-hmac-sha512))
{
	foreach $k ("", "-omp")
	{
		printf "%-22s |", $j.$k;
		foreach $i (1..5)
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
