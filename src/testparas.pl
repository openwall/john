#!/usr/bin/perl -w
#
# Final output is a table in GitHub Markdown format
#
use strict;

my $compiler = `gcc -v 2>&1 | tail -1` or die;
print $compiler;

my ($i, $j, $k);
my %speed;
my %best;

foreach $i (1..5)
{
	my $CPPFLAGS="-DSIMD_PARA_MD4=$i -DSIMD_PARA_MD5=$i -DSIMD_PARA_SHA1=$i -DSIMD_PARA_SHA256=$i -DSIMD_PARA_SHA512=$i -DOMP_SCALE=1";
	print `./configure CPPFLAGS="$CPPFLAGS" --disable-cuda --disable-opencl --enable-openmp-for-fast-formats >/dev/null` or die;
	print `make -s clean` or die;
	print `make -sj4` or die;

	print "\n===== Speeds for ${i}x interleaving: =====\n";
	foreach $j (qw(nt md5crypt pbkdf2-hmac-sha1 pbkdf2-hmac-sha256 pbkdf2-hmac-sha512))
	{
		my $out = `OMP_NUM_THREADS=1 ../run/john -test -form:$j` or die;
		print $out;
		$out =~ s/.*^Raw:\t(\d+K?).*/$1/ms;
		$speed{$j}{$i} = $out;
		my $sp = $out;
		$sp =~ s/K/000/;
		if (!defined $best{$j}{"speed"} || ($best{$j}{"speed"} < $sp))
		{
			$best{$j}{"speed"} = $sp;
			$best{$j}{"para"} = $i;
		}
		$out = `../run/john -test -form:$j` or die;
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
}

print "\n", $compiler, "\n";
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
