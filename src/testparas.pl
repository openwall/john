#!/usr/bin/perl -w
#
# Final output is a table in GitHub Markdown format
#
use strict;

my $compiler = `gcc -v 2>&1 | tail -1` or die;
print $compiler;

my ($i, $j);
my %speed;
my %best;

foreach $i (1..5)
{
	my $CPPFLAGS="-DSIMD_PARA_MD4=$i -DSIMD_PARA_MD5=$i -DSIMD_PARA_SHA1=$i -DSIMD_PARA_SHA256=$i -DSIMD_PARA_SHA512=$i -DOMP_SCALE=1";
	print `./configure CPPFLAGS="$CPPFLAGS" --disable-cuda --disable-opencl >/dev/null` or die;
	print `make -s clean` or die;
	print `make -sj4` or die;

	print "\n===== Speeds for ${i}x interleaving: =====\n";
	foreach $j (qw(nt md5crypt pbkdf2-hmac-sha1 pbkdf2-hmac-sha256 pbkdf2-hmac-sha512))
	{
		my $out = `../run/john -test -form:$j` or die;
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
	}
}

print "\n", $compiler, "\n";
printf "%-18s |  %6d  |  %6d  |  %6d  |  %6d  |  %6d  |\n", "hash\\para", 1, 2, 3, 4, 5;
print "-------------------|----------|----------|----------|----------|----------|\n";
foreach $j (qw(nt md5crypt pbkdf2-hmac-sha1 pbkdf2-hmac-sha256 pbkdf2-hmac-sha512))
{
	printf "%-18s |", $j;
	foreach $i (1..5)
	{
		if ($best{$j}{"para"} == $i)
		{
			$speed{$j}{$i} = "**".$speed{$j}{$i}."**";
			printf "%10s|", $speed{$j}{$i};
		} else {
			printf "  %6s  |", $speed{$j}{$i};
		}
	}
	print "\n";
}
print "\n";
