#!/usr/bin/perl

# This script will stack rules from john's .conf file. (2 3 or 4 sections get stacked)

use warnings;
use File::Basename;
use lib dirname(__FILE__).'/';
use lib dirname(__FILE__).'/../run';
use jtrconf;

# example of how easy it is to use this lib:
#jtrconf::load();
#my @s = jtrconf::getsection("List.Rules:jumbosingle");
#print "[List.Rules:jumbosingle]\n@s\n\n";
#my $s = jtrconf::getparam("Options", "WordlistMemoryMap");
#print "WordlistMemoryMap = $s\n";
#exit 0;

print "[List.Rules:Stacked]\n";
jtrconf::load();
if (@ARGV == 2) {
	RulesStack2($ARGV[0], $ARGV[1]);
}

if (@ARGV == 3) {
	RulesStack2($ARGV[0], $ARGV[1]);
	RulesStack2($ARGV[0], $ARGV[2]);
	RulesStack2($ARGV[1], $ARGV[2]);
	RulesStack3($ARGV[0], $ARGV[1], $ARGV[2]);
}

if (@ARGV == 4) {
	RulesStack2($ARGV[0], $ARGV[1]);
	RulesStack2($ARGV[0], $ARGV[2]);
	RulesStack2($ARGV[0], $ARGV[3]);
	RulesStack2($ARGV[1], $ARGV[2]);
	RulesStack2($ARGV[1], $ARGV[3]);
	RulesStack2($ARGV[2], $ARGV[3]);
	RulesStack3($ARGV[0], $ARGV[1], $ARGV[2]);
	RulesStack3($ARGV[0], $ARGV[1], $ARGV[3]);
	RulesStack3($ARGV[0], $ARGV[2], $ARGV[3]);
	RulesStack3($ARGV[1], $ARGV[2], $ARGV[3]);
	RulesStack4($ARGV[0], $ARGV[1], $ARGV[2], $ARGV[3]);
}

sub RulesStack2 {
	my @ar1 = jtrconf::getsection("list.rules:".$_[0]);
	my @ar2 = jtrconf::getsection("list.rules:".$_[1]);
	chomp @ar1; chomp @ar2;
	for (my $i = 0; $i < @ar1; ++$i) {
		for (my $j = 0; $j < @ar2; ++$j) {
			print "$ar1[$i] $ar2[$j]\n";
		}
	}
}
sub RulesStack3 {
	my @ar1 = jtrconf::getsection("list.rules:".$_[0]);
	my @ar2 = jtrconf::getsection("list.rules:".$_[1]);
	my @ar3 = jtrconf::getsection("list.rules:".$_[2]);
	chomp @ar1; chomp @ar2; chomp @ar3;
	for (my $i = 0; $i < @ar1; ++$i) {
		for (my $j = 0; $j < @ar2; ++$j) {
			for (my $k = 0; $k < @ar3; ++$k) {
				print "$ar1[$i] $ar2[$j] $ar3[$k]\n";
			}
		}
	}
}
sub RulesStack4 {
	my @ar1 = jtrconf::getsection("list.rules:".$_[0]);
	my @ar2 = jtrconf::getsection("list.rules:".$_[1]);
	my @ar3 = jtrconf::getsection("list.rules:".$_[2]);
	my @ar4 = jtrconf::getsection("list.rules:".$_[3]);
	chomp @ar1; chomp @ar2; chomp @ar3; chomp @ar4;
	for (my $i = 0; $i < @ar1; ++$i) {
		for (my $j = 0; $j < @ar2; ++$j) {
			for (my $k = 0; $k < @ar3; ++$k) {
				for (my $l = 0; $l < @ar4; ++$l) {
					print "$ar1[$i] $ar2[$j] $ar3[$k] $ar4[$l]\n";
				}
			}
		}
	}
}
