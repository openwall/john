#!/usr/bin/env perl

use warnings;
use strict;

open FILE, "<", $ARGV[0] or die;
my @file = <FILE>;
close FILE;

# 's/^\(struct fmt_main [^ ]*\) =.*/extern \1;/p'
# 's/^struct fmt_main \([^ ]*\) =.*/john_register_one(\&\1);/p'
my @struct = grep(/^struct fmt_main [^ ]+ =.*/, @file);
my $decl = "#if FMT_EXTERNS_H\n";
my $reg = "#elif FMT_REGISTERS_H\n";
foreach my $s (@struct) {
	$s =~ m/^(struct fmt_main [^ ]+) =.*/;
	$decl .= "extern $1;\n";
	$s =~ m/^struct fmt_main ([^ ]+) =.*/;
	$reg .= "john_register_one(&$1);\n";
}

my $new = "";
if (defined $ARGV[1]) {
	$new .= "#ifdef $ARGV[1]\n\n";
}
$new .= $decl . $reg . "#else\n\n";
my $p = 0;
open FILE, ">", $ARGV[0] or die;

foreach (@file) {
	if ($p == 0 && m/^#/) {
		$p = 1;
		print FILE "$new";
	}
	print FILE "$_";
}
print FILE "\n#endif /* plugin stanza */\n";
if (defined $ARGV[1]) {
	print FILE "\n#endif /* $ARGV[1] */\n";
}
close FILE;
