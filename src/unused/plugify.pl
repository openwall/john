#!/usr/bin/perl -w
use strict;

my @file = <>;

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
my $new = $decl . $reg . "#else\n\n";
my $p = 0;

foreach (@file) {
	if ($p == 0 && m/^#/) {
		$p = 1;
		print $new;
	}
	print $_;
}
printf("\n#endif /* plugin stanza */\n");
