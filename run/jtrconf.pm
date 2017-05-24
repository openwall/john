# handles jtr .conf files (including the .include of files and sections)
package jtrconf;
use strict;
use warnings;
use Exporter;
use File::Basename;

my $basepath = dirname(__FILE__).'/';
my $confname = 'john.conf';
my %sections = ();

our @ISA= qw( Exporter );

# these CAN be exported.
our @EXPORT_OK = qw( setbasepath setname load getsection getparam );

# these are exported by default.
#our @EXPORT = qw( setbasepath setname getsection );

# 'default' is ../run/  Call this function to change that.
sub setbasepath {
	$basepath = $_[0];
	if (!defined $basepath || length($basepath) == 0) {
		$basepath = './';
	}
	if (substr($basepath, length($basepath)-1) ne '/') {
		$basepath .= '/';
	}
}

# set non-standard john.conf name
sub setname { $confname = $_[0]; }

# this inserts include data into the array 1 element past where we are (i.e. after the include line).
sub handle_include { my ($line, $i) = @_;
	# there are 4 include flavors.
	my $inc_name = substr($line, 10, length($line)-11);
	if (substr($line, 0, 10) eq '.include [') {
		# section
		$inc_name = lc $inc_name;
		splice @{$_[2]}, $i+1, 0, @{$sections{$inc_name}};
		return;
	}
	my $missing_ok = 0;
	my $dirname = "";
	if (substr($line, 0, 10) eq '.include <') {
		# basepath - forced.
		$dirname = $basepath;
	} elsif (substr($line, 0, 10) eq '.include "') {
		# local dir - forced
		$dirname = './';
	} elsif (substr($line, 0, 10) eq '.include \'') {
		# local dir - missing OK.
		$dirname = './';
		$missing_ok = 1;
	} else {
		die print STDERR "invalid . conf command $line\n";
	}
	if (-f $dirname.$inc_name) {
		open (FILE, $dirname.$inc_name);
		my @lines = (<FILE>);
		close (FILE);
		splice @{$_[2]}, $i+1, 0, @lines;
	} else {
		if ($missing_ok != 0) { return; }
		die print STDERR "can not include file $dirname.$inc_name\n";
	}
}

# this loads the .conf file.
sub load {
	open (FILE, $basepath.$confname) or die "cant open $basepath$confname\n";
	my @lines = (<FILE>);
	close (FILE);
	my $hc = 0;
	my @cur_section = ();
	my $cur_section_name="";
	for (my $i = 0; $i < scalar @lines; ++$i) {
		my $line = $lines[$i];
		chomp $line;
		if (length($line) == 0 || substr($line, 0, 1) eq '#') {next;}
		if (substr($line, 0, 9) eq '.include ') {
			handle_include($line, $i, \@lines);
			next;
		}
		if ($hc == 0 && substr($line, 0, 1) eq '[') {
			if (length($cur_section_name) > 0) {
				#if (@cur_section < 2) {
				#	$sections{$cur_section_name} = $cur_section[0];
				#} else {
					$sections{$cur_section_name} = [@cur_section];
				#}
			}
			$cur_section_name = lc substr($line, 1, length($line)-2);
			@cur_section = ();
			next;
		}
		if (substr($line, 0, 3) eq "!! ") {
			if ($line eq "!! hashcat logic ON") { $hc = 1; }
			if ($line eq "!! hashcat logic OFF") { $hc = 0; }
		}
		push @cur_section, "$line\n";
	}
	$sections{$cur_section_name} = [@cur_section];
}

# returns a section's data.
sub getsection { my ($section) = @_;
	$section = lc $section;
	my @a = ();
	#if (@sections{$section} == 1) {
	#	print "$sections{$section}\n";
	#	print "@sections{$section}\n";
	#	print "@{$sections{$section}}\n";
	#	push @a, $sections{$section};
	#} else {
#		no strict 'refs';
		@a = @{$sections{$section}};
#		use strict;
	#}
	return @a;
}

# returns the data for a param (i.e. from Options).
sub getparam { my ($section, $param) = @_;
	$section = lc $section;
	my @a = @{$sections{$section}};
	foreach my $s (@a) {
		my $pos = index($s, '=');
		if ($pos > -1) {
			my $p = substr($s, 0, $pos);
			$p =~ s/\s+$//g;
			if (lc $param eq lc $p) {
				$s = substr($s, $pos+1);
				$s =~ s/^\s+//g;
				return $s;
			}
		}
	}
	return "";
}

1;