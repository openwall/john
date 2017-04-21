package jtr_rulez;
use strict;
use warnings;
use Exporter;

my $debug = 0;
my $stdout_rules = 0;
my $failed = 0;
my $rejected = 0;
my $rules_max_length;
my $l_num; my $p_num;
my %nums;	# these hold variables a ... k (used in the v command, or in get_length)
our @ISA= qw( Exporter );

# these CAN be exported.
our @EXPORT_OK = qw( debug stdout_rules failed jtr_run_rule jtr_dbg_level jtr_rule_pp_init jtr_rule_pp_next jtr_rule_rejected );

# these are exported by default.
our @EXPORT = qw( jtr_run_rule  jtr_dbg_level jtr_std_out_rules_set jtr_rule_pp_init jtr_rule_pp_next jtr_rule_rejected );

my $M="";
my %cclass=(); load_classes();
my @pp_rules=();
my $pp_idx=-0;

sub dbg {
	my $d = shift;
	if ($debug >= $d) {
		foreach my $s (@_) {
			print $s;
		}
	}
}
sub jtr_dbg_level {
	$debug = $_[0];
}
sub jtr_rule_rejected {
	my $r = $rejected;
	$rejected = 0;
	return $r;
}
sub jtr_std_out_rules_set {
	$stdout_rules = $_[0];
}
sub case_all_words { # turn john or "JOHn THE ruppor$$abc" into "John The Ruppor$$Abc"
	my $w = lc $_[0];
	$w =~ s/\b(\w)/\U$1/g;
	return $w;
}
sub case { # turn john or JOHn into John or JOHn THE ruppor$$abc" into "John the ruppor$$abc"
	my $w = lc $_[0];
	my $c = substr($w, 0, 1);
	if (ord($c) >= ord('a') && ord($c) <= ord('z')) {
		substr($w, 0, 1) = uc $c;
	}
	return $w;
}

sub toggle_case {  # turn jOhN into JoHn
	my $w = $_[0];
	# found online, unicode toggle code. Need to test for speed.
	$w =~ s/ (\p{CWU}) | (\p{CWL}) /defined $1 ? uc $1 : lc $2/gex;
	#
	# only valid for 7-bit ascii. Now using the unicode correct version.
	#$w =~ tr/A-Za-z/a-zA-Z/;
	return $w;
}
sub rev { # turn john into nhoj   (inlining reverse was having side effects so we function this)
	my ($w) = (@_);
	$w = reverse $w;
	return $w;
}
sub purge {  #  purge out a set of characters. purge("test123john","0123456789"); gives testjohn
	my ($w, $c) = @_;
	$w =~ s/[$c]*//g;
	return $w;
}
sub replace_chars {
	my ($w, $ch, $c) = @_;
	if ($c eq '^') { $c = '\\^'; }
	if (substr($c,length($c)-1,1) eq '\\' && (length($c)==1 || substr($c,length($c)-2,2) eq '\\\\')) { $c .= '\\'; }
	$w =~ s/[$c]/$ch/g;
	return $w;
}
sub shift_case { # S	shift case: "Crack96" -> "cRACK(^"
	my ($w) = @_;
	$w =~ tr/A-Za-z`~0-9)!@#$%^&*(\-_=+[{]}\\|;:'",<.>\/?/a-zA-Z~`)!@#$%^&*(0-9_\-+={[}]|\\:;"'<,>.?\//;
	return $w;
}
sub vowel_case { # V	lowercase vowels, uppercase consonants: "Crack96" -> "CRaCK96"
	my ($w) = @_;
	$w =~ tr/b-z/B-Z/;
	$w =~ tr/AEIOU/aeiou/;
	return $w;
}
sub keyboard_right { # R	shift each character right, by keyboard: "Crack96" -> "Vtsvl07"
	my ($w) = @_;
	# same behavior as john1.8.0.3-jumbo. I do not think all on the far right are 'quite' right, but at least it matches.
	# it's a very obsure rule, and not likely to have too many real world passwording implications.
	# the only 'real' use is if someone sets a password,and then it does not work. Were their fingers 1 key
	# to left, or 1 key to right?  If so, then they can guess with these rules
	$w =~ tr/`~1qaz!QAZ2wsx@WSX3edc#EDC4rfv$RFV5tgb%TGB6yhn^YHN7ujm&UJM8ik,*IK<9ol.(OL>0p;)P:\-[_{+=?\//1!2wsx@WSX3edc#EDC4rfv$RFV5tgb%TGB6yhn^YHN7ujm&UJM8ik,*IK<9ol.(OL>0p;\/)P:?\-['_{"=]+}|\\|\\/;
	return $w;
}
sub keyboard_left { # L	shift each character left, by keyboard: "Crack96" -> "Xeaxj85"
	my ($w) = @_;
	# idential output as john1.8.0.3-jumbo
	$w =~ tr/2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;\/@WSX#EDC$RFV%TGB^YHN&UJM*IK<(OL>)P:?1!\-[_{=]+}'"\\|/1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.!QAZ@WSX#EDC$RFV%TGB^YHN&UJM*IK<(OL>`~0p)P\-[_{;:=+/;
	return $w;
}
# pluralize: "crack" -> "cracks", etc. (lowercase only)
# plural code is direct port from jtr rules.c
sub pluralizes { my ($word) = (@_);
	my $len = length($word);
	if ($len<2) { return $word; }
	my $last=substr($word, length($word)-1,1);
	my $last2=substr($word, length($word)-2,1);
	if (find_any_chars("sxz", $last) > 0 ||
		($len > 1 && $last eq 'h' &&
		($last2 eq 'c' || $last2 eq 's'))) {
		return $word . "es";
	} elsif ($last eq 'f' && $last2 ne 'f') {
		return $word . "ves";
	} elsif ($len > 1 &&
		$last eq 'e' && $last2 eq 'f') {
		return $word . "ves";
	} elsif ($len  > 1 && $last eq 'y') {
		if (find_any_chars("aeiou", $last2) > 0) {
			return $word . "s";
		}
		return $word . "ies";
	}
	return $word . "s";
}
# "crack" -> "cracked", etc. (lowercase only)
sub pluralized { my ($word) = (@_);
	my $len = length($word);
	if ($len<2) { return $word; }
	my $last=substr($word, length($word)-1,1);
	my $last2=substr($word, length($word)-2,1);
	if ($last eq 'd' && $last2 eq 'e')  { return $word; }
	if ($last eq 'y') {
		substr($word, length($word)-1,1) = 'i';
	} elsif (find_any_chars("bgp", $last) && !find_any_chars("bgp", $last2)) {
		$word .= $last;
	}
	if ($last eq 'e') {
		$word .= 'd';
	} else {
		$word .= 'ed';
	}
	return $word;
}
# "crack" -> "cracking", etc. (lowercase only)
sub pluralizing { my ($word) = (@_);
	my $len = length($word);
	if ($len<3) { return $word; }
	my $last=substr($word, length($word)-1,1);
	my $last2=substr($word, length($word)-2,1);
	my $last3=substr($word, length($word)-3,1);
	if ($last eq 'g' && $last2 eq 'n' && $last3 eq 'i')  { return $word; }
	if (find_any_chars("eaiou", $last)) {
		return substr($word,0,length($word)-1) . "ing";
	}
	if (find_any_chars("bgp", $last) && !find_any_chars("bgp", $last2)) {
		$word .= $last;
	}
	return $word . "ing";
}

sub find_any_chars {
	# this function probably could be optimized, but as written, it works
	# well for all = / ? ( ) % type rejection rules.
	my ($w, $c) = @_;
	if (!defined ($c) || length($c) == 0) { return ""; }
	if (substr($c,length($c)-1,1) eq '\\' && (length($c)==1 || substr($c,length($c)-2,2) eq '\\\\')) { $c .= '\\'; }
#	dbg(3,"find_any_chars: w=$w  c=$c  s/[^$c]*//g;\n");
	$w =~ s/[^$c]*//g;
	return length($w);
}
sub find_first_char {
	# NOTE, this is used for / and % rejections, AND find_any_chars has already
	# returned VALID information.  Now we simply want to know position offsets.
	my ($off, $w, $c) = @_;
	my $v = 0;
	if ($off >= length($w)) { return length($w); }
	$w = substr($w, $off, length($w)-$off);
	my @wa = split('', $w);
	my @ca = split('', $c);
	foreach my $wc (@wa) {
		foreach my $cc (@ca) {
			if ($wc eq $cc) { return $off+$v; }
		}
		++$v;
	}
	return length($w);
}
sub jtr_run_rule { my ($rule, $word, $hc_logic) = @_;
	dbg(1, "jtr_run_rule called with debug level $debug\n");
	$M = $word;  # memory
	if (!defined $hc_logic) { $hc_logic=0; }
	$l_num = length($M);
	%nums = ( 'a'=>0,'b'=>0,'c'=>0,'d'=>0,'e'=>0,'f'=>0,'g'=>0,'h'=>0,'i'=>0,'k'=>0 );
	$failed = 0;
	$rejected = 0;
	dbg(2, "checking word $word with rule $rule\n");
	my @rc = split('', $rule);
	dbg(2, "after split\n");
	for (my $i = 0; $i < scalar(@rc); ++$i) {
		if (length($word) == 0) { return ""; } # in jtr, this is a 'reject'
		my $c = $rc[$i];
		next if ($c eq ' ' || $c eq ':');
		if ($c eq 'l') { $word = lc $word; next; }
		if ($c eq 'u') { $word = uc $word; next; }
		if ($c eq 'c') { $word = case($word); next; }
		if ($c eq 'C') { $word = toggle_case(case($word)); next; }
		if ($c eq 't') { $word = toggle_case($word); next; }
		if ($c eq 'd') { $word = $word.$word; next; }
		if ($c eq 'r') { $word = rev($word); next; }
		if ($c eq 'f') { $word = $word.rev($word); next; }
		if ($c eq '$') { ++$i; $word .= $rc[$i];  next; } #if ($rc[$i] eq '\\' && defined $rc[$i+1]) {++$i;}
		if ($c eq '^') { ++$i; $word = $rc[$i].$word; next; }
		if ($c eq '{') { $word = rotl($word); next; }
		if ($c eq '}') { $word = rotr($word); next; }
		if ($c eq '[') { if (length($word)) {$word = substr($word, 1);} next; }
		if ($c eq ']') { if (length($word)) {$word = substr($word, 0, length($word)-1);} next; }
		if ($c eq 'D') { my $n=get_num_val_raw($rc[++$i],$word); if ($n<length($word)) {substr($word, $n, 1)="";} next; }
		if ($c eq 'S') { $word = shift_case($word); next; }
		if ($c eq 'V') { $word = vowel_case($word); next; }
		if ($c eq '>') { my $n=get_num_val_raw($rc[++$i],$word); if(length($word)<=$n){$rejected=1; return ""; }    next; }
		if ($c eq '<') { my $n=get_num_val_raw($rc[++$i],$word); if(length($word)>=$n){$rejected=1; return ""; }    next; }
		if ($c eq '_') { my $n=get_num_val_raw($rc[++$i],$word); if(length($word)!=$n){$rejected=1; return ""; }    next; }
		if ($c eq '\''){ my $n=get_num_val_raw($rc[++$i],$word); if(length($word)> $n){ $word=substr($word,0,$n); } next; }
		if ($c eq 'p') {
			my $do_hc = 1;
			my $n = 0;
			if (length($rule) > $i+1) {$n=get_num_val_raw($rc[$i+1],$word,1);}
			if ($hc_logic == 0 && ($n < 1 || $n > 9)) {
				$word=pluralizes($word);
				$do_hc = 0;
			}
			if ($hc_logic > 0 || $do_hc > 0) {
				++$i;
				if ($n < 1) {$rejected=1; return ""; }
				my $s = $word;
				while ($n--) {
					$s .= $word;
				}
				$word = $s;
			}
			next;
		}
		if ($c eq 'P') { $word=pluralized($word); next; }
		if ($c eq 'I') { $word=pluralizing($word); next; }
		#
		#   -c -8 -s -p -u -U ->N -<N -: (rejection)
		#   Not sure how to handle these, since we do not have a running john environment
		#   to probe to know what/how these impact us.
		#
		# actually these are removed in the pp (for this code).
		if ($hc_logic != 0) {
			if ($c eq 'R') {
				my $n=get_num_val_raw($rc[++$i],$word);
				if ($n < length($word)) {
					substr($word,$n,1) = chr(ord(substr($word,$n,1))>>1);
				}
				next;
			}
			if ($c eq 'L') {
				my $n=get_num_val_raw($rc[++$i],$word);
				if ($n < length($word)) {
					substr($word,$n,1) = chr((ord(substr($word,$n,1))<<1)&0xFF);
				}
				next;
			}
			if ($c eq '-') {
				my $n=get_num_val_raw($rc[++$i],$word);
				if ($n < length($word)) {
					substr($word,$n,1) = chr(ord(substr($word,$n,1))-1);
				}
				next;
			}
		} else {
			if ($c eq 'R') { $word = keyboard_right($word); next; }
			if ($c eq 'L') { $word = keyboard_left($word); next; }

			if ($c eq '-') {
				++$i;
				$c = $rc[$i];
				if ($c eq ':') {
					next;   # this one actually is done and correct, lol.
				}
				# these are place holders now, until I can figure them out.
				if ($c eq 'c') { next; }
				if ($c eq '8') { next; }
				if ($c eq 's') { next; }
				if ($c eq 'p') { next; }
				if ($c eq 'u') { next; }
				if ($c eq 'U') { next; }
				if ($c eq '>') { ++$i; next; }
				if ($c eq '<') { ++$i; next; }
				dbg(1, "unknown length rejection rule: -$c character $c not valid.\n");
				next;
			}
		}
		if ($c eq 'o') { # oNX
			my $n=get_num_val_raw($rc[++$i],$word);
			++$i;
			dbg(2, "o$n$rc[$i]\n");
			if ($n < length($word)) { substr($word, $n, 1) = $rc[$i]; }
			next;
		}
		if ($c eq 'i') { # iNX
			my $n=get_num_val_raw($rc[++$i],$word);
			++$i;
			if ($n > length($word)) { $word .= $rc[$i]; }
			else { substr($word, $n, 0) = $rc[$i]; }
			next;
		}
		if ($c eq 'x') { # xNM
			my $n=get_num_val_raw($rc[++$i],$word);
			my $m=get_num_val_raw($rc[++$i],$word);
			if ($n>length($word)) { $rejected = 1; return ""; }
			if ($n+$m>length($word)) { $m = length($word)-$n; }
			$word = substr($word, $n, $m);
			next;
		}
		if ($c eq 'O') { # ONM
			my $n=get_num_val_raw($rc[++$i],$word);
			my $m=get_num_val_raw($rc[++$i],$word);
			if ($n>length($word)) { $rejected = 1; return ""; }
			if ($n+$m>length($word)) { $m = length($word)-$n; }
			substr($word, $n, $m) = "";
			next;
		}
		if ($c eq 's') { #   sXY & s?CY
			my $chars = "";
			if ($rc[++$i] eq "?" && $hc_logic==0) { $chars = get_class($rc[++$i]); }
			else { $chars = $rc[$i]; }
			++$i;
			my $ch = $rc[$i];
			$word=replace_chars($word, $ch, $chars);
			next;
		}
		if ($c eq 'D') { # DN
			my $pos = get_num_val($rc[++$i], $word);
			if ($pos >= 0 && $pos < length($word)+1) {
				$word = substr($word, 0,$pos).substr($word, $pos+1,length($word));
			}
			next;
		}
		if ($c eq 'x') { # xNM
			my $pos = get_num_val_raw($rc[++$i], $word);
			my $len = get_num_val_raw($rc[++$i], $word);
			if ($pos >= 0 && $pos <= length($word)) {
				$word = substr($word, $pos, $len);
			} else { return ""; } # this is how jtr does it but it is undefined.
			next;
		}
		if ($c eq 'i') { # iNX
			my $pos = get_num_val($rc[++$i], $word);
			if ($pos >= 0 && $pos <= length($word)) {
				++$i;
				substr($word, $pos,0) = $rc[$i];
			}
			next;
		}
		if ($c eq 'M') { # M
			$M = $word;
			next;
		}
		if ($c eq 'Q') { # Q
			if ($M eq $word) {
				$rejected = 1;
				return "";
			}
			next;
		}
		if ($c eq '!') { # !X  !?C  (rejection)
			my $chars;
			if ($rc[++$i] eq '?' && $hc_logic==0) { $chars = get_class($rc[++$i]); }
			else { $chars = $rc[$i]; }
			if (find_any_chars($word, $chars)) {
				$rejected = 1;
				return "";
			}
			next;
		}
		if ($c eq '/') { # /X  /?C  (rejection) reject UNLESS it contains.
			my $chars;
			if ($rc[++$i] eq '?' && $hc_logic==0) { $chars = get_class($rc[++$i]); }
			else { $chars = $rc[$i]; }
			if (!find_any_chars($word, $chars)) {
				$rejected = 1;
				$p_num = length;
				return "";
			}
			$p_num = find_first_char(0, $word, $chars);
			next;
		}
		if ($c eq '=') { # =NX  =N?C  (rejection)
			my $chars;
			my $pos = get_num_val($rc[++$i], $word);
			if ($pos >= 0 && $pos <= length($word)) {
				my $w = substr($word, $pos, 1);
				if ($rc[++$i] eq '?') { $chars = get_class($rc[++$i]); }
				else { $chars = $rc[$i]; }
				if (!find_any_chars($w, $chars)) {
					$rejected = 1;
					return "";
				}
			}
			next;
		}
		if ($c eq '(') { # (X  (?C  (rejection)
			my $chars;
			if (length($word)==0) { $rejected = 1; return ""; }
			if ($rc[++$i] eq '?' && $hc_logic==0) { $chars = get_class($rc[++$i]); }
			else { $chars = $rc[$i]; }
			if (!find_any_chars(substr($word,0,1), $chars)) {
				$rejected = 1;
				return "";
			}
			next;
		}
		if ($c eq ')') { # )X  )?C  (rejection)
			my $chars;
			if (length($word)==0) { $rejected = 1; return ""; }
			if ($rc[++$i] eq '?' && $hc_logic==0) { $chars = get_class($rc[++$i]); }
			else { $chars = $rc[$i]; }
			if (!find_any_chars(substr($word,length($word)-1,1), $chars)) {
				$rejected = 1;
				return "";
			}
			next;
		}
		if ($c eq '%') { # %NX  %N?C  (rejection)
			my $chars;
			my $n = get_num_val($rc[++$i], $word);
			if ($rc[++$i] eq '?' && $hc_logic==0) { $chars = get_class($rc[++$i]); }
			else { $chars = $rc[$i]; }
			if (find_any_chars($word, $chars) < $n) {
				$rejected = 1;
				$p_num = length;
				return "";
			}
			my $fnd = 0;
			$p_num = 0;
			while ($fnd < $n) {
				$p_num = find_first_char($p_num, $word, $chars);
				++$fnd;
			}
			next;
		}
		if ($c eq 'X') { # XNMI
			my $posM = get_num_val($rc[++$i], $M);  # note using $M not $word.
			my $len = get_num_val($rc[++$i], $M);
			my $posI = get_num_val($rc[++$i], $word);
			if ($posM >= 0 && $len > 0 && $posI >= 0) {
				substr($word, $posI, 0) = substr($M, $posM, $len);
			}
			next;
		}
		if ($c eq 'o') { # oNX
			my $pos = get_num_val($rc[++$i], $word);
			if ($pos >= 0 && $pos < length($word)) {
				++$i;
				substr($word, $pos,1) = $rc[$i];
			}
			next;
		}
		if ($c eq 'T') { # TN  (toggle case of letter at N)
			my $pos = get_num_val($rc[++$i], $word);
			if ($pos >= 0) {
				my $c = substr($word, $pos, 1);
				if (ord($c) >= ord('a') && ord($c) <= ord('z')) { substr($word, $pos, 1) = uc $c; }
				elsif (ord($c) >= ord('A') && ord($c) <= ord('Z')) { substr($word, $pos, 1) = lc $c; }
			}
			next;
		}
		if ($c eq '@') {  # @X & @?C
			my $chars = "";
			if ($rc[++$i] eq "?" && $hc_logic==0) { $chars = get_class($rc[++$i]); }
			else { $chars = $rc[$i]; }
			$word=purge($word, $chars);
			next;
		}
		if ($c eq 'A') { # AN"STR"  with de-ESC in STR
			my $pos = get_num_val($rc[++$i], $word);
			if ($pos < 0) {next;}
			my $delim = $rc[++$i];
			my $s = "";
			while ($rc[$i+1] ne $delim) {
				if ($rc[$i] eq '\\' && $rc[$i+1] eq "x") {
					# \xhh escape, replace with 'real' character
					$i += 2;
					my $s = $rc[++$i]; $s .= $rc[$i];
					($rc[$i]) = sscanf($s, "%X");
					$rc[$i] = chr($rc[$i]);
				}
				$s .= $rc[++$i];
			}
			++$i;
			substr($word, $pos, 0) = $s;
			next;
		}
		if ($c eq 'v') { # vVNM numeric handling
			# first update $l_num
			$l_num = length($word);
			my $V = $rc[++$i];
			my $N = get_num_val_raw($rc[++$i], $word);
			my $M = get_num_val_raw($rc[++$i], $word);
			$nums{$V} = $N-$M;
			next;
		}
		# hashcat rules.
		if ($c eq 'z') {
			my $n=get_num_val_raw($rc[++$i],$word);
			if (length($word) > 0) {
				while ($n-- > 0) {
					$word = substr($word, 0, 1) . $word;
				}
			}
			next;
		}
		if ($c eq 'Z') {
			my $n=get_num_val_raw($rc[++$i],$word);
			if (length($word) > 0) {
				while ($n-- > 0) {
					$word .= substr($word, length($word)-1, 1);
				}
			}
			next;
		}
		if ($c eq '6') {
			$word = $M.$word;
			next;
		}
		if ($c eq '4') {
			$word .= $M;
			next;
		}
		if ($c eq 'q') {
			my $p;
			my $s = "";
			for ($p = 0; $p < length($word); $p++) {
				$s .= substr($word, $p, 1).substr($word, $p, 1);
			}
			$word = $s;
			next;
		}
		if ($c eq '.') {
			my $n=get_num_val_raw($rc[++$i],$word);
			if ($n < length($word)-1) {
				substr($word,$n,1) = substr($word,$n+1,1);
			}
			next;
		}
		if ($c eq ',') {
			my $n=get_num_val_raw($rc[++$i],$word);
			if ($n < length($word) && $n > 0) {
				substr($word,$n,1) = substr($word,$n-1,1);
			}
			next;
		}
		if ($c eq 'k') {
			if (length($word)>1) {
				substr($word,0,2) = substr($word,1,1).substr($word,0,1);
			}
			next;
		}
		if ($c eq 'K') {
			if (length($word)>1) {
				substr($word,length($word)-2) = substr($word,length($word)-1,1).substr($word,length($word)-2,1);
			}
			next;
		}
		if ($c eq '*') {
			my $n=get_num_val_raw($rc[++$i],$word);
			my $m=get_num_val_raw($rc[++$i],$word);
			if ($n < length($word) && $m < length($word)) {
				my $c = substr($word,$n, 1);
				substr($word,$n, 1) = substr($word,$m, 1);
				substr($word,$m, 1) = $c;
			}
			next;
		}
		if ($c eq '+') {
			my $n=get_num_val_raw($rc[++$i],$word);
			if ($n < length($word)) {
				substr($word,$n,1) = chr((ord(substr($word,$n,1))+1)&0xFF);
			}
			next;
		}
		if ($c eq 'y') {
			my $n=get_num_val_raw($rc[++$i],$word);
			if ($n < length($word)) {
				$word = substr($word,0,$n).$word;
			}
			next;
		}
		if ($c eq 'Y') {
			my $n=get_num_val_raw($rc[++$i],$word);
			if ($n < length($word)) {
				$word .= substr($word,length($word)-$n);
			}
			next;
		}
		if ($c eq 'E') {
			$word = lc $word;
			substr($word, 0, 1) = uc substr($word, 0, 1);
			my $pos = index($word, ' ');
			while ($pos >= 0) {
				++$pos;
				substr($word, $pos, 1) = uc substr($word, $pos, 1);
				$pos = index($word, ' ', $pos);
			}
			next;
		}
		if ($c eq 'e') {
			my $chars;
			if ($rc[++$i] eq '?' && $hc_logic==0) { $chars = get_class($rc[++$i]); }
			else { $chars = $rc[$i]; }
			$word = lc $word;
			substr($word, 0, 1) = uc substr($word, 0, 1);
			for (my $i = 0; $i < length($chars); ++$i) {
				my $c = substr($chars, $i, 1);
				my $pos = index($word, $c);
				while ($pos >= 0) {
					++$pos;
					substr($word, $pos, 1) = uc substr($word, $pos, 1);
					$pos = index($word, $c, $pos);
				}
			}
			next;
		}

		print "\nDo not know how to handle character $c in $rule\n";
		exit(-1);
	}
	if (length($word) > 125) { return substr($word, 0, 125); }
	dbg(2, "resultant word after rule $rule is: $word\n");
	return $word;
}
sub rotl {
	my $w = $_[0];
	$w = substr($w, 1, length($w)).substr($w, 0, 1);
	return $w;
}
sub rotr {
	my $w = $_[0];
	$w = substr($w, length($w)-1, 1).substr($w, 0, length($w)-1);
	return $w;
}
sub get_class {
	my ($c) = @_;
	if ($c eq '?') { dbg(2,"Doing get class of ?\n"); return $cclass{'?'}; }
	return $cclass{$c};
}
sub get_num_val_raw { my ($p, $w, $dont_warn) = (@_);
#0...9	for 0...9
#A...Z	for 10...35
#*	for max_length
#-	for (max_length - 1)
#+	for (max_length + 1)
#a...k	user-defined numeric variables (with the "v" command)
#l	initial or updated word's length (updated whenever "v" is used)
#m	initial or memorized word's last character position
#p	position of the character last found with the "/" or "%" commands
#z	"infinite" position or length (beyond end of word)
	if (ord($p) >= ord("0") && ord($p) <= ord('9')) {return ord($p)-ord('0');}
	if (ord($p) >= ord("A") && ord($p) <= ord('Z')) {return  ord($p)-ord('A')+10;}
	if ($p eq '*') { return $rules_max_length; }
	if ($p eq '-') { return $rules_max_length-1; }
	if ($p eq '+') { return $rules_max_length+1; }
	if (index('abcdefghijk',$p)>-1) { return $nums{$p}; }
	if ($p eq 'z') {return length($w);}
	if ($p eq 'l') { return $l_num; }
	if ($p eq 'p') { return $p_num; }
	if ($p eq 'm') { my $m = length($M); if ($m>0){$m-=1;} return $m; }
	if (!defined $dont_warn || $dont_warn < 1) {
		print "ERROR, $p is NOT a valid length item\n";
	}
	return -1;
}
sub get_num_val { my ($p, $w) = (@_);
	$p = get_num_val_raw($p, $w);
	if ($p > length($w)) { return -1; }
	return $p;
}
sub esc_remove { my ($w) = (@_);
	my $s = "";
	my $i = 0;
	my @ch = split('', $w);
	while ($i < scalar @ch) {
		if ($ch[$i] eq '\\' && $i+1 < scalar @ch) {++$i;}
		$s .= $ch[$i];
		++$i;
	}
	return $s;
}
sub get_items {
	my ($s, $pos, $pos2, $esc_r) = (@_);
	$_[2] = index($s, ']', $pos);
	if ($_[2] < 0) { return ""; }
	while ($pos < $_[2] && substr($s, $_[2]-1, 1) eq "\\") {
		$_[2] = index($s, ']', $_[2]+1);
	}
	if ($pos+2 > $_[2])  { return ""; }
	if ($pos+2 == $_[2])  {
		# handle a 1 byte group [x] should return "x";
		$s = substr($s, $pos+1, 1);
		return $s;
	}
	$s = substr($s, $pos+1, $_[2]-$pos-1);
	# remove escapes here \v and \xHH
	my $idx = index($s, '\\x');
	while ($idx > -1) {
		my $n = substr($s, $idx+2, 2);
		my $v = hex($n);
		substr($s, $idx, 4) = chr($v);
		$idx = index($s, '\\x', $idx+1);
	}
	$idx = index($s, '\\');
	while ($idx > -1) {
		# remove all \C except for  \-  We have to keep that one.
		if (substr($s, $idx, 2) ne '\\-') {
			substr($s, $idx, 2) = substr($s, $idx+1, 1);
		} else { ++$idx; }
		if (substr($s, $idx, 1) eq '\\') { ++$idx; }
		$idx = index($s, '\\', $idx);
	}

	# now $s is raw characters in the range, no escapes.
	my @ch = split('', $s);

	# convert ranges into 'raw' values.  de-escape values (i.e. \\ or \[ become \ or [ )
	# note, we do not check for some invalid ranges, like [-b] or [ab-] or [z-a]
	my $i = 0;
	my $chars = "";
	for ($i = 0; $i < length($s); ++$i) {
		if ($i>0 && $ch[$i] eq '-') {
			dbg(4, "doing range fix for $ch[$i-1]-$ch[$i+1]\n");
			if (ord($ch[$i-1]) > ord($ch[$i+1])) {
				# jumbo john handles [6-0][9-0] also (i.e. count down).
				# note, I do not think core handles this!!!
				for (my $c = ord($ch[$i-1])-1; $c >= ord($ch[$i+1]); --$c) {
					$chars .= chr($c);
				}
			} else {
				# normal order
				for (my $c = ord($ch[$i-1])+1; $c <= ord($ch[$i+1]); ++$c) {
					$chars .= chr($c);
				}
			}
			++$i;
		} else {
			if ($ch[$i] eq '\\' && $ch[$i+1] eq '-') { ++$i; }
			$chars .= $ch[$i];
		}
	}
	if (defined($esc_r) && $esc_r) {
		# if magic \r was seen, we do NOT unique the group.
		dbg(2, "get_item returning (no-dedupe): chars=$chars\n");
		return $chars;
	}
	# we must 'unique' this data.
	$chars = reverse $chars;
	$chars =~ s/(.)(?=.*?\1)//g;
	$chars = reverse $chars;
	dbg(2, "get_item returning: chars=$chars\n");
	return $chars;
}

sub hexify_space_in_groups { my ($w) = (@_);
	if (index($w, ' ') == -1) { return $w; }
	my $pos = index($w, '[');
	while ($pos > -1) {
		if ($pos > 0 && substr($w, $pos-1, 1) eq '\\') {
			$pos = index($w, '[', $pos+1);
			next;
		}
		my $pos2 = index($w, ']', $pos);
		while ($pos2 > 0 && substr($w, $pos2-1, 1) eq '\\') {
			$pos2 = index($w, ']', $pos2+1);
			next;
		}
		if ($pos2 > 0) {
			my $s = substr($w, $pos, $pos2-$pos);
			$s =~ s/ /\\x20/g;
			substr($w, $pos, $pos2-$pos) = $s;
			$pos += length($s);
			$pos = index($w, '[', $pos);
		} else { $pos = -1; }
	}
	return $w;
}

# preprocessor.  We have an array of rules that get built. Then
# we keep count of which have been handled, so we eat them one
# at a time, in order.
sub jtr_rule_pp_init { my ($pre_pp_rule, $len, $max_cnt, $hc_logic) = (@_);
	$pp_idx = 0;
	if (defined $hc_logic && $hc_logic != 0) {
		@pp_rules = ();
		$_[2] = 1;
		if ($debug>2||$stdout_rules) {
			foreach my $s (@pp_rules) {
				print "$s\n";
			}
			if ($debug>3||$stdout_rules==1) { exit(0); }
		}
		return $pre_pp_rule;
	}
	# removed all stray spaces. HOWEVER, we must preserve them within groups, so we
	# first find all spaces in groups, and replace them with \x20 and then purge spaces.
	my $stripped = hexify_space_in_groups($pre_pp_rule);

	#$stripped = purge($stripped,' ');
	# They must ALSO need to be preserved for any character in character based commands $^ios@!/=()%e
	my $p = index($stripped, ' ');
	while ($p != -1) {
		if ($p > 0) {
			if (index('$^s@!/()e', substr($stripped, $p-1, 1)) != -1) {
				#substr($stripped, $p, 1) = '[\\x20]';
				$p = index($stripped, ' ', $p+1);
				next;
			}
		}
		if ($p > 1) {
			if (index('sio=%', substr($stripped, $p-2, 1)) != -1) {
				#substr($stripped, $p, 1) = '[\\x20]';
				$p = index($stripped, ' ', $p+1);
				next;
			}
		}
		substr($stripped, $p, 1) = '';
		$p = index($stripped, ' ', $p);
	}
	#print "stripped = $stripped\n";

	# normalize all \r\p[] or \r\px[] into \p\r[] and \px\r[]
	$stripped =~ s/\\r\\p\[/\\p\\r\[/g;
	$stripped =~ s/\\r\\p([0-9])\[/\\p$1\\r\[/g;
	# strip out \\ etc outside of groups []
	if (!defined($len) || $len==0) {$rules_max_length = 0;}
	else {$rules_max_length = $len; }
	@pp_rules = ();
	if (defined $max_cnt) {
		my $cnt = pp_rule_cnt($stripped);
		if ($max_cnt && $cnt > $max_cnt) { $_[2] = $cnt; return ""; }
	}
	dbg(4, "calling pp_rule() to prepare our rule:\n\n$pre_pp_rule\n\n");
	pp_rule($stripped, 0, 0);
	dbg(4, "There were ".scalar @pp_rules." created\n");

	# do a final strip of all \ values from the finished rule.
	my @p=();
	foreach my $s (@pp_rules) {
		dbg(3, "   before esc_remove: $s\n");
		$s = esc_remove($s);
		dbg(3, "   after  esc_remove: $s\n");
		push(@p,$s);
	}
	@pp_rules = @p;

	if ($debug>2||$stdout_rules) {
		foreach my $s (@pp_rules) {
			print "$s\n";
		}
		if ($debug>3||$stdout_rules==1) { exit(0); }
	}

	if (scalar @pp_rules > 0) {
		return $pp_rules[0];
	}
	return "";
}
sub jtr_rule_pp_next { my () = (@_);
	if (scalar @pp_rules == $pp_idx) { return ""; }
	return $pp_rules[++$pp_idx];
}
sub handle_backref { my ($gnum, $c, $s, $total, $idx) = (@_);
	my $i; my $i2; my $n;

	# find any \$gnum and replace with $c
	$s =~ s/\\$gnum/$c/g;

	# find any \p$gnum[] and replace with the $gnum from its group
	$i = index($s, "\\p$gnum"."[");
	while ($i >= 0) {
		my $chars = get_items($s, $i+3, $i2);
		if ($i2 == -1) { print STDERR "invalid \\p$gnum"."[..] found in rule\n"; die; }
		my @a = split('', $chars);
		my $c;
		my $i3 = $idx;
		$i3 %= scalar @a;
		substr($s, $i, $i2-$i+1) = $a[$i3];
		$i = index($s, "\\p$gnum"."[");
	}

	# find any \p$gnum\r[] and replace with the $gnum from its non-dedup'd group
	$i = index($s, "\\p$gnum\\r[");
	while ($i >= 0) {
		my $chars = get_items($s, $i+5, $i2, 1);
		if ($i2 == -1) { print STDERR "invalid \\p$gnum\\r[..] found in rule\n"; die; }
		my @a = split('', $chars);
		my $c;
		my $i3 = $idx;
		$i3 %= scalar @a;
		substr($s, $i, $i2-$i+1) = $a[$i3];
		$i = index($s, "\\p$gnum\\r[");
	}

	# now that all the stray ['s are gone, we can look for \p[] \p\r[] and \0
	# NOTE, there must not be ANY groups ahead of this, else we leave it for later.
	$i = index($s, "\\p[");
	while ($i >= 0) {
		#print"here $s : ".substr($s,$i)."\n";
		$i2 = index($s, '[');
		if ($i > 0 && $i2 >= 0 && $i2 < $i) {
			while ($i2 < $i) {
				if ($i2 == 0) { $i = -1; }
				elsif (substr($s, $i2-1, 1) eq '\\') {
					$i2 = index($s, '[', $i2+1);
				} else {
					$i = -1;
				}
			}
		}
		if ($i > 0) {
			my $chars = get_items($s, $i+2, $i2);
			if ($i2 == -1) { print STDERR "invalid \\p0[..] found in rule\n"; die; }
			my @a = split('', $chars);
			my $c;
			my $i3 = $idx;
			$i3 %= scalar @a;
			substr($s, $i, $i2-$i+1) = $a[$i3];
			$i = index($s, "\\p[");
		}
	}

	# find any \p\r[ and step them. The step is $total
	$i = index($s, "\\p\\r[");
	while ($i >= 0) {
		$i2 = index($s, '[');
		if ($i > 0 && $i2 >= 0 && $i2 < $i) {
			while ($i2 < $i) {
				if ($i2 == 0) { $i = -1; }
				elsif (substr($s, $i2-1, 1) eq '\\') {
					$i2 = index($s, '[', $i2+1);
				} else {
					$i = -1;
				}
			}
		}
		if ($i >= 0) {
			my $chars = get_items($s, $i+4, $i2, 1);
			#print "in \\p\\r[ and found $chars with total=$total\n";
			if ($i2 == -1) { print STDERR "invalid \\p\\r[] found in rule\n"; die; }
			my @a = split('', $chars);
			my $c;
			$total %= scalar @a;
			substr($s, $i, $i2-$i+1) = $a[$total];
			$i = index($s, "\\p\\r[");
		}
	}

	# find any \0 before the next [  and replace with $c
	$i = index($s, "\\0");
	#print "i for \\0 = $i  (s=$s)\n";
	while ($i >= 0) {
		$i2 = index($s, '[');
		if ($i > 0 && $i2 >= 0 && $i2 < $i) {
			while ($i2 < $i) {
				if ($i2 == 0) { $i = -1; }
				elsif (substr($s, $i2-1, 1) eq '\\') {
					$i2 = index($s, '[', $i2+1);
				} else {
					$i = -1;
				}
			}
		}
		if ($i >= 0) {
			substr($s, $i, 2) = $c;
			$i = index($s, "\\0");
		}
	}
	return $s;
}
sub handle_rule_rej {
	my $rule = $_[0];
	dbg(3, "Entering handle_rule_rej rule=$rule\n");
	# remove our 3 hacks for problem letters
	$rule =~ s/\\([ -~])``~/\\$1/g;

	dbg(3, "Leaving  handle_rule_rej rule=$rule\n");
	if (substr($rule, 0, 1) ne '-') { return $rule;}
	my $v = substr($rule,1,1);
	if ($v eq ':') { return substr($rule, 2); }
	if ($v eq 'c') { return substr($rule, 2); }
	if ($v eq '8') { return substr($rule, 2); }
	if ($v eq 's') { return substr($rule, 2); }
	if ($v eq 'p') { return substr($rule, 2); }
	if ($v eq 'u') { return substr($rule, 2); }
	if ($v eq 'U') { return substr($rule, 2); }
	if ($v eq '<') { return substr($rule, 3); }
	if ($v eq '>') { return substr($rule, 3); }
	return $rule;
}
sub is_pnum_r { my ($w) = (@_);
	if (substr($w, 0, 2) ne '\\p') { return 0; }
	if (substr($w, 3) ne '\\r')    { return 0; }
	return 1;
}
sub pp_rule { my ($rules, $which_group, $idx) = (@_);
	my $total = 0;
	dbg(3, "** entered pp_rule($rules, $which_group, $idx, $total)\n");
	my $pos = index($rules, '[');
	if ($pos == -1) { $rules=handle_rule_rej($rules); dbg(3, "**** This rule being saved: $rules\n"); push(@pp_rules,$rules); return 0; }
	while ($pos > 0 && substr($rules, $pos-1, 1) eq "\\" && ($pos == 1 || substr($rules, $pos-2, 2) ne "\\\\")) {
		$pos = index($rules, '[', $pos+1);
	}
	if ($pos < 0)  { $rules=handle_rule_rej($rules); dbg(3, "**** This rule being saved: $rules\n"); push(@pp_rules,$rules); return 0;}
	my $esc_r = 0;
	if ($pos > 1 && substr($rules, $pos-2,2) eq "\\r") {
		$esc_r = 1;
		if ($pos > 3 && substr($rules, $pos-4,4) eq "\\p\\r") {
			# we leave these alone \p\r  , they are needed for the handle-backref logic
		} elsif ($pos > 4 && is_pnum_r(substr($rules, $pos-5,5))) {
			# we leave these alone \p1\r , they are needed for the handle-backref logic
		} else {
			# remove the \r we 'know' it is there, it now serves no purpose from here on.
			substr($rules, $pos-2,2) = "";
			$pos -= 2;
		}
	}
	my $pos2;
	dbg(3,"calling get_items($rules, $pos, pos2, $esc_r);\n");
	my $Chars = get_items($rules, $pos, $pos2, $esc_r);
	if ($pos > $pos2)  { $rules=handle_rule_rej($rules); dbg(3, "**** This rule being saved: $rules\n"); push(@pp_rules,$rules); return 0;}
	my @chars = split('', $Chars);
	$idx = 0;
	$which_group += 1;
	dbg(2," * before foreach loop. rules=$rules Chars=$Chars\n");
	foreach my $c (@chars) {
		my $s = $rules;
		# note handling \ chars in a group is a bitch, since we remove them
		# 1 at a time, and then continue to process the line. THUS, these
		# 'look' like stray \, so this [\\x][01] end up doing this
		#    \[01] during one level of recursion. Thus the crux of the problem.
		# We change any \ returned from a group, into \\``~ and then later undo
		# that problem (when the rule is complete), and the \\ is used as our
		# signal that this is NOT part of any escaping.
		#  We have to do same type shit with [ ] chars also :(
		if (index('\\\[\]', $c) != -1)  { $c = "\\".$c."``~"; }
		substr($s, $pos, $pos2-$pos+1) = $c;
		my $s2 = handle_backref($which_group, $c, $s, $total, $idx);
		if ($s2 ne $s) {dbg(3, "before handle_backref($which_group, $c, $s, $total, $idx)\nhandle_backref returned     $s2\n"); }
		else { dbg(3, "  handle_backref nothing changed ($which_group, $c, $s, $total, $idx)\n"); }
		++$total;
		dbg(3, "*** entering      recurse pp_rule($s2, $which_group, $idx, $total) pos=$pos pos2=$pos2\n");
		if (pp_rule($s2, $which_group, $idx, $_[6])) { return 1; }
		$_[6]++;
		$idx++;
		dbg(3, "*** returned from recurse pp_rule($s2, $which_group, $idx, $total) pos=$pos pos2=$pos2\n");
	}
	return 0;
}
# we simply find how many items are in each group, and multiply total, returning that total.
sub pp_rule_cnt{ my ($rules) = (@_);
	my $total = 1;
	my $pos = index($rules, '[');
	if ($pos == -1) { return 1; }
	dbg(3, "** entered pp_rule_cnt($rules)\n");
	do {
		while ($pos >= 0 && substr($rules, $pos-1, 1) eq "\\") {
			$pos = index($rules, '[', $pos+1);
		}
		my $pos2;
		my $esc_r = 0;
		if ($pos > 1 && substr($rules, $pos-2,2) eq "\\r") {
			$esc_r = 1;
		}
		my $Chars = get_items($rules, $pos, $pos2, $esc_r);

		if ($pos > $pos2)  { dbg(3, "** Returning pp_rule_cnt $total rules\n\n"); return $total; }
		my $skip = 0; # skip will be set to 1 for any parallel groups.
		if (($pos > 1 && substr($rules, $pos-2,2) eq "\\p")) { $skip = 1; }  # skip \p[]
		if (($pos > 3 && substr($rules, $pos-4,4) eq "\\p\\r")) { $skip = 1; }  # skip \p\r[]
		if (($pos > 2 && substr($rules, $pos-3,2) eq "\\p") && ord(substr($rules, $pos-1,1)) >= ord('0') && ord(substr($rules, $pos-1,1)) <= ord('9')) { $skip = 1; }  # skip \p0[] to \p9[]
		if (($pos > 4 && substr($rules, $pos-5,2) eq "\\p") && ord(substr($rules, $pos-3,1)) >= ord('0') && ord(substr($rules, $pos-3,1)) <= ord('9')) { $skip = 1; }  # skip \p0\r[] to \p9\r[]
		if ($skip==0) {
			dbg(3, "    This string part of count multiplier: $Chars\n\n");
			$total *= length($Chars);
		}
		$rules = substr($rules, $pos2);
		$pos = index($rules, '[');
	} while ($pos > 0);
	dbg(3, "** Returning pp_rule_cnt $total rules\n\n");
	return $total;
}

sub load_classes {
	my $i;
	my $c_all;  for ($i = 1;    $i < 255; ++$i) { $c_all  .= chr($i); }
	my $c_8all; for ($i = 0x80; $i < 255; ++$i) { $c_8all .= chr($i); }
	$cclass{z}=$c_all;
	$cclass{b}=$c_8all;
	$cclass{'?'}='?';
	$cclass{v}="aeiouAEIOU";
	$cclass{c}="bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ";
	$cclass{w}=" \t";
	$cclass{p}="\.,:;\'\?!`\"";
	$cclass{s}="\$%^&\*\(\)-_+=|\<\>\[\]\{\}#@/~";
	$cclass{l}="abcdefghijklmnopqrstuvwxyz";
	$cclass{u}=uc $cclass{l};
	$cclass{d}="0123456789";
	$cclass{a}=$cclass{l}.$cclass{u};
	$cclass{x}=$cclass{l}.$cclass{u}.$cclass{d};
	$cclass{o}="\x01\x02\x03\x04\x05\x06\x07\x08\x0A\x0B\x0C\x0D\x0E\x0F\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x7F\x84\x85\x88\x8D\x8E\x8F\x90\x96\x97\x98\x9A\x9B\x9C\x9D\x9E\x9F";
	$cclass{y}=""; # note some types some chars are not valid (i.e. A..Z is not valid for a format where pass is lc(pass)
	foreach my $c (split("","bvcwpsludaxo")) {
		my $C = uc $c;
		$cclass{$C}=purge($cclass{z}, $cclass{$c});

		# some 'corrections' are needed to get a string to play nice in the reg-x we have
		$cclass{$C} =~ s/\\/\\\\/g; # change \ into \\
		$cclass{$C} =~ s/\^/\\\^/g; # change ^ into \^
		$cclass{$C} =~ s/\-/\\\-/g; # change - into \-
		$cclass{$C} =~ s/\]/\\\]/g; # change ] into \]
	}
	$cclass{Y}=$c_all;
	$cclass{Y} =~ s/\\/\\\\/g; # change \ into \\
	$cclass{Y} =~ s/\^/\\\^/g; # change ^ into \^
	$cclass{Y} =~ s/\-/\\\-/g; # change - into \-
	$cclass{Y} =~ s/\]/\\\]/g; # change ] into \]
}
1;
