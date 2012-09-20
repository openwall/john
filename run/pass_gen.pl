#!/usr/bin/perl -w
use strict;

#############################################################################
# For the version information list and copyright statement,
# see doc/pass_gen.Manifest
#############################################################################

use Authen::Passphrase::DESCrypt;
use Authen::Passphrase::BigCrypt;
use Authen::Passphrase::MD5Crypt;
use Authen::Passphrase::BlowfishCrypt;
use Authen::Passphrase::EggdropBlowfish;
use Authen::Passphrase::LANManager;
use Authen::Passphrase::NTHash;
use Authen::Passphrase::PHPass;
use Digest::MD4 qw(md4 md4_hex md4_base64);
use Digest::MD5 qw(md5 md5_hex md5_base64);
use Digest; # Whirlpool is gotten from Digest->new('Whirlpool')
use Digest::SHA qw(sha1 sha1_hex sha1_base64 sha224 sha224_hex sha224_base64 sha256 sha256_hex sha256_base64 sha384 sha384_hex sha384_base64 sha512 sha512_hex sha512_base64 );
use Digest::GOST qw(gost gost_hex gost_base64);
use Encode;
use Switch 'Perl5', 'Perl6';
use POSIX;
use Getopt::Long;
use Math::BigInt;
use Crypt::RC4;
use Crypt::CBC;
use Crypt::DES;
use Crypt::ECB qw(encrypt PADDING_AUTO PADDING_NONE);
use Crypt::PBKDF2;
use Crypt::OpenSSL::PBKDF2;
use String::CRC32;
use MIME::Base64;

#############################################################################
#
# Here is how to add a new hash subroutine to this script file:
#
# 1.	add a new element to the @funcs array.  The case of this string does
#	not matter.  The only time it is shown is on the usage screen, so make
#	it something recognizable to the user wanting to know what this script
#	can do.
# 2.	add a new  sub to the bottom of this program. The sub MUST be same
#	spelling as what is added here, but MUST be lower case.  Thus, we see
#	DES here in funcs array, but the sub is:   sub des($pass)  This
#	subroutine will be passed a candidate password, and should should output
#	the proper hash.  All salts are randomly selected, either from the perl
#	function doing the script, or by using the randstr()  subroutine.
# 3.	Test to make sure it works properly.  Make sure john can find ALL values
#	your subroutine returns.
# 4.	Update the version of this file (at the top of it)
# 5.	Publish it to the john wiki for others to also use.
#
# These john jumbo formats are not done 'yet':
# AFS/KRB5/dominosec/sapG/sapB/DMD5/trip/keychain/pfx/racf/sip/vnc/wpapsk
#
# these are decrypt images, which we may not be able to do in perl. We will take these case by case.
# odf office pdf pkzip zip rar ssh
#
# lotus5 is done in some custom C code.  If someone wants to take a crack at it here, be my guest :)
#############################################################################
my @funcs = (qw(DES BigCrypt BSDI MD5_1 MD5_a BF BFx BFegg RawMD5 RawMD5u
		RawSHA1 RawSHA1u msCash LM NT pwdump RawMD4 PHPass PO hmacMD5
		IPB2 PHPS MD4p MD4s SHA1p SHA1s mysqlSHA1 pixMD5 MSSql05 MSSql12 nsldap
		nsldaps ns XSHA mskrb5 mysql mssql_no_upcase_change mssql oracle
		oracle_no_upcase_change oracle11 hdaa netntlm_ess openssha
		l0phtcrack netlmv2 netntlmv2 mschapv2 mscash2 mediawiki crc_32
		Dynamic dummy rawsha224 rawsha256 rawsha384 rawsha512 dragonfly3_32
		dragonfly4_32 dragonfly3_64 dragonfly4_64 saltedsha1 raw_gost
		raw_gost_cp hmac_sha1 hmac_sha224 hmac_sha256 hmac_sha384 hmac_sha512
		sha256crypt sha512crypt XSHA512  dynamic_27 dynamic_28 pwsafe django
		drupal7 epi episerver_sha1 episerver_sha256 hmailserver ike keepass
		keychain nukedclan pfx racf radmin rawsha0 sip SybaseASE vnc wbb3 wpapsk
		sunmd5 wow_srp));

# todo: ike keychain pfx racf sip vnc wpapsk

my $i; my $h; my $u; my $salt;
my @chrAsciiText=('a'..'z','A'..'Z');
my @chrAsciiTextLo=('a'..'z');
my @chrAsciiTextHi=('A'..'Z');
my @chrAsciiTextNum=('a'..'z','A'..'Z','0'..'9');
my @chrAsciiTextNumUnder=('a'..'z','A'..'Z','0'..'9','_');
my @chrHexHiLo=('0'..'9','a'..'f','A'..'F');
my @chrHexLo=('0'..'9','a'..'f');
my @chrHexHi=('0'..'9','A'..'F');
my @i64 = ('.','/','0'..'9','A'..'Z','a'..'z');
my @ns_i64 = ('A'..'Z', 'a'..'z','0'..'9','+','/',);
my @userNames = (
	"admin", "root", "bin", "Joe", "fi15_characters", "Babeface", "Herman", "lexi Conrad", "jack", "John", "sz110",
	"fR14characters", "Thirteenchars", "Twelve_chars", "elev__chars", "teN__chars", "six16_characters",
#	"Bãrtin",
	"ninechars", "eightchr", "sevench", "barney", "C0ffee", "deadcafe", "user", "01234", "nineteen_characters",
	"eight18_characters", "seven17characters", "u1", "harvey", "john", "ripper", "a", "Hank", "1", "u2", "u3",
	"2", "3", "usr", "usrx", "usry", "skippy", "Bing", "Johnson", "addams", "anicocls", "twentyXXX_characters",
	"twentyoneX_characters", "twentytwoXX_characters");

#########################################################
# These global vars are used by the Dynamic parsing engine
# to deal with unknown formats.
#########################################################
my $gen_u; my $gen_s; my $gen_soutput, my $gen_stype; my $gen_s2; my $gen_pw; my @gen_c; my @gen_toks; my $gen_num;
my $gen_lastTokIsFunc; my $gen_u_do; my $dynamic_usernameType; my $dynamic_passType; my $salt2len; my $saltlen; my $gen_PWCase="";
# pcode, and stack needed for pcode.
my @gen_pCode; my @gen_Stack; my @gen_Flags;
my $debug_pcode=0; my $gen_needs; my $gen_needs2; my $gen_needu; my $gen_singlesalt;
my $hash_format; my $arg_utf8 = 0; my $arg_codepage = ""; my $arg_minlen = 0; my $arg_maxlen = 128; my $arg_dictfile = "unknown";
my $arg_count = 1500, my $argsalt, my $arg_nocomment = 0; my $arg_hidden_cp;

GetOptions(
	'codepage=s'       => \$arg_codepage,
	'hiddencp=s'       => \$arg_hidden_cp,
	'utf8!'            => \$arg_utf8,
	'nocomment!'       => \$arg_nocomment,
	'minlength=n'      => \$arg_minlen,
	'maxlength=n'      => \$arg_maxlen,
	'salt=s'           => \$argsalt,
	'count=n'          => \$arg_count,
	'dictfile=s'       => \$arg_dictfile
	) || usage();

sub usage {
die <<"UsageHelp";
usage: $0 [-h|-?] [codepage=CP|-utf8] [-option[s]] HashType [HashType2 [...]] [ < wordfile ]
    Options can be abbreviated!
    HashType is one or more (space separated) from the following list:
      [ @funcs ]
    Multiple hashtypes are done one after the other. All sample words
    are read from stdin or redirection of a wordfile

    Default is to read and write files as binary, no conversions
    -utf8         shortcut to -codepage=utf8.
    -codepage=CP  Read and write files in CP encoding.

	Options are:
    -minlen <n>   Discard lines shorter than <n> characters  (0)
    -maxlen <n>   Discard lines longer than <n> characters (128)
    -count <n>    Stop when we have produced <n> hashes   (1320)

	-salt <s>     Force a single salt (only supported in a few formats)
    -dictfile <s> Put name of dict file into the first line comment
	-nocomment    eliminate the first line comment

    -help         shows this help screen.
UsageHelp
}

if (@ARGV == 0) {
	die usage();
}

if ($arg_utf8) { $arg_codepage="utf8"; }

#if not a redirected file, prompt the user
if (-t STDIN) {
	print STDERR "\nEnter words to hash, one per line.\n";
	print STDERR "When all entered ^D starts the processing.\n\n";
	$arg_nocomment = 1;  # we do not output 'comment' line if writing to stdout.
}

###############################################################################################
# modifications to character set used.  This is to get pass_gen.pl working correctly
# with john's -utf8 switch.  Also added is code to do max length of passwords.
###############################################################################################
if (defined $arg_codepage and length($arg_codepage)) {
	binmode(STDIN,"encoding(:$arg_codepage)");
	binmode(STDOUT,"encoding(:$arg_codepage)");
	if (!$arg_nocomment) { printf("#!comment: Built with pass_gen.pl using -codepage-$arg_codepage mode, $arg_minlen to $arg_maxlen characters. dict file=$arg_dictfile\n"); }
} else {
	binmode(STDIN,":raw");
	binmode(STDOUT,":raw");
	if (!$arg_nocomment) { printf("#!comment: Built with pass_gen.pl using RAW mode, $arg_minlen to $arg_maxlen characters dict file=$arg_dictfile\n"); }
}
###############################################################################################
###############################################################################################
#### Data Processing Loop.  We read all candidates here, and send them to the proper hashing
#### function(s) to build into john valid input lines.
###############################################################################################
###############################################################################################
if (@ARGV == 1) {
	# if only one format (how this script SHOULD be used), then we do not slurp the file, but we
	# read STDIN line by line.  Cuts down on memory usage GREATLY within the running of the script.
	$u = 0;
	my $orig_arg = lc (defined($_) ? $_ : '');
	my $arg = lc $ARGV[0];
	if ($arg eq "dynamic") { $arg = "dynamic="; }
	if (substr($arg,0,8) eq "dynamic=") {
		@funcs = ();
		push(@funcs, $arg = dynamic_compile(substr($arg,8)));
	}
	foreach (@funcs) {
		if ($arg eq lc $_) {
			if (-t STDOUT) { print "\n  ** Here are the hashes for format $orig_arg **\n"; }
			while (<STDIN>) {
				next if (/^#!comment/);
				chomp;
				s/\r$//;  # strip CR for non-Windows
				my $line_len = length($_);
				next if $line_len > $arg_maxlen || $line_len < $arg_minlen;
				no strict 'refs';
				&$arg($_);
				use strict;
				++$u;
				if ($u >= $arg_count) {
				    print STDERR "Got $arg_count, not processing more. Use -count to bump limit.\n";
				    last;
				}
			}
			last;
		}
	}
} else {
	#slurp the wordlist words from stdin.  We  have to, to be able to run the same words multiple
	# times, and not interleave the format 'types' in the file.  Doing this allows us to group them.
	my @lines = <STDIN>;

	foreach (@ARGV) {
		$u = 0;
		my $orig_arg = lc $_;
		my $arg = lc $_;
		if (substr($arg,0,8) eq "dynamic=") {
			push(@funcs, $arg = dynamic_compile(substr($ARGV[0],8)));
		}
		foreach (@funcs) {
			if ($arg eq lc $_) {
				if (-t STDOUT) { print "\n  ** Here are the hashes for format $orig_arg **\n"; }
				foreach (@lines) {
					next if (/^#!comment/);
					chomp;
					s/\r$//;  # strip CR for non-Windows
					my $line_len = length($_);
					next if $line_len > $arg_maxlen || $line_len < $arg_minlen;
					no strict 'refs';
					&$arg($_);
					use strict;
					++$u;
					last if $u >= $arg_count;
				}
				last;
			}
		}
	}
}

#############################################################################
# used to get salts.  Call with randstr(count[,array of valid chars] );   array is 'optional'  Default is AsciiText (UPloCase,  nums, _ )
#############################################################################
sub randstr
{
	my @chr = defined($_[1]) ? @{$_[1]} : @chrAsciiTextNum;
	my $s;
	foreach (1..$_[0]) {
		$s.=$chr[rand @chr];
	}
	return $s;
}
sub randbytes {
	my $ret = "";
	foreach(1 .. $_[0]) {
		$ret .= chr(rand(256));
	}
	return $ret;
}
sub randusername {
	my $num = shift;
	my $user = $userNames[rand @userNames];
	if (defined($num) && $num > 0) {
		while (length($user) > $num) {
			$user = $userNames[rand @userNames];
		}
	}
	return $user;
}

# helper function needed by md5_a (or md5_1 if we were doing that one)
sub to64 #unsigned long v, int n)
{
	my $str, my $n = $_[1], my $v = $_[0];
	while (--$n >= 0) {
		$str .= $i64[$v & 0x3F];
		$v >>= 6;
	}
	return $str;
}
# helper function for nsldap and nsldaps
sub base64 {
	my $ret = encode_base64($_[0]);
	chomp $ret;
	return $ret;
}
sub _crypt_to64 {
	my $itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	my ($v, $n) = ($_[1], $_[2]);
	while (--$n >= 0) {
		$_[0] .= substr($itoa64, $v & 0x3f, 1);
		$v >>= 6;
	}
}
# used by drupal.  Would also probably be used for phpass.  dragonfly also uses something similar, but 'mixes'
sub base64i {
	my $final = $_[0];
	my $len = length $final;
	my $mod = $len%3;
	my $cnt = ($len-$mod)/3;
	my $out = "";
	my ($l, $p);
	for ($i = 0; $i < $cnt; $i++) {
		$l = (ord(substr($final, $i*3, 1))) | (ord(substr($final, $i*3+1, 1)) << 8) | (ord(substr($final, $i*3+2, 1))<<16);
		_crypt_to64($out, $l, 4); $p += 4;
	}
	if ($mod == 2) { $l = ord(substr($final, $i*3, 1)) | (ord(substr($final, $i*3+1, 1)) << 8); _crypt_to64($out, $l, 4); }
	if ($mod == 1) { $l = ord(substr($final, $i*3, 1));                                         _crypt_to64($out, $l, 4); }
	return $out;
}

#sub ns_base64 {
#	my $ret = "";
#	my $n; my @ha = split(//,$h);
#	for ($i = 0; $i <= $_[0]; ++$i) {
#		# the first one gets some unitialized at times.
#		#$n = ord($ha[$i*3+2]) | (ord($ha[$i*3+1])<<8)  | (ord($ha[$i*3])<<16);
#		$n = ord($ha[$i*3])<<16;
#		if (@ha > $i*3+1) {$n |= (ord($ha[$i*3+1])<<8);}
#		if (@ha > $i*3+2) {$n |= ord($ha[$i*3+2]);}
#		$ret .= "$ns_i64[($n>>18)&0x3F]";
#		if ($_[1] == 3 && $i == $_[0]) { $ret .= "="; }
#		else {$ret .= "$ns_i64[($n>>12)&0x3F]"; }
#		if ($_[1] > 1 && $i == $_[0]) { $ret .= "="; }
#		else {$ret .= "$ns_i64[($n>>6)&0x3F]"; }
#		if ($_[1] > 0 && $i == $_[0]) { $ret .= "="; }
#		else {$ret .= "$ns_i64[$n&0x3F]"; }
#	}
#	return $ret;
#}
##helper function for ns
#sub ns_base64_2 {
#	my $ret = "";
#	my $n; my @ha = split(//,$h);
#	for ($i = 0; $i < $_[0]; ++$i) {
#		# the first one gets some unitialized at times..  Same as the fix in ns_base64
#		#$n = ord($ha[$i*2+1]) | (ord($ha[$i*2])<<8);
#		$n = ord($ha[$i*2])<<8;
#		if (@ha > $i*2+1) { $n |= ord($ha[$i*2+1]); }
#		$ret .= "$ns_i64[($n>>12)&0xF]";
#		$ret .= "$ns_i64[($n>>6)&0x3F]";
#		$ret .= "$ns_i64[$n&0x3F]";
#	}
#	return $ret;
#}
# helper function to convert binary to hex.  Many formats store salts and such in hex
sub saltToHex {
	my $ret = "";
	my @sa = split(//,$salt);
	for ($i = 0; $i < $_[0]; ++$i) {
		$ret .= $chrHexLo[ord($sa[$i])>>4];
		$ret .= $chrHexLo[ord($sa[$i])&0xF];
	}
	return $ret;
}

sub whirlpool_hex {
	my $whirlpool = Digest->new('Whirlpool');
    $whirlpool->add( $_[0] );
    return $whirlpool->hexdigest;
}
sub whirlpool_base64 {
	my $whirlpool = Digest->new('Whirlpool');
    $whirlpool->add( $_[0] );
    return $whirlpool->b64digest;
}
sub whirlpool {
    my $ret;
    my $i;
    my $h = whirlpool_hex($_[0]);
	for($i = 0; $i < 128; $i += 2) {
		$ret .= chr(substr($h,$i,1)*16 + substr($h,$i,1)*1);
	}
    return $ret;
}
#############################################################################
# Here are the encryption subroutines.
#  the format of ALL of these is:    function(password)
#  all salted formats choose 'random' salts, in one way or another.
#############################################################################
sub des {
	if ($argsalt && length($argsalt)==2) {
		$h = Authen::Passphrase::DESCrypt->new(passphrase => $_[0], salt_base64 => $argsalt);
	} else {
		$h = Authen::Passphrase::DESCrypt->new(passphrase => $_[0], salt_random => 12);
	}
	print "u$u-DES:", $h->as_crypt, ":$u:0:$_[0]::\n";
}
sub bigcrypt {
	if (length($_[0]) > 8) {
		$h = Authen::Passphrase::BigCrypt->new(passphrase => $_[0], salt_random => 12);
		print "u$u-DES_BigCrypt:", $h->salt_base64_2, $h->hash_base64, ":$u:0:$_[0]::\n";
	}
}
sub bsdi {
	$h = Authen::Passphrase::DESCrypt->new(passphrase => $_[0], fold => 1, nrounds => 725, salt_random => 24);
	print "u$u-BSDI:", $h->as_crypt, ":$u:0:$_[0]::\n";
}
sub md5_1 {
#	if (length($_[0]) > 15) { print "Warning, john can only handle 15 byte passwords for this format!\n"; }
#	$h = Authen::Passphrase::MD5Crypt->new(passphrase => $_[0], salt_random => 1);
#	print "u$u-MD5:", $h->as_crypt, ":$u:0:$_[0]::\n";

	if (length($_[0]) > 15) { print "Warning, john can only handle 15 byte passwords for this format!\n"; }
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(8); }
	$h = md5_a_hash($_[0], $salt, "\$1\$");
	print "u$u-MD5:$h:$u:0:$_[0]::\n";
}
sub bfx_fix_pass {
	my $pass = $_[0];
	my $i;
	for ($i = 0; $i < length($pass); $i++) {
	   my $s = substr($pass, $i, 1);
	   last if (ord($s) >= 0x80);
	}
	if ($i == length($pass)) { return $pass; } # if no high bits set, then the error would NOT show up.
	my $pass_ret = "";
	# Ok, now do the logic from 'broken' BF_std_set_key().
	# When we get to a 4 byte limb, that has (limb&0xFF) == 0, we return the accumlated string, minus that last null.
	my $BF_word; my $ptr=0;
	for ($i = 0; $i < 18; $i++) {  # BF_Rounds is 16, so 16+2 is 18
		$BF_word = 0;
		for (my $j = 0; $j < 4; $j++) {
			$BF_word <<= 8;
			my $c;
			if ($ptr < length($pass)) {
				$c = substr($pass, $ptr, 1);
				if (ord($c) > 0x80) {
					$BF_word = 0xFFFFFF00;
				}
				$BF_word |= ord($c);
			}
			if ($ptr < length($pass)) { $ptr++; }
			else { $ptr = 0; }
		}
		$pass_ret .= chr(($BF_word&0xFF000000)>>24);
		$pass_ret .= chr(($BF_word&0x00FF0000)>>16);
		$pass_ret .= chr(($BF_word&0x0000FF00)>>8);
		if ( ($BF_word & 0xFF) == 0) {
			# done  (uncomment to see just 'what' the password is.  i.e. the hex string of the password)
			#print unpack("H*", $pass_ret) . "\n";
			return $pass_ret;
		}
		$pass_ret .= chr($BF_word&0xFF);
	}
}
sub bfx {
	my $fixed_pass = bfx_fix_pass($_[0]);
	if ($argsalt && length($argsalt)==16) {
		$h = Authen::Passphrase::BlowfishCrypt->new(passphrase => $fixed_pass, cost => 5, salt => $argsalt);
	}
	else {
		$h = Authen::Passphrase::BlowfishCrypt->new(passphrase => $fixed_pass, cost => 5, salt_random => 1);
	}
	my $hash_str = $h->as_crypt;
	$hash_str =~ s/\$2a\$/\$2x\$/;
	print "u$u-BF:", $hash_str, ":$u:0:$_[0]::\n";
}
sub bf {
	if ($argsalt && length($argsalt)==16) {
		$h = Authen::Passphrase::BlowfishCrypt->new(passphrase => $_[0], cost => 5, salt => $argsalt);
	}
	else {
		$h = Authen::Passphrase::BlowfishCrypt->new(passphrase => $_[0], cost => 5, salt_random => 1);
	}
	print "u$u-BF:", $h->as_crypt, ":$u:0:$_[0]::\n";
}
sub bfegg {
	if (length($_[0]) > 0) {
		$h = Authen::Passphrase::EggdropBlowfish->new(passphrase => $_[0] );
		print "u$u-BFegg:+", $h->hash_base64, ":$u:0:$_[0]::\n";
	}
}
sub rawmd5 {
	print "u$u-RawMD5:", md5_hex($_[0]), ":$u:0:$_[0]::\n";
}
sub rawmd5u {
	print "u$u-RawMD5-unicode:", md5_hex(encode("UTF-16LE",$_[0])), ":$u:0:$_[0]::\n";
}
sub rawsha1 {
	print "u$u-RawSHA1:", sha1_hex($_[0]), ":$u:0:$_[0]::\n";
}
sub rawsha1u {
	print "u$u-RawSHA1-unicode:", sha1_hex(encode("UTF-16LE",$_[0])), ":$u:0:$_[0]::\n";
}
sub rawsha256 {
	print "u$u-RawSHA256:", sha256_hex($_[0]), ":$u:0:$_[0]::\n";
}
sub rawsha224 {
	print "u$u-RawSHA224:", sha224_hex($_[0]), ":$u:0:$_[0]::\n";
}
sub rawsha384 {
	print "u$u-RawSHA384:", sha384_hex($_[0]), ":$u:0:$_[0]::\n";
}
sub rawsha512 {
	print "u$u-RawSHA512:", sha512_hex($_[0]), ":$u:0:$_[0]::\n";
}
sub dragonfly3_32 {
	$salt = randstr(rand(8)+1);
	my $final = sha256($_[0]."\$3\$\0".$salt);
	my $out = "";
	my ($l, $p);
	for ($i = 0; $i < 10; $i++) {
		$l = ord(substr($final, $i, 1)) << 16 | ord(substr($final, $i + 11, 1)) << 8 | ord(substr($final, $i + 21, 1));
		_crypt_to64($out, $l, 4); $p += 4;
	}
	$l = ord(substr($final, 10, 1)) << 16 | ord(substr($final, 31, 1)) << 8;
	_crypt_to64($out, $l, 4);
	print "u$u-dragonfly3_32:", "\$3\$$salt\$" . $out, ":$u:0:$_[0]::\n";
}
sub dragonfly4_32 {
	$salt = randstr(rand(8)+1);
	my $final = sha512($_[0]."\$4\$\0".$salt);
	my $out = "";
	my ($l, $p);
	for ($i = 0; $i < 20; $i++) {
		$l = ord(substr($final, $i, 1)) << 16 | ord(substr($final, $i + 21, 1)) << 8 | ord(substr($final, $i + 42, 1));
		_crypt_to64($out, $l, 4); $p += 4;
	}
	$l = ord(substr($final, 20, 1)) << 16 | ord(substr($final, 41, 1)) << 8;
	_crypt_to64($out, $l, 4);
	print "u$u-dragonfly4_32:", "\$4\$$salt\$" . $out, ":$u:0:$_[0]::\n";
}
sub dragonfly3_64 {
	$salt = randstr(rand(8)+1);
	my $final = sha256($_[0]."\$3\$\0sha5".$salt);
	my $out = "";
	my ($l, $p);
	for ($i = 0; $i < 10; $i++) {
		$l = ord(substr($final, $i, 1)) << 16 | ord(substr($final, $i + 11, 1)) << 8 | ord(substr($final, $i + 21, 1));
		_crypt_to64($out, $l, 4); $p += 4;
	}
	$l = ord(substr($final, 10, 1)) << 16 | ord(substr($final, 31, 1)) << 8;
	_crypt_to64($out, $l, 4);
	print "u$u-dragonfly3_64:", "\$3\$$salt\$" . $out, ":$u:0:$_[0]::\n";
}

sub dragonfly4_64 {
	$salt = randstr(rand(8)+1);
	my $final = sha512($_[0]."\$4\$\0/etc".$salt);
	my $out = "";
	my ($l, $p);
	for ($i = 0; $i < 20; $i++) {
		$l = ord(substr($final, $i, 1)) << 16 | ord(substr($final, $i + 21, 1)) << 8 | ord(substr($final, $i + 42, 1));
		_crypt_to64($out, $l, 4); $p += 4;
	}
	$l = ord(substr($final, 20, 1)) << 16 | ord(substr($final, 41, 1)) << 8;
	_crypt_to64($out, $l, 4);
	print "u$u-dragonfly4_64:", "\$4\$$salt\$" . $out, ":$u:0:$_[0]::\n";
}

sub mscash {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt = randusername(19); }
	print "$salt:", md4_hex(md4(encode("UTF-16LE",$_[0])).encode("UTF-16LE", lc($salt))),
			":$u:0:$_[0]:mscash (uname is salt):\n";
}
sub mscash2 {
	# max username (salt) length is supposed to be 19 characters (in John)
	# max password length is 27 characters (in John)
	# the algorithm lowercases the salt
	my $user;
	if (defined $argsalt) { $user = $argsalt; } else { $user = randusername(22); }
	$salt = encode("UTF-16LE", lc($user));
	my $pbkdf2 = Crypt::PBKDF2->new(
		hash_class => 'HMACSHA1',
		iterations => 10240,
		output_len => 16,
		salt_len => length($salt),
		);
	# Crypt::PBKDF2 hex output is buggy, we do it ourselves!
	print "$user:", unpack("H*", $pbkdf2->PBKDF2($salt,md4(md4(encode("UTF-16LE",$_[0])).$salt))),
	":$u:0:$_[0]:mscash2:\n";
}
sub lm {
	my $s = $_[0];
	if (length($s)>14) { $s = substr($s,14);}
	$h = Authen::Passphrase::LANManager->new(passphrase => length($s) <= 14 ? $s : "");
	print "u$u-LM:$u:", $h->hash_hex, ":$u:0:", uc $s, "::\n";
}
sub nt { #$utf8mode=0, $utf8_pass;
	$h = Authen::Passphrase::NTHash->new(passphrase => $_[0]);
	print "u$u-NT:\$NT\$", $h->hash_hex, ":$u:0:$_[0]::\n";
}
sub pwdump {
	my $lm = Authen::Passphrase::LANManager->new(passphrase => length($_[0]) <= 14 ? $_[0] : "");
	my $nt = Authen::Passphrase::NTHash->new(passphrase => $_[0]);
	print "u$u-pwdump:$u:", $lm->hash_hex, ":", $nt->hash_hex, ":$_[0]::\n";
}
sub rawmd4 {
	print "u$u-RawMD4:", md4_hex($_[0]), ":$u:0:$_[0]::\n";
}
sub mediawiki {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt = randstr(8); }
	print "u$u-mediawiki:\$B\$" . $salt . "\$" . md5_hex($salt . "-" . md5_hex($_[0])) . ":$u:0:$_[0]::\n";
}
sub phpass {
	$h = Authen::Passphrase::PHPass->new(cost => 11, salt_random => 1, passphrase => $_[0]);
	print "u$u-PHPass:", $h->as_crypt, ":$u:0:$_[0]::\n";
}
sub po {
	if (defined $argsalt) {
		if ($argsalt.length() == 32) { $salt = $argsalt; }
		else { $salt = md5_hex($argsalt); }
	} else {
		$salt=randstr(32, \@chrHexLo);
	}
	print "u$u-PO:", md5_hex($salt . "Y" . $_[0] . "\xF7" . $salt), "$salt:$u:0:$_[0]::\n";
}
sub _md5_crypt_to_64 {
	my $c = $_[0];
	my $i;
	# MD5-a (or MD5-BSD and sunmd5), do a strange
	# transposition and base-64 conversion. We do the same here, to get the same hash
	$i = (ord(substr($c,0,1))<<16) | (ord(substr($c,6,1))<<8) | ord(substr($c,12,1));
	my $tmp = to64($i,4);
	$i = (ord(substr($c,1,1))<<16) | (ord(substr($c,7,1))<<8) | ord(substr($c,13,1));
	$tmp .= to64($i,4);
	$i = (ord(substr($c,2,1))<<16) | (ord(substr($c,8,1))<<8) | ord(substr($c,14,1));
	$tmp .= to64($i,4);
	$i = (ord(substr($c,3,1))<<16) | (ord(substr($c,9,1))<<8) | ord(substr($c,15,1));
	$tmp .= to64($i,4);
	$i = (ord(substr($c,4,1))<<16) | (ord(substr($c,10,1))<<8) | ord(substr($c,5,1));
	$tmp .= to64($i,4);
	$i =                                                         ord(substr($c,11,1));
	$tmp .= to64($i,2);
	return $tmp;
}
sub md5_a_hash {
	# not 'native' in the Authen::MD5Crypt (but should be!!!)
	# NOTE, this function is about 2.5x FASTER than Authen::MD5Crypt !!!!!
	# have to use md5() function to get the 'raw' md5s, and do our 1000 loops.
	# md5("a","b","c") == md5("abc");
	my $b, my $c, my $tmp;
	my $type = $_[2];
	my $salt = $_[1];
	#create $b
	$b = md5($_[0],$salt,$_[0]);
	#create $a
	$tmp = $_[0] . $type . $salt;  # if this is $1$ then we have 'normal' BSD MD5
	for ($i = length($_[0]); $i > 0; $i -= 16) {
		if ($i > 16) { $tmp .= $b; }
		else { $tmp .= substr($b,0,$i); }
	}
	for ($i = length($_[0]); $i > 0; $i >>= 1) {
		if ($i & 1) { $tmp .= "\x0"; }
		else { $tmp .= substr($_[0],0,1); }
	}
	$c = md5($tmp);

	# now we do 1000 iterations of md5.
	for ($i = 0; $i < 1000; ++$i) {
		if ($i&1) { $tmp = $_[0]; }
		else      { $tmp = $c; }
		if ($i%3) { $tmp .= $salt; }
		if ($i%7) { $tmp .= $_[0]; }
		if ($i&1) { $tmp .= $c; }
		else      { $tmp .= $_[0]; }
		$c = md5($tmp);
	}
	$tmp = _md5_crypt_to_64($c);
	my $ret = "$type$salt\$$tmp";
	return $ret;
}
sub md5_a {
	if (length($_[0]) > 15) { print "Warning, john can only handle 15 byte passwords for this format!\n"; }
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(8); }
	$h = md5_a_hash($_[0], $salt, "\$apr1\$");
	print "u$u-md5a:$h:$u:0:$_[0]::\n";
}
#int md5bit(unsigned char *digest, int bit_num)
sub md5bit {
	my $digest = $_[0]; my $bit_num=$_[1];
	my $byte_off;
	my $bit_off;

	$bit_num %= 128;
	$byte_off = $bit_num / 8;
	$bit_off = $bit_num % 8;

	my $b = ord(substr($digest, $byte_off, 1));
	if ($b&(1<<$bit_off)) { return 1; }
	return 0;
}
# F'n ugly function, but pretty much straight port from sunmd5 C code.
sub moffet_coinflip {
	my $c = $_[0];
	my $round = $_[1];
	my $i;
	my @shift_4; my @shift_7; my @indirect_4; my @indirect_7;
	my $shift_a; my $shift_b;
	my $indirect_a; my $indirect_b;
	my $bit_a; my $bit_b;

	for ($i = 0; $i < 16; $i++) {
		my $j;
		$j = ($i + 3) & 0xF;
		$shift_4[$i] = ord(substr($c,$j,1)) % 5;
		$shift_7[$i] = (ord(substr($c,$j,1)) >> (ord(substr($c,$i,1)) & 7)) & 0x01;
	}

	$shift_a = md5bit($c, $round);
	$shift_b = md5bit($c, $round + 64);

	for ($i = 0; $i < 16; $i++) {
		$indirect_4[$i] = (ord(substr($c,$i,1)) >> $shift_4[$i]) & 0x0f;
	}
	for ($i = 0; $i < 16; $i++) {
		$indirect_7[$i] = (ord(substr($c,$indirect_4[$i],1)) >> $shift_7[$i]) & 0x7f;
	}
	$indirect_a = $indirect_b = 0;

	for ($i = 0; $i < 8; $i++) {
		$indirect_a |= (md5bit($c, $indirect_7[$i]) << $i);
		$indirect_b |= (md5bit($c, $indirect_7[$i + 8]) << $i);
	}

	$indirect_a = ($indirect_a >> $shift_a) & 0x7f;
	$indirect_b = ($indirect_b >> $shift_b) & 0x7f;

	$bit_a = md5bit($c, $indirect_a);
	$bit_b = md5bit($c, $indirect_b);

	return $bit_a ^ $bit_b;
}
sub _sunmd5_hash {
	my $pw=$_[0];
	my $salt = $_[1];
	my $c = md5($pw,$salt);
	my $i = 0;
	while ($i < 5000) {
		# compute coin flip
		my $round = sprintf("%d", $i);
		# now do md5 on this round
		if (moffet_coinflip($c, $i)) {
			$c = md5(
					$c,
					# this long constant string (AND the null trailing),
					# need to be added, then the round's text number
					"To be, or not to be,--that is the question:--\n",
					"Whether 'tis nobler in the mind to suffer\n",
					"The slings and arrows of outrageous fortune\n",
					"Or to take arms against a sea of troubles,\n",
					"And by opposing end them?--To die,--to sleep,--\n",
					"No more; and by a sleep to say we end\n",
					"The heartache, and the thousand natural shocks\n",
					"That flesh is heir to,--'tis a consummation\n",
					"Devoutly to be wish'd. To die,--to sleep;--\n",
					"To sleep! perchance to dream:--ay, there's the rub;\n",
					"For in that sleep of death what dreams may come,\n",
					"When we have shuffled off this mortal coil,\n",
					"Must give us pause: there's the respect\n",
					"That makes calamity of so long life;\n",
					"For who would bear the whips and scorns of time,\n",
					"The oppressor's wrong, the proud man's contumely,\n",
					"The pangs of despis'd love, the law's delay,\n",
					"The insolence of office, and the spurns\n",
					"That patient merit of the unworthy takes,\n",
					"When he himself might his quietus make\n",
					"With a bare bodkin? who would these fardels bear,\n",
					"To grunt and sweat under a weary life,\n",
					"But that the dread of something after death,--\n",
					"The undiscover'd country, from whose bourn\n",
					"No traveller returns,--puzzles the will,\n",
					"And makes us rather bear those ills we have\n",
					"Than fly to others that we know not of?\n",
					"Thus conscience does make cowards of us all;\n",
					"And thus the native hue of resolution\n",
					"Is sicklied o'er with the pale cast of thought;\n",
					"And enterprises of great pith and moment,\n",
					"With this regard, their currents turn awry,\n",
					"And lose the name of action.--Soft you now!\n",
					"The fair Ophelia!--Nymph, in thy orisons\n",
					"Be all my sins remember'd.\n\x0", # the NULL must be included.
					$round);
		} else {
			$c = md5($c,$round);
		}
		$i++;
	}
	return $c;
}
sub sunmd5 {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(16); }
	$salt = "\$md5\$rounds=904\$".$salt;
	my $c = _sunmd5_hash($_[0], $salt);
	my $h = _md5_crypt_to_64($c);
	print "u$u-sunmd5:$salt\$$h:$u:0:$_[0]::\n";
}
sub wow_srp {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(16); }
	my $usr = uc randusername();

	my $h = sha1($salt, sha1($usr,":",uc $_[0]));

	# turn $h into a hex, so we can load it into a BigInt
	$h = "0x" . unpack("H*", $h);

	# perform exponentation.
	my $base = Math::BigInt->new(47);
	my $exp = Math::BigInt->new($h);
	my $mod = Math::BigInt->new("112624315653284427036559548610503669920632123929604336254260115573677366691719");
	$h = $base->bmodpow($exp, $mod);

	# convert h into upper cased hex  (also salt gets converted into upcased hex)
	$h = uc substr($h->as_hex(), 2);

	print "u$u-wow_srp:\$WoWSRP\$$h\$", uc unpack("H*", $salt), "*$usr:$u:0:", uc $_[0], "::\n";
}
sub binToHex {
	my $bin = shift;
	my $ret = "";
	my @sa = split(//,$bin);
	for ($i = 0; $i < length($bin); ++$i) {
		$ret .= $chrHexLo[ord($sa[$i])>>4];
		$ret .= $chrHexLo[ord($sa[$i])&0xF];
	}
	return $ret;
}
sub _hmacmd5 {
	my ($key, $data) = @_;
	my $ipad; my $opad;
	for ($i = 0; $i < length($key); ++$i) {
		$ipad .= chr(ord(substr($key, $i, 1)) ^ 0x36);
		$opad .= chr(ord(substr($key, $i, 1)) ^ 0x5C);
	}
	while ($i++ < 64) {
		$ipad .= chr(0x36);
		$opad .= chr(0x5C);
	}
	return md5($opad,md5($ipad,$data));
}
sub hmacmd5 {
	# now uses _hmacmd5 instead of being done inline.
	$salt = randstr(32);
	my $bin = _hmacmd5($_[0], $salt);
	print "u$u-hmacMD5:$salt#", binToHex($bin), ":$u:0:$_[0]::\n";
}
sub _hmac_shas {
	my ($func, $pad_sz, $key, $data) = @_;
	my $ipad; my $opad;
	for ($i = 0; $i < length($key); ++$i) {
		$ipad .= chr(ord(substr($key, $i, 1)) ^ 0x36);
		$opad .= chr(ord(substr($key, $i, 1)) ^ 0x5C);
	}
	while ($i++ < $pad_sz) {
		$ipad .= chr(0x36);
		$opad .= chr(0x5C);
	}
	return $func->($opad,$func->($ipad,$data));
}
sub hmac_sha1 {
	$salt = randstr(24);
	my $bin = _hmac_shas(\&sha1, 64, $_[0], $salt);
	print "u$u-hmacSHA1:$salt#", binToHex($bin), ":$u:0:$_[0]::\n";
}
sub hmac_sha224 {
	$salt = randstr(32);
	my $bin = _hmac_shas(\&sha224, 64, $_[0], $salt);
	print "u$u-hmacSHA224:$salt#", binToHex($bin), ":$u:0:$_[0]::\n";
}
sub hmac_sha256 {
	$salt = randstr(32);
	my $bin = _hmac_shas(\&sha256, 64, $_[0], $salt);
	print "u$u-hmacSHA256:$salt#", binToHex($bin), ":$u:0:$_[0]::\n";
}
sub hmac_sha384 {
	$salt = randstr(32);
	my $bin = _hmac_shas(\&sha384, 128, $_[0], $salt);
	print "u$u-hmacSHA384:$salt#", binToHex($bin), ":$u:0:$_[0]::\n";
}
sub hmac_sha512 {
	$salt = randstr(32);
	my $bin = _hmac_shas(\&sha512, 128, $_[0], $salt);
	print "u$u-hmacSHA512:$salt#", binToHex($bin), ":$u:0:$_[0]::\n";
}
sub _sha_crypts {
	my $a; my $b, my $c, my $tmp; my $i; my $ds; my $dp; my $p; my $s;
	my ($func, $bits, $key, $salt) = @_;
	my $bytes = $bits/8;

	$b = $func->($key.$salt.$key);

	# Add for any character in the key one byte of the alternate sum.
	$tmp = $key . $salt;
	for ($i = length($key); $i > 0; $i -= $bytes) {
		if ($i > $bytes) { $tmp .= $b; }
		else { $tmp .= substr($b,0,$i); }
	}

	# Take the binary representation of the length of the key and for every 1 add the alternate sum, for every 0 the key.
	for ($i = length($key); $i > 0; $i >>= 1) {
		if (($i & 1) != 0) { $tmp .= $b; }
		else { $tmp .= $key; }
	}
	$a = $func->($tmp);
	# NOTE, this will be the 'initial' $c value in the inner loop.

	# For every character in the password add the entire password.  produces DP
	$tmp = "";
	for ($i = 0; $i < length($key); ++$i) {
		$tmp .= $key;
	}
	$dp = $func->($tmp);
	# Create byte sequence P.
	$p = "";
	for ($i = length($key); $i > 0; $i -= $bytes) {
		if ($i > $bytes) { $p .= $dp; }
		else { $p .= substr($dp,0,$i); }
	}
	# produce ds
	$tmp = "";
	my $til = 16 + ord(substr($a,0,1));
	for ($i = 0; $i < $til; ++$i) {
		$tmp .= $salt;
	}
	$ds = $func->($tmp);

	# Create byte sequence S.
	for ($i = length($salt); $i > 0; $i -= $bytes) {
		if ($i > $bytes) { $s .= $ds; }
		else { $s .= substr($ds,0,$i); }
	}

	$c = $a; # Ok, we saved this, which will 'seed' our crypt value here in the loop.
	# now we do 5000 iterations of md5.
	for ($i = 0; $i < 5000; ++$i) {
		if ($i&1) { $tmp  = $p; }
		else      { $tmp  = $c; }
		if ($i%3) { $tmp .= $s; }
		if ($i%7) { $tmp .= $p; }
		if ($i&1) { $tmp .= $c; }
		else      { $tmp .= $p; }
#		printf ("%02d=" . unpack("H*", $tmp) . "\n", $i);  # for debugging.
		$c = $func->($tmp);
	}
#	printf ("F =" . unpack("H*", $c) . "\n");  # final value.

	# $c now contains the 'proper' sha_X_crypt hash.  However, a strange transposition and
	# base-64 conversion. We do the same here, to get the same hash.  sha256 and sha512 use
	# a different key schedule.  I have come up with a way to do this, that is not using a
	# table, but using modular walking of the data, 3 values at a time.
	# seel http://www.akkadia.org/drepper/SHA-crypt.txt for information

	my $inc1; my $inc2; my $mod; my $end;
	if ($bits==256) { $inc1=10;$inc2=21;$mod=30;$end=0;  }
	else            { $inc1=21;$inc2=22;$mod=63;$end=21; }
	$i = 0;
	$tmp = "";
	do {
		$tmp .= to64((ord(substr($c,$i,1))<<16) | (ord(substr($c,($i+$inc1)%$mod,1))<<8) | ord(substr($c,($i+$inc1*2)%$mod,1)),4);
		$i = ($i + $inc2) % $mod;
	} while ($i != $end);
	if ($bits==256) { $tmp .= to64((ord(substr($c,31,1))<<8) | ord(substr($c,30,1)),3); }
	else            { $tmp .= to64(ord(substr($c,63,1)),2); }

	return $tmp;
}
sub sha256crypt {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(16); }
	my $bin = _sha_crypts(\&sha256, 256, $_[0], $salt);
	print "u$u-sha256crypt:\$5\$$salt\$$bin:$u:0:$_[0]::\n";
}
sub sha512crypt {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(16); }
	my $bin = _sha_crypts(\&sha512, 512, $_[0], $salt);
	print "u$u-sha512crypt:\$6\$$salt\$$bin:$u:0:$_[0]::\n";
}
sub xsha512 {
# simple 4 byte salted crypt.  No seperator char, just raw hash. Also 'may' have $LION$.  We altenate, and every other
# hash get $LION$ (all even ones)
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(4); }
	print "u$u-XSHA512:";
	if ($u&1) { print ("\$LION\$"); }
	print "" . unpack("H*", $salt) . sha512_hex($salt . $_[0]) . ":$u:0:$_[0]::\n";
}
sub mskrb5 {
	my $password = shift;
	my $datestring = sprintf('20%02u%02u%02u%02u%02u%02uZ', rand(100), rand(12)+1, rand(31)+1, rand(24), rand(60), rand(60));
	my $timestamp = randbytes(14) . $datestring . randbytes(7);
	my $K = Authen::Passphrase::NTHash->new(passphrase => $password)->hash;
	my $K1 = _hmacmd5($K, pack('N', 0x01000000));
	my $K2 = _hmacmd5($K1, $timestamp);
	my $K3 = _hmacmd5($K1, $K2);
	my $encrypted = RC4($K3, $timestamp);
	printf("%s:\$mskrb5\$\$\$%s\$%s:::%s:%s\n", "u$u-mskrb5", binToHex($K2), binToHex($encrypted), $password, $datestring);
}
sub ipb2 {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt = randstr(5); }
	print "u$u-IPB2:\$IPB2\$", saltToHex(5);
	print "\$", md5_hex(md5_hex($salt), md5_hex($_[0])), ":$u:0:$_[0]::\n";

}
sub phps {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt = randstr(3); }
	print "u$u-PHPS:\$PHPS\$", saltToHex(3);
	print "\$", md5_hex(md5_hex($_[0]), $salt), ":$u:0:$_[0]::\n";
}
sub md4p {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt = randstr(8); }
	print "u$u-MD4p:\$MD4p\$$salt\$", md4_hex($salt, $_[0]), ":$u:0:$_[0]::\n";;
}
sub md4s {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt = randstr(8); }
	print "u$u-MD4s:\$MD4s\$$salt\$", md4_hex($_[0], $salt), ":$u:0:$_[0]::\n";;
}
sub sha1p {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt = randstr(8); }
	print "u$u-SHA1p:\$SHA1p\$$salt\$", sha1_hex($salt, $_[0]), ":$u:0:$_[0]::\n";;
}
sub sha1s {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt = randstr(8); }
	print "u$u-SHA1s:\$SHA1s\$$salt\$", sha1_hex($_[0], $salt), ":$u:0:$_[0]::\n";;
}
sub mysqlsha1 {
	print "u$u-mysqlSHA1:*", sha1_hex(sha1($_[0])), ":$u:0:$_[0]::\n";
}
sub mysql{
	my $nr=0x50305735;
	my $nr2=0x12345671;
	my $add=7;
	for (my $i = 0; $i < length($_[0]); ++$i) {
		my $ch = substr($_[0], $i, 1);
		if ( !($ch eq ' ' || $ch eq '\t') ) {
			my $charNum = ord($ch);
			# since perl is big num, we need to force some 32 bit truncation
			# at certain 'points' in the algorithm, by doing &= 0xffffffff
			$nr ^= ((($nr & 63)+$add)*$charNum) + (($nr << 8)&0xffffffff);
			$nr2 += ( (($nr2 << 8)&0xffffffff) ^ $nr);
			$add += $charNum;
		}
	}
	printf("u%d-mysq:%08x%08x:%d:0:%s::\n", $u, ($nr & 0x7fffffff), ($nr2 & 0x7fffffff), $u, $_[0]);
}
sub pixmd5 {
	my $pass = $_[0];
	if (length($pass)>16) { $pass = substr($pass,0,16); }
	my $pass_padd = $pass;
	while (length($pass_padd) < 16) { $pass_padd .= "\x0"; }
	my $c = md5($pass_padd);
	$h = "";
	for ($i = 0; $i < 16; $i+=4) {
		my $n = ord(substr($c,$i,1))|(ord(substr($c,$i+1,1))<<8)|(ord(substr($c,$i+2,1))<<16);
		$h .= $i64[$n       & 0x3f];
		$h .= $i64[($n>>6)  & 0x3f];
		$h .= $i64[($n>>12) & 0x3f];
		$h .= $i64[($n>>18) & 0x3f];
	}
	print "u$u-pixmd5:$h:$u:0:", $pass, "::\n";
}
sub mssql12 {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(4); }
	print "u$u-mssql12:0x0200", uc saltToHex(4);
	print uc sha512_hex(encode("UTF-16LE", $_[0]).$salt), ":$u:0:$_[0]::\n";
}
sub mssql05 {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(4); }
	print "u$u-mssql05:0x0100", uc saltToHex(4);
	print uc sha1_hex(encode("UTF-16LE", $_[0]).$salt), ":$u:0:$_[0]::\n";
}
sub mssql {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(4); }
	my $t = uc $_[0];
	#if (length($_[0]) != length($t)) { print "length wrong\n"; }
	#if ($t =~ m/\uFFFD/) { print "Invalid chars found\n"; }
	#if ($_[0] =~ m/\uFFFD/) { print "Invalid chars found\n"; }

	if (length($_[0]) == length($t)) {
		print "u$u-mssql:0x0100", uc saltToHex(4);
		print uc sha1_hex(encode("UTF-16LE", $_[0]).$salt) . uc sha1_hex(encode("UTF-16LE", $t).$salt), ":$u:0:" . $t . ":" . $_[0] . ":\n";
	}
}
sub mssql_no_upcase_change {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(4); }
	# converts $c into utf8, from $enc code page, and 'sets' the 'flag' in perl that $c IS a utf8 char.
	# since we are NOT doing case changes in this function, it is ASSSUMED that we have been given a properly upcased dictionary
	if (!defined $arg_hidden_cp) { print "ERROR, for this format, you MUST use -hiddencp=CP to set the proper code page conversion\n"; exit(1); }
	my $PASS = Encode::decode(":".$arg_hidden_cp, $_[0]);
	print "u$u-mssql:0x0100", uc saltToHex(4);
	print uc sha1_hex(encode("UTF-16LE", $PASS).$salt) . uc sha1_hex(encode("UTF-16LE", $PASS).$salt), ":$u:0:" . $_[0] . ":" . $_[0] . ":\n";
}

sub nsldap {
	$h = sha1($_[0]);
	#print "u$u-nsldap:{SHA}", ns_base64(6,1), ":$u:0:$_[0]::\n";
	print "u$u-nsldap:{SHA}", base64($h), ":$u:0:$_[0]::\n";
}
sub nsldaps {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(8); }
	$h = sha1($_[0],$salt);
	$h .= $salt;
	#print "u$u-nsldap:{SSHA}", ns_base64(9,2), ":$u:0:$_[0]::\n";
	print "u$u-nsldap:{SSHA}", base64($h), ":$u:0:$_[0]::\n";
}
sub openssha {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(4); }
	$h = sha1($_[0],$salt);
	$h .= $salt;
	#print "u$u-openssha:{SSHA}", ns_base64(7,0), ":$u:0:$_[0]::\n";
	print "u$u-openssha:{SSHA}", base64($h), ":$u:0:$_[0]::\n";
}
sub saltedsha1 {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(rand(16)+1); }
	$h = sha1($_[0],$salt);
	$h .= $salt;
	print "u$u-openssha:{SSHA}", base64($h), ":$u:0:$_[0]::\n";
}
sub ns {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(3 + rand 4, \@chrHexLo); }
	$h = md5($salt, ":Administration Tools:", $_[0]);
	#my $hh = ns_base64_2(8);
	my $hh = base64($h);
	substr($hh, 0, 0) = 'n';
	substr($hh, 6, 0) = 'r';
	substr($hh, 12, 0) = 'c';
	substr($hh, 17, 0) = 's';
	substr($hh, 23, 0) = 't';
	substr($hh, 29, 0) = 'n';
	print "u$u-ns:$salt\$", $hh, ":$u:0:$_[0]::\n";
}
sub xsha {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(4); }
	print "u$u-xsha:", uc saltToHex(4), uc sha1_hex($salt, $_[0]), ":$u:0:$_[0]::\n";
}
sub oracle {
	# snagged perl source from http://users.aber.ac.uk/auj/freestuff/orapass.pl.txt
	my $username;
	if (defined $argsalt) { $username = $argsalt; } else { $username = randusername(16); }
	my $pass = $_[0];
#	print "orig = " . $username . $pass . "\n";
#	print "upcs = " . uc($username.$pass) . "\n\n";
	my $userpass = pack('n*', unpack('C*', uc($username.$pass)));
	$userpass .= pack('C', 0) while (length($userpass) % 8);
	my $key = pack('H*', "0123456789ABCDEF");
	my $iv = pack('H*', "0000000000000000");
	my $cr1 = new Crypt::CBC(	-literal_key => 1, -cipher => "DES", -key => $key, -iv => $iv, -header => "none" );
	my $key2 = substr($cr1->encrypt($userpass), length($userpass)-8, 8);
	my $cr2 = new Crypt::CBC( -literal_key => 1, -cipher => "DES", -key => $key2, -iv => $iv, -header => "none" );
	my $hash = substr($cr2->encrypt($userpass), length($userpass)-8, 8);
	print "$username:", uc(unpack('H*', $hash)), ":$u:0:$pass:oracle_des_hash:\n";
}
sub oracle_no_upcase_change {
	# snagged perl source from http://users.aber.ac.uk/auj/freestuff/orapass.pl.txt
	my $username;
	if (defined $argsalt) { $username = uc $argsalt; } else { $username = uc randusername(16); }
	# converts $c into utf8, from $enc code page, and 'sets' the 'flag' in perl that $c IS a utf8 char.
	# since we are NOT doing case changes in this function, it is ASSSUMED that we have been given a properly upcased dictionary
	if (!defined $arg_hidden_cp) { print "ERROR, for this format, you MUST use -hiddencp=CP to set the proper code page conversion\n"; exit(1); }

	my $pass = $username . Encode::decode(":".$arg_hidden_cp, $_[0]);

	my $userpass = encode("UTF-16BE", $pass);
	$userpass .= pack('C', 0) while (length($userpass) % 8);
	my $key = pack('H*', "0123456789ABCDEF");
	my $iv = pack('H*', "0000000000000000");
	my $cr1 = new Crypt::CBC(	-literal_key => 1, -cipher => "DES", -key => $key, -iv => $iv, -header => "none" );
	my $key2 = substr($cr1->encrypt($userpass), length($userpass)-8, 8);
	my $cr2 = new Crypt::CBC( -literal_key => 1, -cipher => "DES", -key => $key2, -iv => $iv, -header => "none" );
	my $hash = substr($cr2->encrypt($userpass), length($userpass)-8, 8);
	print "$username:", uc(unpack('H*', $hash)), ":$u:0:$pass:oracle_des_hash:\n";
}
sub oracle11 {
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randbytes(10); }
	print "u$u-oracle11:", uc sha1_hex($_[0], $salt), uc saltToHex(10), ":$u:0:$_[0]::\n";
}
sub hdaa {
	# same as dynamic_21
	#  	{"$response$679066476e67b5c7c4e88f04be567f8b$user$myrealm$GET$/$8c12bd8f728afe56d45a0ce846b70e5a$00000001$4b61913cec32e2c9$auth", "nocode"},
	my $user = randusername(20);
	my $realm = randusername(10);
	my $url = randstr(rand(64)+1);
	my $nonce = randstr(rand(32)+1, \@chrHexLo);
	my $clientNonce = randstr(rand(32)+1, \@chrHexLo);
	my $h1 = md5_hex($user, ":".$realm.":", $_[0]);
	my $h2 = md5_hex("GET:/$url");
	my $resp = md5_hex($h1, ":", $nonce, ":00000001:", $clientNonce, ":auth:", $h2);
	print "u$u-HDAA:\$response\$$resp\$$user\$$realm\$GET\$/$url\$$nonce\$00000001\$$clientNonce\$auth:$u:0:$_[0]::\n";
}

sub setup_des_key
{
	my @key_56 = split(//, shift);
	my $key = "";
	$key = $key_56[0];
	$key .= chr(((ord($key_56[0]) << 7) | (ord($key_56[1]) >> 1)) & 255);
	$key .= chr(((ord($key_56[1]) << 6) | (ord($key_56[2]) >> 2)) & 255);
	$key .= chr(((ord($key_56[2]) << 5) | (ord($key_56[3]) >> 3)) & 255);
	$key .= chr(((ord($key_56[3]) << 4) | (ord($key_56[4]) >> 4)) & 255);
	$key .= chr(((ord($key_56[4]) << 3) | (ord($key_56[5]) >> 5)) & 255);
	$key .= chr(((ord($key_56[5]) << 2) | (ord($key_56[6]) >> 6)) & 255);
	$key .= chr((ord($key_56[6]) << 1) & 255);
	return $key;
}
# This produces only NETNTLM ESS hashes, in L0phtcrack format
sub netntlm_ess {
	my $password = shift;
	my $domain = randstr(rand(15)+1);
	my $nthash = Authen::Passphrase::NTHash->new(passphrase => $password)->hash;
	$nthash .= "\x00"x5;
	my $s_challenge = randbytes(8);
	my $c_challenge = randbytes(8);
	my $challenge = substr(md5($s_challenge.$c_challenge), 0, 8);
	my $ntresp = Crypt::ECB::encrypt(setup_des_key(substr($nthash, 0, 7)), 'DES', $challenge, PADDING_NONE);
	$ntresp .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 7, 7)), 'DES', $challenge, PADDING_NONE);
	$ntresp .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 14, 7)), 'DES', $challenge, PADDING_NONE);
	my $type = "ntlm ESS";
	my $lmresp = $c_challenge . "\0"x16;
	printf("%s\\%s:::%s:%s:%s::%s:%s\n", $domain, "u$u-netntlm", binToHex($lmresp), binToHex($ntresp), binToHex($s_challenge), $password, $type);
}
# This produces NETHALFLM, NETLM and non-ESS NETNTLM hashes in L0pthcrack format
sub l0phtcrack {
    my $password = shift;
	my $domain = randstr(rand(15)+1);
	my $nthash = Authen::Passphrase::NTHash->new(passphrase => $password)->hash;
	$nthash .= "\x00"x5;
	my $lmhash; my $lmresp;
	my $challenge = randbytes(8);
	my $ntresp = Crypt::ECB::encrypt(setup_des_key(substr($nthash, 0, 7)), 'DES', $challenge, PADDING_NONE);
	$ntresp .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 7, 7)), 'DES', $challenge, PADDING_NONE);
	$ntresp .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 14, 7)), 'DES', $challenge, PADDING_NONE);
	my $type;
	#if ($arg_utf8 or length($password) > 14) {
	if ($arg_codepage or length($password) > 14) {
		$type = "ntlm only";
		$lmresp = $ntresp;
	} else {
		$type = "lm and ntlm";
		$lmhash = Authen::Passphrase::LANManager->new(passphrase => $password)->hash;
		$lmhash .= "\x00"x5;
		$lmresp = Crypt::ECB::encrypt(setup_des_key(substr($lmhash, 0, 7)), 'DES', $challenge, PADDING_NONE);
		$lmresp .= Crypt::ECB::encrypt(setup_des_key(substr($lmhash, 7, 7)), 'DES', $challenge, PADDING_NONE);
		$lmresp .= Crypt::ECB::encrypt(setup_des_key(substr($lmhash, 14, 7)), 'DES', $challenge, PADDING_NONE);
	}
	printf("%s\\%s:::%s:%s:%s::%s:%s\n", $domain, "u$u-netntlm", binToHex($lmresp), binToHex($ntresp), binToHex($challenge), $password, $type);
}
sub netlmv2 {
	my $pwd = shift;
	my $nthash = Authen::Passphrase::NTHash->new(passphrase => $pwd)->hash;
	my $domain = randstr(rand(15)+1);
	my $user = randusername(20);
	my $identity = Encode::encode("UTF-16LE", uc($user).$domain);
	my $s_challenge = randbytes(8);
	my $c_challenge = randbytes(8);
	my $lmresponse = _hmacmd5(_hmacmd5($nthash, $identity), $s_challenge.$c_challenge);
	printf("%s\\%s:::%s:%s:%s::%s:netlmv2\n", $domain, $user, binToHex($s_challenge), binToHex($lmresponse), binToHex($c_challenge), $pwd);
}
sub netntlmv2 {
	my $pwd = shift;
	my $nthash = Authen::Passphrase::NTHash->new(passphrase => $pwd)->hash;
	my $domain = randstr(rand(15)+1);
	my $user = randusername(20);
	my $identity = Encode::encode("UTF-16LE", uc($user).$domain);
	my $s_challenge = randbytes(8);
	my $c_challenge = randbytes(8);
	my $temp = '\x01\x01' . "\x00"x6 . randbytes(8) . $c_challenge . "\x00"x4 . randbytes(20*rand()+1) . '\x00';
	my $ntproofstr = _hmacmd5(_hmacmd5($nthash, $identity), $s_challenge.$temp);
	# $ntresponse = $ntproofstr.$temp but we separate them with a :
	printf("%s\\%s:::%s:%s:%s::%s:netntlmv2\n", $domain, $user, binToHex($s_challenge), binToHex($ntproofstr), binToHex($temp), $pwd);
}
sub mschapv2 {
	my $pwd = shift;
	my $nthash = Authen::Passphrase::NTHash->new(passphrase => $pwd)->hash;
	my $user = randusername();
	my $a_challenge = randbytes(16);
	my $p_challenge = randbytes(16);
	my $ctx = Digest::SHA->new('sha1');
	$ctx->add($p_challenge);
	$ctx->add($a_challenge);
	$ctx->add($user);
	my $challenge = substr($ctx->digest, 0, 8);
	my $response = Crypt::ECB::encrypt(setup_des_key(substr($nthash, 0, 7)), 'DES', $challenge, PADDING_NONE);
	$response .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 7, 7)), 'DES', $challenge, PADDING_NONE);
	$response .= Crypt::ECB::encrypt(setup_des_key(substr($nthash . "\x00" x 5, 14, 7)), 'DES', $challenge, PADDING_NONE);
	printf("%s:::%s:%s:%s::%s:netntlmv2\n", $user, binToHex($a_challenge), binToHex($response), binToHex($p_challenge), $pwd);
}
sub crc_32 {
	my $pwd = shift;
	if (rand(256) > 245) {
		my $init = rand(2000000000);
		printf("$u-crc32:\$crc32\$%08x.%08x:0:0:100:%s:\n", $init, crc32($pwd,$init), $pwd);
	} else {
		printf("$u-crc32:\$crc32\$00000000.%08x:0:0:100:%s:\n", crc32($pwd), $pwd);
	}
}
sub dummy {
    print "$u-dummy:", '$dummy$', unpack('H*', $_[0]), "\n";
}
sub raw_gost {
	my $pwd = shift;
	printf("$u-gost:\$gost\$%s:0:0:100:%s:\n", gost_hex($pwd), $pwd);
}
#sub raw_gost_cp {
#	# HMMM.  Not sure how to do this at this time in perl.
#}
sub pwsafe {
	if (defined $argsalt && length($argsalt)==32) { $salt = $argsalt; } else { $salt=randstr(32); }
	my $digest = sha256($_[0],$salt);
	my $i;
	for ($i = 0; $i <= 2048; ++$i) {
		$digest = sha256($digest);
	}
	print "u$u-pwsafe:\$pwsafe\$\*3\*", unpack('H*', $salt), "\*2048\*", unpack('H*', $digest), ":$u:0:$_[0]::\n";
}
sub django {
	if (defined $argsalt && length($argsalt)<=32) { $salt = $argsalt; } else { $salt=randstr(12); }
	my $pbkdf2 = Crypt::PBKDF2->new(
		hash_class => 'HMACSHA2',
		iterations => 10000,
		output_len => 32,
		salt_len => length($salt),
		);
	print "u$u-django:\$django\$\*1\*pbkdf2_sha256\$10000\$$salt\$", base64($pbkdf2->PBKDF2($salt, $_[0])), ":$u:0:$_[0]::\n";
}
sub drupal7 {
	if (defined $argsalt && length($argsalt)<=8) { $salt = $argsalt; } else { $salt=randstr(8); }
	# We only handle the 'C' count (16384)
	my $h = sha512($salt.$_[0]);
	my $i = 16384;
	do { $h = sha512($h.$_[0]); } while (--$i > 0);

	print "u$u-drupal:\$S\$C",$salt,substr(base64i($h),0,43),":$u:0:$_[0]::\n";
}
sub epi {
	if (defined $argsalt && length($argsalt)==30) { $salt = $argsalt; } else { $salt=randstr(30); }
	print "u$u-epi:0x", uc(unpack("H*", $salt))," 0x",uc(sha1_hex(substr($salt,0,29),$_[0], "\0")),":$u:0:$_[0]::\n";
}
sub episerver_sha1 {
	if (defined $argsalt && length($argsalt)==16) { $salt = $argsalt; } else { $salt=randstr(16); }
	print "u$u-episvr-v0:\$episerver\$\*0\*", base64($salt), "\*", sha1_base64($salt, Encode::encode("UTF-16LE", $_[0])), ":$u:0:$_[0]::\n";
}
sub episerver_sha256 {
	if (defined $argsalt && length($argsalt)==16) { $salt = $argsalt; } else { $salt=randstr(16); }
	print "u$u-episvr-v1:\$episerver\$\*1\*", base64($salt), "\*", sha256_base64($salt, Encode::encode("UTF-16LE", $_[0])), ":$u:0:$_[0]::\n";
}
sub hmailserver {
	if (defined $argsalt && length($argsalt)==6) { $salt = $argsalt; } else { $salt=randstr(6, \@chrHexLo); }
	print "u$u-hmailserver:$salt",sha256_hex($salt,$_[0]),":$u:0:$_[0]::\n";
}
sub nukedclan {
	if (defined $argsalt && length($argsalt)==20) { $salt = $argsalt; } else { $salt=randstr(20, \@chrAsciiTextNum); }
	my $decal=randstr(1, \@chrHexLo);
	my $pass_hash = sha1_hex($_[0]);
	my $i = 0; my $k;
	$k = hex($decal);

	my $out = "";
	for (; $i < 40; $i += 1, $k += 1) {
		$out .= substr($pass_hash, $i, 1);
		if ($k > 19) { $k = 0; }
		$out .= substr($salt, $k, 1);
	}
	print "u$u-nukedclan:\$nk\$\*",unpack("H*", $salt),"\*#$decal",md5_hex($out),":$u:0:$_[0]::\n";
}
sub radmin {
	my $pass = $_[0];
	while (length($pass) < 100) { $pass .= "\0"; }
	print "u$u-radmin:\$radmin2\$",md5_hex($pass),":$u:0:$_[0]::\n";
}
sub rawsha0 {
# this method sux, but I can find NO sha0 anywhere else in perl.
# It does exist in "openssl dgst -sha"  however. Slow, but works.
	$h = `echo -n '$_[0]' | openssl dgst -sha`;
	chomp($h);
	if (substr($h,0,9) eq "(stdin)= ") { $h = substr($h,9); }
	if (substr($h,0,8) eq "(stdin)=") { $h = substr($h,8); }
	print "u$u-rawsha0:$h:$u:0:$_[0]::\n";
}
sub sybasease {
	if (defined $argsalt && length($argsalt)==8) { $salt = $argsalt; } else { $salt=randstr(8, \@chrAsciiTextNum); }
	my $h = Encode::encode("UTF-16BE", $_[0]);
	while (length($h) < 510) { $h .= "\0\0"; }
	print "u$u-SybaseAES:0xc007", unpack("H*",$salt), sha256_hex($h.$salt),":$u:0:$_[0]::\n";
}
sub wbb3 {
	# Simply 'dynamic' format:  sha1($s.sha1($s.sha1($p)))
	if (defined $argsalt && length($argsalt)==40) { $salt = $argsalt; } else { $salt=randstr(40, \@chrHexLo); }
	print "u$u-wbb3:\$wbb3\$\*1\*$salt\*",sha1_hex($salt,sha1_hex($salt,sha1_hex($_[0]))),":$u:0:$_[0]::\n";
}
sub vnc {
}
sub sip {
}
sub pfx {
}
sub racf {
}
sub keepass {
}
sub ike {
}
sub keychain {
}
sub wpapsk {
}
############################################################
#  DYNAMIC code.  Quite a large block.  Many 'fixed' formats, and then a parser
############################################################
sub dynamic_7 { #dynamic_7 --> md5(md5($p).$s)
	if (defined $argsalt) {
		$salt = $argsalt;
	} else {
		$salt = randstr(3);
	}
	print "u$u-dynamic_7"."\x1F"."dynamic_7", md5_hex(md5_hex($_[0]), $salt), "\$$salt"."\x1F"."$u"."\x1F"."0"."\x1F"."$_[0]"."\x1F"."\x1F"."\n";
}
sub dynamic_17 { #dynamic_17 --> phpass ($P$ or $H$)	phpass
	$h = Authen::Passphrase::PHPass->new(cost => 11, salt_random => 1, passphrase => $_[0]);
	my $hh = $h->as_crypt;
	$salt = substr($hh,3,9);
	print "u$u-dynamic_17:dynamic_17", substr($hh,12), "\$$salt:$u:0:$_[0]::\n";
}
sub dynamic_19 { #dynamic_19 --> Cisco PIX (MD5)
	my $pass;
	if (length($_[0])>16) { $pass = substr($_[0],0,16); } else { $pass = $_[0]; }
	my $pass_padd = $pass;
	while (length($pass_padd) < 16) { $pass_padd .= "\x0"; }
	my $c = md5($pass_padd);
	$h = "";
	for ($i = 0; $i < 16; $i+=4) {
		my $n = ord(substr($c,$i,1))|(ord(substr($c,$i+1,1))<<8)|(ord(substr($c,$i+2,1))<<16);
		$h .= $i64[$n       & 0x3f];
		$h .= $i64[($n>>6)  & 0x3f];
		$h .= $i64[($n>>12) & 0x3f];
		$h .= $i64[($n>>18) & 0x3f];
	}
	print "u$u-dynamic_19:dynamic_19$h:$u:0:", $pass, "::\n";
}
sub dynamic_20 { #dynamic_20 --> Cisco PIX (MD5 salted)
	if (defined $argsalt) {
		$salt = $argsalt;
		if (length($salt) > 4) { $salt = substr($salt,0,4); }
	} else {
		$salt = randstr(4);
	}
	my $pass;
	if (length($_[0])>12) { $pass = substr($_[0],0,12); } else { $pass = $_[0]; }
	my $pass_padd = $pass . $salt;
	while (length($pass_padd) < 16) { $pass_padd .= "\x0"; }
	my $c = md5($pass_padd);
	$h = "";
	for ($i = 0; $i < 16; $i+=4) {
		my $n = ord(substr($c,$i,1))|(ord(substr($c,$i+1,1))<<8)|(ord(substr($c,$i+2,1))<<16);
		$h .= $i64[$n       & 0x3f];
		$h .= $i64[($n>>6)  & 0x3f];
		$h .= $i64[($n>>12) & 0x3f];
		$h .= $i64[($n>>18) & 0x3f];
	}
	print "u$u-dynamic_20:dynamic_20$h\$$salt:$u:0:", $pass, "::\n";
}
sub dynamic_21 { #HDAA HTTP Digest  access authentication
	#dynamic_21679066476e67b5c7c4e88f04be567f8b$8c12bd8f728afe56d45a0ce846b70e5a$$Uuser$$F2myrealm$$F3GET$/$$F400000001$4b61913cec32e2c9$auth","nocode"},
	#
	#digest authentication scheme :
	#H1 = md5(user:realm:password)
	#H2 = md5(method:digestURI)
	#response = H3 = md5(h1:nonce:nonceCount:ClientNonce:qop:h2)
	my $user = randusername(20);
	my $nonce = randstr(32, \@chrHexLo);
	my $clientNonce = randstr(16, \@chrHexLo);
	my $h1 = md5_hex($user, ":myrealm:", $_[0]);
	my $h2 = md5_hex("GET:/");
	my $resp = md5_hex($h1, ":", $nonce, ":00000001:", $clientNonce, ":auth:", $h2);
	print "$user:dynamic_21$resp\$$nonce\$\$U$user\$\$F2myrealm\$\$F3GET\$/\$\$F400000001\$$clientNonce\$auth:$u:0:$_[0]::\n";
}
sub dynamic_27 { #dynamic_27 --> OpenBSD MD5
	#if (length($_[0]) > 15) { print "Warning, john can only handle 15 byte passwords for this format!\n"; }
	#$h = Authen::Passphrase::MD5Crypt->new(salt_random => 1, passphrase => $_[0]);
	#my $hh = $h->as_crypt;
	#$salt = substr($hh,3,8);
	#print "u$u-dynamic_27:\$dynamic_27\$", substr($hh,12), "\$$salt:$u:0:$_[0]::\n";

	if (length($_[0]) > 15) { print "Warning, john can only handle 15 byte passwords for this format!\n"; }
	if (defined $argsalt) {
		$salt = $argsalt;
	} else {
		$salt=randstr(8);
	}
	$h = md5_a_hash($_[0], $salt, "\$1\$");
	print "u$u-dynamic_27:\$dynamic_27\$", substr($h,15), "\$$salt:$u:0:$_[0]::\n";
}
sub dynamic_28 { # Apache MD5
	if (length($_[0]) > 15) { print "Warning, john can only handle 15 byte passwords for this format!\n"; }
	if (defined $argsalt) {
		$salt = $argsalt;
	} else {
		$salt=randstr(8);
	}
	$h = md5_a_hash($_[0], $salt, "\$apr1\$");
	print "u$u-dynamic_28:\$dynamic_28\$", substr($h,15), "\$$salt:$u:0:$_[0]::\n";
}
sub dynamic_compile {
	my $dynamic_args = $_[0];
	if (length($dynamic_args) == 0) {
		print "usage: $0 [-h|-?] HashType ... [ < wordfile ]\n";
		print "\n";
		print "NOTE, for DYNAMIC usage:   here are the possible formats:\n";
		print "    dynamic=#   # can be any of the built in dynamic values. So,\n";
		print "                dynamic=0 will output for md5(\$p) format\n";
		print "\n";
		print "    dynamic=num=#,format=FMT_EXPR[,saltlen=#][,salt=true|ashex|tohex]\n";
		print "         [,pass=uni][,salt2len=#][,const#=value][,usrname=true|lc|uc|uni]\n";
		print "         [,single_salt=1][passcase=uc|lc]]\n";
		print "\n";
		print "The FMT_EXPR is somewhat 'normal' php type format, with some extensions.\n";
		print "    A format such as md5(\$p.\$s.md5(\$p)) is 'normal'.  Dots must be used\n";
		print "    where needed. Also, only a SINGLE expression is valid.  Using an\n";
		print "    expression such as md5(\$p).md5(\$s) is not valid.\n";
		print "    The extensions are:\n";
		print "        Added \$s2 (if 2nd salt is defined),\n";
		print "        Added \$c1 to \$c9 for constants (must be defined in const#= values)\n";
		print "        Added \$u if user name (normal, upper/lower case or unicode convert)\n";
		print "        Handle md5, sha1, md4 sha2 (sha224,sha256,sha384,sha512) gost and whirlpool crypts.\n";
		print "        Handle MD5, SHA1, MD4 SHA2 (all uc(sha2) types) GOST WHILRPOOL which output hex in uppercase.\n";
		print "        Handle md5u, sha1u md4u, sha2*u gostu whirlpoolu which encode to UTF16LE.\n";
		print "          prior to hashing. Warning, be careful with md5u and usrname=uni,\n";
		print "          they will 'clash'\n";
		print "        Handle md5_64, sha1_64, md4_64, sha2*_64 gost_64 whirlpool_64 which output in\n";
		print "          'standard' base-64 which is \"./0-9A-Za-z\"\n";
		print "        Handle md5_64e, sha1_64e, md4_64e, sha2*_64e goste, whirlpoole which output in\n";
		print "          'standard' base-64 which is \"./0-9A-Za-z\" with '=' padding up to even\n";
		print "          4 character (similar to mime-base64\n";
		print "        Handle md5_raw, sha1_raw, md4_raw, sha2*_raw gost_raw whirlpool_raw which output\n";
		print "          is the 'binary' 16 or 20 bytes of data.  CAN not be used as 'outside'\n";
		print "           function\n";
		print "    User names are handled by usrname=  if true, then \'normal\' user names\n";
		print "    used, if lc, then user names are converted to lowercase, if uc then\n";
		print "    they are converted to UPPER case. if uni they are converted into unicode\n";
		print "    If constants are used, then they have to start from const1= and can \n";
		print "    go up to const9= , but they need to be in order, and start from one (1).\n";
		print "    So if there are 3 constants in the expression, then the line needs to\n";
		print "    contain const1=v1,const2=v2,const3=v3 (v's replaced by proper constants)\n";
		print "    if pw=uni is used, the passwords are converted into unicode before usage\n";
		die;
	}
	if ($dynamic_args =~ /^[+\-]?\d*.?\d+$/) { # is $dynamic_args a 'simple' number?
		#my $func = "dynamic_" . $dynamic_args;
		#return $func;

		# before we had custom functions for 'all' of the builtin's.  Now we use the compiler
		# for most of them (in the below switch statement) There are only a handful where
		# we keep the 'original' hard coded function (7,17,19,20,21,27,28)

 		my $func = "dynamic_" . $dynamic_args;
		my $prefmt = "num=$dynamic_args,optimize=1,format=";
		my $fmt;

		SWITCH:	{
			$dynamic_args==0  && do {$fmt='md5($p)';					last SWITCH; };
			$dynamic_args==1  && do {$fmt='md5($p.$s),saltlen=32';		last SWITCH; };
			$dynamic_args==2  && do {$fmt='md5(md5($p))';				last SWITCH; };
			$dynamic_args==3  && do {$fmt='md5(md5(md5($p)))';			last SWITCH; };
			$dynamic_args==4  && do {$fmt='md5($s.$p),saltlen=2';		last SWITCH; };
			$dynamic_args==5  && do {$fmt='md5($s.$p.$s)';				last SWITCH; };
			$dynamic_args==6  && do {$fmt='md5(md5($p).$s)';			last SWITCH; };
			$dynamic_args==8  && do {$fmt='md5(md5($s).$p)';			last SWITCH; };
			$dynamic_args==9  && do {$fmt='md5($s.md5($p))';			last SWITCH; };
			$dynamic_args==10 && do {$fmt='md5($s.md5($s.$p))';			last SWITCH; };
			$dynamic_args==11 && do {$fmt='md5($s.md5($p.$s))';			last SWITCH; };
			$dynamic_args==12 && do {$fmt='md5(md5($s).md5($p))';		last SWITCH; };
			$dynamic_args==13 && do {$fmt='md5(md5($p).md5($s))';		last SWITCH; };
			$dynamic_args==14 && do {$fmt='md5($s.md5($p).$s)';			last SWITCH; };
			$dynamic_args==15 && do {$fmt='md5($u.md5($p).$s)';	 		last SWITCH; };
			$dynamic_args==16 && do {$fmt='md5(md5(md5($p).$s).$s2)';	last SWITCH; };
			$dynamic_args==18 && do {$fmt='md5($s.$c1.$p.$c2.$s),const1=Y,const2='."\xf7".',salt=ashex'; last SWITCH; };
			$dynamic_args==22 && do {$fmt='md5(sha1($p))';				last SWITCH; };
			$dynamic_args==23 && do {$fmt='sha1(md5($p))';				last SWITCH; };
			$dynamic_args==24 && do {$fmt='sha1($p.$s)';				last SWITCH; };
			$dynamic_args==25 && do {$fmt='sha1($s.$p)';				last SWITCH; };
			$dynamic_args==26 && do {$fmt='sha1($p)';					last SWITCH; };
			$dynamic_args==29 && do {$fmt='md5u($p)';					last SWITCH; };
			$dynamic_args==30 && do {$fmt='md4($p)';					last SWITCH; };
			$dynamic_args==31 && do {$fmt='md4($s.$p)';					last SWITCH; };
			$dynamic_args==32 && do {$fmt='md4($p.$s)';					last SWITCH; };
			$dynamic_args==33 && do {$fmt='md4u($p)';					last SWITCH; };
			$dynamic_args==34 && do {$fmt='md5(md4($p))';				last SWITCH; };
			$dynamic_args==35 && do {$fmt='sha1($u.$c1.$p),usrname=uc,const1=:';	last SWITCH; };
			$dynamic_args==36 && do {$fmt='sha1($u.$c1.$p),usrname=true,const1=:';	last SWITCH; };
			$dynamic_args==37 && do {$fmt='sha1($u.$p),usrname=lc';		last SWITCH; };
			$dynamic_args==38 && do {$fmt='sha1($s.sha1($s.sha1($p))),saltlen=20';	last SWITCH; };
			$dynamic_args==50 && do {$fmt='sha224($p)';					last SWITCH; };
			$dynamic_args==51 && do {$fmt='sha224($s.$p),saltlen=2';	last SWITCH; };
			$dynamic_args==52 && do {$fmt='sha224($p.$s)';				last SWITCH; };
			$dynamic_args==60 && do {$fmt='sha256($p)';					last SWITCH; };
			$dynamic_args==61 && do {$fmt='sha256($s.$p),saltlen=2';	last SWITCH; };
			$dynamic_args==62 && do {$fmt='sha256($p.$s)';				last SWITCH; };
			$dynamic_args==70 && do {$fmt='sha384($p)';					last SWITCH; };
			$dynamic_args==71 && do {$fmt='sha384($s.$p),saltlen=2';	last SWITCH; };
			$dynamic_args==72 && do {$fmt='sha384($p.$s)';				last SWITCH; };
			$dynamic_args==80 && do {$fmt='sha512($p)';					last SWITCH; };
			$dynamic_args==81 && do {$fmt='sha512($s.$p),saltlen=2';	last SWITCH; };
			$dynamic_args==82 && do {$fmt='sha512($p.$s)';				last SWITCH; };
			$dynamic_args==90 && do {$fmt='gost($p)';					last SWITCH; };
			$dynamic_args==91 && do {$fmt='gost($s.$p),saltlen=2';		last SWITCH; };
			$dynamic_args==92 && do {$fmt='gost($p.$s)';				last SWITCH; };
			$dynamic_args==100 && do {$fmt='whirlpool($p)';				last SWITCH; };
			$dynamic_args==101 && do {$fmt='whirlpool($s.$p),saltlen=2';	last SWITCH; };
			$dynamic_args==102 && do {$fmt='whirlpool($p.$s)';			last SWITCH; };

			# 7, 17, 19, 20, 21, 27, 28 are still handled by 'special' functions.

			# since these are in dynamic.conf, and treatly 'like' builtins, we might as well put them here.
			$dynamic_args==1001 && do {$fmt='md5(md5(md5(md5($p))))';	last SWITCH; };
			$dynamic_args==1002 && do {$fmt='md5(md5(md5(md5(md5($p)))))';	last SWITCH; };
			$dynamic_args==1003 && do {$fmt='md5(md5($p).md5($p))';		last SWITCH; };
			$dynamic_args==1004 && do {$fmt='md5(md5(md5(md5(md5(md5($p))))))';	last SWITCH; };
			$dynamic_args==1005 && do {$fmt='md5(md5(md5(md5(md5(md5(md5($p)))))))';	last SWITCH; };
			$dynamic_args==1006 && do {$fmt='md5(md5(md5(md5(md5(md5(md5(md5($p))))))))';	last SWITCH; };
			$dynamic_args==1007 && do {$fmt='md5(md5($p).$s)';			last SWITCH; };
			$dynamic_args==1008 && do {$fmt='md5($p.$s),saltlen=16';	last SWITCH; };
			$dynamic_args==1009 && do {$fmt='md5($s.$p),saltlen=16';	last SWITCH; };
			$dynamic_args==1010 && do {$fmt='sha256($s.$p),saltlen=2';	last SWITCH; };
			# dyna-1010 not handled yet (the pad null to 100 bytes)
			return $func;
		}
		# allow the generic compiler to handle these types.
		$dynamic_args = $prefmt.$fmt;

	}

	# now compile.
	dynamic_compile_to_pcode($dynamic_args);

	#return the name of the function to run the compiled pcode.
	return "dynamic_run_compiled_pcode";
}
sub do_dynamic_GetToken {
	# parses next token.
	# the token is placed on the gen_toks array as the 'new' token.
	#  the return is the rest of the string (not tokenized yet)
	# if there is an error, then "tok_bad" (X) is pushed on to the top of the gen_toks array.
	$gen_lastTokIsFunc = 0;
	my $exprStr = $_[0];
	if (!defined($exprStr) || length($exprStr) == 0) { push(@gen_toks, "X"); return $exprStr; }
	my $stmp = substr($exprStr, 0, 1);
 	if ($stmp eq ".") { push(@gen_toks, "."); return substr($exprStr, 1); }
	if ($stmp eq "(") { push(@gen_toks, "("); return substr($exprStr, 1); }
	if ($stmp eq ")") { push(@gen_toks, ")"); return substr($exprStr, 1); }
	if ($stmp eq '$') {
		$stmp = substr($exprStr, 0, 2);
		if ($stmp eq '$p') { push(@gen_toks, "p"); return substr($exprStr, 2); }
		if ($stmp eq '$u') { push(@gen_toks, "u"); return substr($exprStr, 2); }
		if ($stmp eq '$s') {
			if (substr($exprStr, 0, 3) eq '$s2')
			{
				push(@gen_toks, "S");
				return substr($exprStr, 3);
			}
			push(@gen_toks, "s");
			return substr($exprStr, 2);
		}
		if ($stmp ne '$c') { push(@gen_toks, "X"); return $exprStr; }
		$stmp = substr($exprStr, 2, 1);
		if ($stmp eq "1") { push(@gen_toks, "1"); if (!defined($gen_c[0])) {print "\$c1 found, but no constant1 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "2") { push(@gen_toks, "2"); if (!defined($gen_c[1])) {print "\$c2 found, but no constant2 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "3") { push(@gen_toks, "3"); if (!defined($gen_c[2])) {print "\$c3 found, but no constant3 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "4") { push(@gen_toks, "4"); if (!defined($gen_c[3])) {print "\$c4 found, but no constant4 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "5") { push(@gen_toks, "5"); if (!defined($gen_c[4])) {print "\$c5 found, but no constant5 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "6") { push(@gen_toks, "6"); if (!defined($gen_c[5])) {print "\$c6 found, but no constant6 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "7") { push(@gen_toks, "7"); if (!defined($gen_c[6])) {print "\$c7 found, but no constant7 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "8") { push(@gen_toks, "8"); if (!defined($gen_c[7])) {print "\$c8 found, but no constant8 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "9") { push(@gen_toks, "9"); if (!defined($gen_c[8])) {print "\$c9 found, but no constant9 loaded\n"; die; } return substr($exprStr, 3); }
		push(@gen_toks, "X");
		return $exprStr;
	}

	$gen_lastTokIsFunc=1;
	$stmp = uc substr($exprStr, 0, 3);
	if ($stmp eq "MD5") {
		if (substr($exprStr, 0, 7) eq "md5_64e") { push(@gen_toks, "f5e"); return substr($exprStr, 7); }
		if (substr($exprStr, 0, 6) eq "md5_64")  { push(@gen_toks, "f56"); return substr($exprStr, 6); }
		if (substr($exprStr, 0, 4) eq "md5u")    { push(@gen_toks, "f5u"); return substr($exprStr, 4); }
		if (substr($exprStr, 0, 3) eq "md5")     { push(@gen_toks, "f5h"); return substr($exprStr, 3); }
		if (substr($exprStr, 0, 3) eq "MD5")     { push(@gen_toks, "f5H"); return substr($exprStr, 3); }
	} elsif ($stmp eq "SHA") {
		if (substr($exprStr, 0, 8) eq "sha1_64e")  { push(@gen_toks, "f1e");   return substr($exprStr, 8); }
		if (substr($exprStr, 0, 7) eq "sha1_64")   { push(@gen_toks, "f16");   return substr($exprStr, 7); }
		if (substr($exprStr, 0, 5) eq "sha1u")     { push(@gen_toks, "f1u");   return substr($exprStr, 5); }
		if (substr($exprStr, 0, 4) eq "SHA1")      { push(@gen_toks, "f1H");   return substr($exprStr, 4); }
		if (substr($exprStr, 0, 4) eq "sha1")      { push(@gen_toks, "f1h");   return substr($exprStr, 4); }
		if (substr($exprStr, 0,10) eq "sha224_64e"){ push(@gen_toks, "f224e"); return substr($exprStr, 10); }
		if (substr($exprStr, 0, 9) eq "sha224_64") { push(@gen_toks, "f2246"); return substr($exprStr, 9); }
		if (substr($exprStr, 0, 7) eq "sha224u")   { push(@gen_toks, "f224u"); return substr($exprStr, 7); }
		if (substr($exprStr, 0, 6) eq "SHA224")    { push(@gen_toks, "f224H"); return substr($exprStr, 6); }
		if (substr($exprStr, 0, 6) eq "sha224")    { push(@gen_toks, "f224h"); return substr($exprStr, 6); }
		if (substr($exprStr, 0,10) eq "sha256_64e"){ push(@gen_toks, "f256e"); return substr($exprStr, 10); }
		if (substr($exprStr, 0, 9) eq "sha256_64") { push(@gen_toks, "f2566"); return substr($exprStr, 9); }
		if (substr($exprStr, 0, 7) eq "sha256u")   { push(@gen_toks, "f256u"); return substr($exprStr, 7); }
		if (substr($exprStr, 0, 6) eq "SHA256")    { push(@gen_toks, "f256H"); return substr($exprStr, 6); }
		if (substr($exprStr, 0, 6) eq "sha256")    { push(@gen_toks, "f256h"); return substr($exprStr, 6); }
		if (substr($exprStr, 0,10) eq "sha384_64e"){ push(@gen_toks, "f384e"); return substr($exprStr, 10); }
		if (substr($exprStr, 0, 9) eq "sha384_64") { push(@gen_toks, "f3846"); return substr($exprStr, 9); }
		if (substr($exprStr, 0, 7) eq "sha384u")   { push(@gen_toks, "f384u"); return substr($exprStr, 7); }
		if (substr($exprStr, 0, 6) eq "SHA384")    { push(@gen_toks, "f384H"); return substr($exprStr, 6); }
		if (substr($exprStr, 0, 6) eq "sha384")    { push(@gen_toks, "f384h"); return substr($exprStr, 6); }
		if (substr($exprStr, 0,10) eq "sha512_64e"){ push(@gen_toks, "f512e"); return substr($exprStr, 10); }
		if (substr($exprStr, 0, 9) eq "sha512_64") { push(@gen_toks, "f5126"); return substr($exprStr, 9); }
		if (substr($exprStr, 0, 7) eq "sha512u")   { push(@gen_toks, "f512u"); return substr($exprStr, 7); }
		if (substr($exprStr, 0, 6) eq "SHA512")    { push(@gen_toks, "f512H"); return substr($exprStr, 6); }
		if (substr($exprStr, 0, 6) eq "sha512")    { push(@gen_toks, "f512h"); return substr($exprStr, 6); }
	} elsif ($stmp eq "MD4") {
		if (substr($exprStr, 0, 7) eq "md4_64e")   { push(@gen_toks, "f4e"); return substr($exprStr, 7); }
		if (substr($exprStr, 0, 6) eq "md4_64")    { push(@gen_toks, "f46"); return substr($exprStr, 6); }
		if (substr($exprStr, 0, 4) eq "md4u")      { push(@gen_toks, "f4u"); return substr($exprStr, 4); }
		if (substr($exprStr, 0, 3) eq "md4")       { push(@gen_toks, "f4h"); return substr($exprStr, 3); }
		if (substr($exprStr, 0, 3) eq "MD4")       { push(@gen_toks, "f4H"); return substr($exprStr, 3); }
	} elsif ($stmp eq "GOS") {
		if (substr($exprStr, 0, 8) eq "gost_64e")  { push(@gen_toks, "fgoste"); return substr($exprStr, 8); }
		if (substr($exprStr, 0, 7) eq "gost_64")   { push(@gen_toks, "fgost6"); return substr($exprStr, 7); }
		if (substr($exprStr, 0, 5) eq "gostu")     { push(@gen_toks, "fgostu"); return substr($exprStr, 6); }
		if (substr($exprStr, 0, 4) eq "GOST")      { push(@gen_toks, "fgostH"); return substr($exprStr, 4); }
		if (substr($exprStr, 0, 4) eq "gost")      { push(@gen_toks, "fgosth"); return substr($exprStr, 4); }
	} elsif ($stmp eq "WHI") {
		if (substr($exprStr, 0,13) eq "whirlpool_64e")  { push(@gen_toks, "fwrlpe"); return substr($exprStr, 13); }
		if (substr($exprStr, 0,12) eq "whirlpool_64")   { push(@gen_toks, "fwrlp6"); return substr($exprStr, 12); }
		if (substr($exprStr, 0,10) eq "whirlpoolu")     { push(@gen_toks, "fwrlpu"); return substr($exprStr, 10); }
		if (substr($exprStr, 0, 9) eq "WHIRLPOOL")      { push(@gen_toks, "fwrlpH"); return substr($exprStr, 9); }
		if (substr($exprStr, 0, 9) eq "whirlpool")      { push(@gen_toks, "fwrlph"); return substr($exprStr, 9); }
	}

	$gen_lastTokIsFunc=2; # a func, but can NOT be the 'outside' function.
	if (substr($exprStr, 0, 7) eq "md5_raw")    { push(@gen_toks, "f5r");   return substr($exprStr, 7); }
	if (substr($exprStr, 0, 8) eq "sha1_raw")   { push(@gen_toks, "f1r");   return substr($exprStr, 8); }
	if (substr($exprStr, 0, 7) eq "md4_raw")    { push(@gen_toks, "f4r");   return substr($exprStr, 7); }
	if (substr($exprStr, 0,10) eq "sha224_raw") { push(@gen_toks, "f224r"); return substr($exprStr,10); }
	if (substr($exprStr, 0,10) eq "sha256_raw") { push(@gen_toks, "f256r"); return substr($exprStr,10); }
	if (substr($exprStr, 0,10) eq "sha384_raw") { push(@gen_toks, "f384r"); return substr($exprStr,10); }
	if (substr($exprStr, 0,10) eq "sha512_raw") { push(@gen_toks, "f512r"); return substr($exprStr,10); }
	if (substr($exprStr, 0, 8) eq "gost_raw")   { push(@gen_toks, "fgostr");return substr($exprStr, 8); }
	if (substr($exprStr, 0,13) eq "whirlpool_raw")   { push(@gen_toks, "fwrlpr");return substr($exprStr, 13); }

	$gen_lastTokIsFunc=0;
	push(@gen_toks, "X");
	return $exprStr;
}
sub do_dynamic_LexiError {
	print STDERR "Syntax Error around this part of expression:\n";
	print STDERR "$hash_format\n";
	my $v = (length($hash_format) - length($_[0]));
	if ($gen_toks[@gen_toks - 1] ne "X") { --$v; }
	print STDERR " " x $v;
	print STDERR "^\n";
	if ($gen_toks[@gen_toks - 1] eq "X") { print STDERR "Invalid token found\n"; }
	elsif (defined $_[1]) { print STDERR "$_[1]\n"; }
}
sub do_dynamic_Lexi {
	# tokenizes the string, and syntax validates that it IS valid.
	@gen_toks=();
	my $fmt = do_dynamic_GetToken($hash_format);
	if ($gen_lastTokIsFunc!=1) {
		print "The expression MUST start with an md5/md4/sha1 type function.  This one starts with: $_[0]\n";  die;
	}
	my $paren = 0;
	while ($gen_toks[@gen_toks - 1] ne "X") {
		if ($gen_lastTokIsFunc) {
			$fmt = do_dynamic_GetToken($fmt);
			if ($gen_toks[@gen_toks - 1] ne "(") {
				do_dynamic_LexiError($fmt, "A ( MUST follow one of the hash function names"); die;
			}
			next;
		}
		if ($gen_toks[@gen_toks - 1] eq "(") {
			$fmt = do_dynamic_GetToken($fmt);
			if ($gen_toks[@gen_toks - 1] eq "X" || $gen_toks[@gen_toks - 1] eq "." || $gen_toks[@gen_toks - 1] eq "(" || $gen_toks[@gen_toks - 1] eq ")") {
				do_dynamic_LexiError($fmt, "Invalid character following the ( char"); die;
			}
			++$paren;
			next;
		}
		if ($gen_toks[@gen_toks - 1] eq ")") {
			--$paren;
			if ( length($fmt) == 0) {
				if ($paren == 0) {
					# The format is VALID, and proper syntax checking fully done.

					# if we want to dump the token table:
					#for (my $i = 0; $i < @gen_toks; ++$i) {
					#   print "$gen_toks[$i]\n";
					#}
					return @gen_toks; # return the count
				}
				do_dynamic_LexiError($fmt, "Error, not enough ) characters at end of expression"); die;
			}
			if ($paren == 0) {
				do_dynamic_LexiError($fmt, "Error, reached the matching ) to the initial (, but there is still more expression left."); die;
			}
			$fmt = do_dynamic_GetToken($fmt);
			unless ($gen_toks[@gen_toks - 1] eq "." || $gen_toks[@gen_toks - 1] eq ")") {
				do_dynamic_LexiError($fmt, "The only things valid to follow a ) char, are a . or another )"); die;
			}
			next;
		}
		if ($gen_toks[@gen_toks - 1] eq ".") {
			$fmt = do_dynamic_GetToken($fmt);
			if ($gen_toks[@gen_toks - 1] eq "X" || $gen_toks[@gen_toks - 1] eq "." || $gen_toks[@gen_toks - 1] eq "(" || $gen_toks[@gen_toks - 1] eq ")") {
				do_dynamic_LexiError($fmt, "invalid character following the . character"); die;
			}
			next;
		}
		# some 'string op
		$fmt = do_dynamic_GetToken($fmt);
		unless ($gen_toks[@gen_toks - 1] eq ")" || $gen_toks[@gen_toks - 1] eq ".") {
			do_dynamic_LexiError($fmt, "Only a dot '.' or a ) can follow a string type token"); die;
		}
	}
}
sub dynamic_compile_to_pcode {
	$gen_s = ""; $gen_u = ""; $gen_s2 = "";

	my $dynamic_args = $_[0];
	# ok, not a specific version, so we use 'this' format:
	# dynamic=num=1,salt=true,saltlen=8,format=md5(md5(md5($p.$s).$p).$s)
	# which at this point, we would 'see' in dynamic_args:
	# num=1,salt=true,saltlen=8,format=md5(md5(md5($p.$s).$p).$s)

	# get all of the params into a hash table.
	my %hash;
	my @opts = split(/,/,$dynamic_args);
	foreach my $x (@opts) {
	   my @opt = split(/=/,$x);
	   $hash {$opt[0]} = $opt[1];
	}

	@gen_pCode = ();
	@gen_Flags = ();

	########################
	# load the values
	########################

	# Validate that the 'required' params are at least here.
	$gen_num = $hash{"num"};
	if (!defined ($gen_num )) { print "Error, num=# is REQUIRED for dynamic\n"; die; }
	my $v = $hash{"format"};
	if (!defined ($v)) { print "Error, format=EXPR is REQUIRED for dynamic\n"; die; }

	$gen_singlesalt = $hash{"single_salt"};
	if (!defined($gen_singlesalt)) {$gen_singlesalt=0;}

	# load PW
	$gen_pw = $_[0];

	# load a salt.  If this is unused, then we will clear it out after parsing Lexicon
	$saltlen = $hash{"saltlen"};
	unless (defined($saltlen) && $saltlen =~ /^[+\-]?\d*.?\d+$/) { $saltlen = 8; }
	$gen_stype = $hash{"salt"};
	unless (defined($gen_stype)) { $gen_stype = "true"; }

	# load salt #2
	$salt2len = $hash{"salt2len"};
	unless (defined($salt2len) && $salt2len =~ /^[+\-]?\d*.?\d+$/) { $salt2len = 6; }

	# load user name
	$dynamic_usernameType = $hash{"usrname"};
	if (!$dynamic_usernameType) { $dynamic_usernameType=0; }
	$dynamic_passType = $hash{"pass"};
	if (!defined ($dynamic_passType) || $dynamic_passType ne "uni") {$dynamic_passType="";}
	my $pass_case = $hash{"passcase"};
	if (defined($pass_case)) {
		if ( (lc $pass_case) eq "lc") { $gen_PWCase = "L"; }
		if ( (lc $pass_case) eq "uc") { $gen_PWCase = "U"; }
	}

	# load constants
	@gen_c=();
	for (my $n = 1; $n <= 9; ++$n) {
		my $c = "const" . $n;
		$v = $hash{$c};
		if (defined($v)) { push(@gen_c, $v); }
		else {last;}
	}

	$debug_pcode = $hash{"debug"};
	if (!$debug_pcode) { $debug_pcode=0; }

	$hash_format = $hash{"format"};
	my $optimize = $hash{"optimize"};
	if (defined($optimize) && $optimize > 0) {dynamic_compile_Optimize1();}

	######################################
	# syntax check, and load the expression into our token table.
	######################################
	do_dynamic_Lexi();
	unless (@gen_toks > 3) { print "Error, the format= of the expression was missing, or NOT valid\n"; die; }

 	# now clean up salt, salt2, user, etc if they were NOT part of the expression:
	$v = $saltlen; $saltlen=0;
	foreach(@gen_toks) { if ($_ eq "s") {$saltlen=$v;last;} }
	$gen_u_do=0;
	foreach(@gen_toks) { if ($_ eq "u") {$gen_u_do=1;last;} }
	$v = $salt2len; $salt2len=0;
	foreach(@gen_toks) { if ($_ eq "S") {$salt2len=$v;last;} }

	# this function actually BUILDS the pcode.
	$gen_needs = 0; $gen_needs2 = 0; $gen_needu = 0;
	dynamic_compile_expression_to_pcode(0, @gen_toks-1);

	if (defined($optimize) && $optimize > 1) {dynamic_compile_Optimize2();}

	# dump pcode
	if ($debug_pcode) {	foreach (@gen_Flags) { print STDERR "Flag=$_\n"; } }
	if ($debug_pcode) {	foreach (@gen_pCode) { print STDERR "$_\n"; } }
}
sub dynamic_compile_Optimize2() {
}
sub dynamic_compile_Optimize1() {
	# Look for 'salt as hash'  or 'salt as hash in salt2'
	# If ALL instances of $s are md5($s), then then we can use
	# 'salt as hash'.  If there are some md5($s), but some
	# extra $s's scattered in, and we do NOT have any $s2 then
	# we can use the 'salt as hash in salt2' optimization.
	my @positions; my $pos=0;
	while (1) {
		$pos = index($hash_format, 'md5($s)', $pos);
		last if($pos < 0);
		push(@positions, $pos++);
	}
	if (@positions) {
		# found at least 1 md5($s)
		# now, count number of $s's, and if same, then ALL $s's are in md5($s)
		my $count = 0;
		$pos = 0;
		while (1) {
			$pos = index($hash_format, '$s', $pos) + 1;
			last if($pos < 1);
			++$count;
		}
		if ($count == @positions) {
			my $from = quotemeta 'md5($s)'; my $to = '$s';
			$gen_stype = "tohex";
			push (@gen_Flags, "MGF_SALT_AS_HEX");
			if ($debug_pcode == 1) {
				print STDERR "Performing Optimization(Salt_as_hex). Changing format from\n";
				print STDERR "$hash_format\n";
			}
			$hash_format =~ s/$from/$to/g;
			if ($debug_pcode == 1) { print STDERR "to\n$hash_format\n"; }
		}
		else {
			# we still 'might' be able to optimize.  if there is no $s2, then
			# we can still have a salt, and use salt2 as our md5($s) preload.
			if (index($hash_format, '$s2') < 0) {
				$gen_stype = "toS2hex";
				$gen_needs2 = 1;
				my $from = quotemeta 'md5($s)'; my $to = '$s2';
				push (@gen_Flags, "MGF_SALT_AS_HEX_TO_SALT2");
				if ($debug_pcode == 1) {
					print STDERR "Performing Optimization(Salt_as_hex_to_salt2). Changing format from\n";
					print STDERR "$hash_format\n";
				}
				$hash_format =~ s/$from/$to/g;
				if ($debug_pcode == 1) { print STDERR "to\n$hash_format\n"; }
			}
		}
	}
}
sub dynamic_compile_expression_to_pcode {
	#
	# very crappy, recursive decent parser, but 'it works', lol.
	#
	# Now, same parser, but converted into a pcode generator
	# which were very simple changes, using a stack.
	#
	my $cur = $_[0];
	my $curend = $_[1];
	my $curTok;

	# we 'assume' it is likely that we have ( and ) wrapping the expr. We trim them off, and ignore them.
	if ($gen_toks[$cur] eq "(" && $gen_toks[$curend] eq ")") { ++$cur; --$curend; }

	while ($cur <= $curend) {
		$curTok = $gen_toks[$cur];
		if ($curTok eq ".") {
			# in this expression builder, we totally ignore these.
			++$cur;
			next;
		}
		if (length($curTok) > 1 && substr($curTok,0,1) eq "f")
		{
			# find the closing ')' for this md5.
			my $tail; my $count=1;
			++$cur;
			$tail = $cur;
			while ($count) {
				++$tail;
				if ($gen_toks[$tail] eq "(") {++$count;}
				elsif ($gen_toks[$tail] eq ")") {--$count;}
			}

			# OUTPUT CODE  Doing 'some'   md5($value) call   First, push a 'new' var'.  Build it, then perform the crypt
			push(@gen_pCode, "dynamic_push");

			# recursion.
			my $cp = dynamic_compile_expression_to_pcode($cur,$tail);
			$cur = $tail+1;

			# OUTPUT CODE  Now perform the 'correct' crypt.   This will do:
			#   1.  Pop the stack
			#   2. Perform crypt,
			#   3. Perform optional work (like up case, appending '=' chars, etc)
			#   4. Append the computed (and possibly tweaked) hash string to the last string in the stack.
			#   5. return the string.
			push(@gen_pCode, "dynamic_".$curTok);
			next;
		}
		if ($curTok eq "s") {
			# salt could be 'normal' or might be the md5 hex of the salt
			# OUTPUT CODE
			if ($gen_stype eq "tohex") { push(@gen_pCode, "dynamic_app_sh"); }
			else { push(@gen_pCode, "dynamic_app_s"); }
			++$cur;
			$gen_needs = 1;
			next;
		}
		if ($curTok eq "p") { push(@gen_pCode, "dynamic_app_p" . $gen_PWCase); ++$cur; next; }
		if ($curTok eq "S") { push(@gen_pCode, "dynamic_app_S"); ++$cur; $gen_needs2 = 1; next; }
		if ($curTok eq "u") { push(@gen_pCode, "dynamic_app_u"); ++$cur; $gen_needu = 1; next; }
 		if ($curTok eq "1") { push(@gen_pCode, "dynamic_app_1"); ++$cur; next; }
		if ($curTok eq "2") { push(@gen_pCode, "dynamic_app_2"); ++$cur; next; }
		if ($curTok eq "3") { push(@gen_pCode, "dynamic_app_3"); ++$cur; next; }
		if ($curTok eq "4") { push(@gen_pCode, "dynamic_app_4"); ++$cur; next; }
		if ($curTok eq "5") { push(@gen_pCode, "dynamic_app_5"); ++$cur; next; }
		if ($curTok eq "6") { push(@gen_pCode, "dynamic_app_6"); ++$cur; next; }
		if ($curTok eq "7") { push(@gen_pCode, "dynamic_app_7"); ++$cur; next; }
		if ($curTok eq "8") { push(@gen_pCode, "dynamic_app_8"); ++$cur; next; }
		if ($curTok eq "9") { push(@gen_pCode, "dynamic_app_9"); ++$cur; next; }

		print "Error, invalid, can NOT create this expression (trying to build sample test buffer\n";
		die;
	}
}
sub dynamic_run_compiled_pcode {
	######################################
	# now, RUN the expression, to generate our final hash.
	######################################

	if ($gen_needu == 1) { dynamic_load_username(); }
	if ($gen_needs == 1) { dynamic_load_salt(); if ($gen_singlesalt==1) {$gen_needs=2;} }
	if ($gen_needs2 == 1) { dynamic_load_salt2(); if ($gen_singlesalt==1) {$gen_needs=2;} }

	if ($dynamic_passType eq "uni") { $gen_pw = encode("UTF-16LE",$_[0]); }
	else { $gen_pw = $_[0]; }
	@gen_Stack = ();
	# we have to 'preload' this, since the md5() pops, then modifies top element, then returns string.
	# Thus, for the 'last' modification, we need a dummy var there.
	push(@gen_Stack,"");
	foreach my $fn (@gen_pCode) {
		no strict 'refs';
		$h = &$fn();
		use strict;
	}
	if ($gen_needu == 1) { print "$gen_u:\$dynamic_$gen_num\$$h"; }
	else { print "u$u-dynamic_$gen_num:\$dynamic_$gen_num\$$h"; }
	if ($gen_needs > 0) { print "\$$gen_soutput"; }
	if ($gen_needs2 > 0) { if (!defined($gen_stype) || $gen_stype ne "toS2hex") {print "\$\$2$gen_s2";} }
	print ":$u:0:$_[0]::\n";
	return $h;  # might as well return the value.
}
sub dynamic_load_username {
	# load user name
	$gen_u = randusername(12);
	if (defined($dynamic_usernameType)) {
		if ($dynamic_usernameType eq "lc") { $gen_u = lc $gen_u; }
		elsif ($dynamic_usernameType eq "uc") { $gen_u = uc $gen_u; }
		elsif ($dynamic_usernameType eq "uni") { $gen_u = encode("UTF-16LE",$gen_u); }
	}
}
sub dynamic_load_salt {
	if (defined $argsalt) {
		if ($gen_stype eq "ashex") { $gen_s=md5_hex($argsalt); }
		else { $gen_s=$argsalt; }
		$gen_soutput = $gen_s;
		$saltlen = $gen_s.length();
		if ($gen_stype eq "tohex") { $gen_s=md5_hex($gen_s); }
	} else {
		if ($gen_stype eq "ashex") { $gen_s=randstr(32, \@chrHexLo); }
		else { $gen_s=randstr($saltlen); }
		$gen_soutput = $gen_s;
		if ($gen_stype eq "tohex") { $gen_s=md5_hex($gen_s); }
	}
}
sub dynamic_load_salt2() {
	if (defined($gen_stype) && $gen_stype eq "toS2hex") { $gen_s2 = md5_hex($gen_s);  }
	else { $gen_s2 = randstr($salt2len); }
}
##########################################################################
#  Here are the ACTUAL pCode primative functions.  These handle pretty
# much everything dealing with hashing expressions for md5/md4/sha1/sha224
# /sha256/sha384/sha512/gost/whirlpool.
# There are some variables which will be properly prepared prior to any of these
# pCode functions.  These are $gen_pw (the password, possibly in unicode
# format).  $gen_s (the salt), $gen_s2 (the 2nd salt), $gen_u the username
# (possibly in unicode), and @gen_c (array of constants).  Also, prior to
# running against a number, the @gen_Stack is cleaned (but a blank variable
# is pushed to preload it).  To perform this function  md5(md5($p.$s).$p)
# here is the code that WILL be run:
# dynamic_push
# dynamic_push
# dynamic_app_p
# dynamic_app_s
# dynamic_f5h
# dynamic_app_p
# dynamic_f5h
##########################################################################
sub dynamic_push   { push @gen_Stack,""; }
sub dynamic_pop    { return pop @gen_Stack; }  # not really needed.
sub dynamic_app_s  { $gen_Stack[@gen_Stack-1] .= $gen_s; }
sub dynamic_app_sh { $gen_Stack[@gen_Stack-1] .= $gen_s; } #md5_hex($gen_s); }
sub dynamic_app_S  { $gen_Stack[@gen_Stack-1] .= $gen_s2; }
sub dynamic_app_u  { $gen_Stack[@gen_Stack-1] .= $gen_u; }
sub dynamic_app_p  { $gen_Stack[@gen_Stack-1] .= $gen_pw; }
sub dynamic_app_pU { $gen_Stack[@gen_Stack-1] .= uc $gen_pw; }
sub dynamic_app_pL { $gen_Stack[@gen_Stack-1] .= lc $gen_pw; }
sub dynamic_app_1  { $gen_Stack[@gen_Stack-1] .= $gen_c[0]; }
sub dynamic_app_2  { $gen_Stack[@gen_Stack-1] .= $gen_c[1]; }
sub dynamic_app_3  { $gen_Stack[@gen_Stack-1] .= $gen_c[2]; }
sub dynamic_app_4  { $gen_Stack[@gen_Stack-1] .= $gen_c[3]; }
sub dynamic_app_5  { $gen_Stack[@gen_Stack-1] .= $gen_c[4]; }
sub dynamic_app_6  { $gen_Stack[@gen_Stack-1] .= $gen_c[5]; }
sub dynamic_app_7  { $gen_Stack[@gen_Stack-1] .= $gen_c[6]; }
sub dynamic_app_8  { $gen_Stack[@gen_Stack-1] .= $gen_c[7]; }
sub dynamic_app_9  { $gen_Stack[@gen_Stack-1] .= $gen_c[8]; }
sub dynamic_f5h    { $h = pop @gen_Stack; $h = md5_hex($h);  $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f1h    { $h = pop @gen_Stack; $h = sha1_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f4h    { $h = pop @gen_Stack; $h = md4_hex($h);  $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f5H    { $h = pop @gen_Stack; $h = uc md5_hex($h);	 $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f1H    { $h = pop @gen_Stack; $h = uc sha1_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f4H    { $h = pop @gen_Stack; $h = uc md4_hex($h);  $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f56    { $h = pop @gen_Stack; $h = md5_base64($h);	 $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f16    { $h = pop @gen_Stack; $h = sha1_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f46    { $h = pop @gen_Stack; $h = md4_base64($h);  $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f5e    { $h = pop @gen_Stack; $h = md5_base64($h);  while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f1e    { $h = pop @gen_Stack; $h = sha1_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f4e    { $h = pop @gen_Stack; $h = md4_base64($h);  while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f5u    { $h = pop @gen_Stack; $h = md5_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f1u    { $h = pop @gen_Stack; $h = sha1_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f4u    { $h = pop @gen_Stack; $h = md4_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f5r    { $h = pop @gen_Stack; $h = md5($h);  $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f1r    { $h = pop @gen_Stack; $h = sha1($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f4r    { $h = pop @gen_Stack; $h = md4($h);  $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f224h  { $h = pop @gen_Stack; $h = sha224_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f224H  { $h = pop @gen_Stack; $h = uc sha224_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f2246  { $h = pop @gen_Stack; $h = sha224_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f224e  { $h = pop @gen_Stack; $h = sha224_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f224u  { $h = pop @gen_Stack; $h = sha224_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f224r  { $h = pop @gen_Stack; $h = sha224($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f256h  { $h = pop @gen_Stack; $h = sha256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f256H  { $h = pop @gen_Stack; $h = uc sha256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f2566  { $h = pop @gen_Stack; $h = sha256_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f256e  { $h = pop @gen_Stack; $h = sha256_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f256u  { $h = pop @gen_Stack; $h = sha256_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f256r  { $h = pop @gen_Stack; $h = sha256($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f384h  { $h = pop @gen_Stack; $h = sha384_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f384H  { $h = pop @gen_Stack; $h = uc sha384_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f3846  { $h = pop @gen_Stack; $h = sha384_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f384e  { $h = pop @gen_Stack; $h = sha384_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f384u  { $h = pop @gen_Stack; $h = sha384_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f384r  { $h = pop @gen_Stack; $h = sha384($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f512h  { $h = pop @gen_Stack; $h = sha512_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f512H  { $h = pop @gen_Stack; $h = uc sha512_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f5126  { $h = pop @gen_Stack; $h = sha512_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f512e  { $h = pop @gen_Stack; $h = sha512_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f512u  { $h = pop @gen_Stack; $h = sha512_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f512r  { $h = pop @gen_Stack; $h = sha512($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgosth { $h = pop @gen_Stack; $h = gost_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgostH { $h = pop @gen_Stack; $h = uc gost_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgost6 { $h = pop @gen_Stack; $h = gost_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgoste { $h = pop @gen_Stack; $h = gost_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgostu { $h = pop @gen_Stack; $h = gost_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgostr { $h = pop @gen_Stack; $h = gost($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlph { $h = pop @gen_Stack; $h = whirlpool_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlpH { $h = pop @gen_Stack; $h = uc whirlpoolt_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlp6 { $h = pop @gen_Stack; $h = whirlpool_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlpe { $h = pop @gen_Stack; $h = whirlpool_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlpu { $h = pop @gen_Stack; $h = whirlpool_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlpr { $h = pop @gen_Stack; $h = whirlpool($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
