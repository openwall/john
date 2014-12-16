#!/usr/bin/perl -w
use strict;

#############################################################################
# For the version information list and copyright statement,
# see ../doc/pass_gen.Manifest
# Version v1.22.  Update this version signature here, AND the document file.
#############################################################################

# Most "use xxx" now moved to "require xxx" *locally* in respective subs in
# order to only require them when actually used.
#
# use Digest::SHA qw(sha1);
# ->
# require Digest::SHA;
# import Digest::SHA qw(sha1);

use Digest::MD4 qw(md4 md4_hex md4_base64);
use Digest::MD5 qw(md5 md5_hex md5_base64);
use Digest::SHA qw(sha1 sha1_hex sha1_base64
                   sha224 sha224_hex sha224_base64
                   sha256 sha256_hex sha256_base64
                   sha384 sha384_hex sha384_base64
                   sha512 sha512_hex sha512_base64 );
use Encode;
use POSIX;
use Getopt::Long;
use MIME::Base64;

#############################################################################
#
# Here is how to add a new hash subroutine to this script file:
#
# 1.    add a new element to the @funcs array.  The case of this string does
#       not matter.  The only time it is shown is on the usage screen, so make
#       it something recognizable to the user wanting to know what this script
#       can do.
# 2.    add a new  sub to the bottom of this program. The sub MUST be same
#       spelling as what is added here, but MUST be lower case.  Thus, we see
#       DES here in funcs array, but the sub is:   sub des($pass)  This
#       subroutine will be passed a candidate password, and should should output
#       the proper hash.  All salts are randomly selected, either from the perl
#       function doing the script, or by using the randstr()  subroutine.
# 3.    Test to make sure it works properly.  Make sure john can find ALL values
#       your subroutine returns.
# 4.    Update the version of this file (at the top of it)
# 5.    Publish it to the john wiki for others to also use.
#
# these are decrypt images, which we may not be able to do in perl. We will
# take these case by case.
# pdf pkzip rar5, ssh
#
# lotus5 is done in some custom C code.  If someone wants to take a crack at
# it here, be my guest :)
#############################################################################
my @funcs = (qw(DESCrypt BigCrypt BSDIcrypt md5crypt md5crypt_a BCRYPT BCRYPTx
		BFegg Raw-MD5 Raw-MD5u Raw-SHA1 Raw-SHA1u msCash LM NT pwdump
		Raw-MD4 PHPass PO hmac-MD5 IPB2 PHPS MD4p MD4s SHA1p SHA1s
		mysql-sha1 pixMD5 MSSql05 MSSql12 netntlm cisco4 cisco8 cisco9
		nsldap nsldaps ns XSHA krb5pa-md5 krb5-18 mysql mssql_no_upcase_change
		mssql oracle oracle_no_upcase_change oracle11 hdaa netntlm_ess
		openssha l0phtcrack netlmv2 netntlmv2 mschapv2 mscash2 mediawiki
		crc_32 Dynamic dummy raw-sha224 raw-sha256 raw-sha384 raw-sha512
		dragonfly3-32 dragonfly4-32 dragonfly3-64 dragonfly4-64 ssh
		salted-sha1 raw_gost raw_gost_cp hmac-sha1 hmac-sha224 mozilla
		hmac-sha256 hmac-sha384 hmac-sha512 sha256crypt sha512crypt
		XSHA512 dynamic_27 dynamic_28 pwsafe django drupal7 epi zip
		episerver_sha1 episerver_sha256 hmailserver ike keepass pkzip
		keychain nukedclan pfx racf radmin raw-SHA sip SybaseASE vnc
		wbb3 wpapsk sunmd5 wowsrp django-scrypt aix-ssha1 aix-ssha256
		aix-ssha512 pbkdf2-hmac-sha512 pbkdf2-hmac-sha256 scrypt pdf
		rakp osc formspring skey_md5 pbkdf2-hmac-sha1 odf odf-1 office_2007
		skey_md4 skey_sha1 skey_rmd160 cloudkeychain agilekeychain
		rar rar5 ecryptfs office_2010 office_2013 tc_ripemd160 tc_sha512
		tc_whirlpool Haval-256));

# todo: ike keepass cloudkeychain agilekeychain pfx racf sip vnc pdf pkzip rar5 ssh raw_gost_cp
my $i; my $h; my $u; my $salt;
my @chrAsciiText=('a'..'z','A'..'Z');
my @chrAsciiTextLo=('a'..'z');
my @chrAsciiTextHi=('A'..'Z');
my @chrAsciiTextNum=('a'..'z','A'..'Z','0'..'9');
my @chrAsciiTextNumLo=('a'..'z','0'..'9');
my @chrAsciiNum=('0'..'9');
my @chrAsciiTextNumUnder=('a'..'z','A'..'Z','0'..'9','_');
my @chrHexHiLo=('0'..'9','a'..'f','A'..'F');
my @chrHexLo=('0'..'9','a'..'f');
my @chrHexHi=('0'..'9','A'..'F');
my @chrRawData=(0..255); foreach(@chrRawData) {$chrRawData[$_] = chr($chrRawData[$_]);}
my @i64 = ('.','/','0'..'9','A'..'Z','a'..'z');
my @ns_i64 = ('A'..'Z', 'a'..'z','0'..'9','+','/',);
my @userNames = (
	"admin", "root", "bin", "Joe", "fi15_characters", "Babeface", "Herman", "lexi Conrad", "jack", "John", "sz110",
	"fR14characters", "Thirteenchars", "Twelve_chars", "elev__chars", "teN__chars", "six16_characters",
#	"B\xE3rtin",
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
my $debug_pcode=0; my $gen_needs; my $gen_needs2; my $gen_needu; my $gen_singlesalt; my $hash_format; my $net_ssl_init_called = 0;
#########################################################
# These global vars settable by command line args.
#########################################################
my $arg_utf8 = 0; my $arg_codepage = ""; my $arg_minlen = 0; my $arg_maxlen = 128; my $arg_dictfile = "unknown";
my $arg_count = 1500, my $argsalt, my $argiv, my $argcontent; my $arg_nocomment = 0; my $arg_hidden_cp; my $arg_loops=-1;
my $arg_tstall = 0; my $arg_genall = 0; my $arg_nrgenall = 0; my $argmode;

GetOptions(
	'codepage=s'       => \$arg_codepage,
	'hiddencp=s'       => \$arg_hidden_cp,
	'utf8!'            => \$arg_utf8,
	'nocomment!'       => \$arg_nocomment,
	'minlength=n'      => \$arg_minlen,
	'maxlength=n'      => \$arg_maxlen,
	'salt=s'           => \$argsalt,
	'iv=s'             => \$argiv,
	'content=s'        => \$argcontent,
	'mode=s'           => \$argmode,
	'count=n'          => \$arg_count,
	'loops=n'          => \$arg_loops,
	'dictfile=s'       => \$arg_dictfile,
	'tstall!'          => \$arg_tstall,
	'genall!'          => \$arg_genall,
	'nrgenall!'        => \$arg_nrgenall
	) || usage();

sub pretty_print_hash_names {
	my $s; my $s2; my $i;
	my @sorted_funcs = sort {lc($a) cmp lc($b)} @funcs;
	$s2 = "       ";
	for ($i = 0; $i < scalar @sorted_funcs; ++$i) {
		if (length($s2)+length($sorted_funcs[$i]) > 78) {
			$s .= $s2."\n";
			$s2 = "       ";
		}
		$s2 .= $sorted_funcs[$i]." ";
	}
	return $s.$s2."\n";
}

sub usage {
my $s = pretty_print_hash_names();
die <<"UsageHelp";
usage:
  $0 [-codepage=CP|-utf8] [-option[s]] HashType [HashType2 [...]] [<wordfile]
    Options can be abbreviated!
    HashType is one or more (space separated) from the following list:
$s
    Multiple hashtypes are done one after the other. All sample words
    are read from stdin or redirection of a wordfile

    Default is to read and write files as binary, no conversions
    -utf8         shortcut to -codepage=UTF-8.
    -codepage=CP  Read and write files in CP encoding.

    Options are:
    -minlen <n>   Discard lines shorter than <n> characters  (0)
    -maxlen <n>   Discard lines longer than <n> characters (128)
    -count <n>    Stop when we have produced <n> hashes   (1320)
    -loops <n>    some format (pbkdf2, etc), have a loop count. This
                  allows setting a custom count for some formats.

    -salt <s>     Force a single salt (only supported in a few formats)
    -iv <s>       Force a single iv (only supported in a few formats)
    -content <s>  Force a single content (for ODF hash)
    -mode <s>     Force mode (zip, mode 1..3, rar4 modes 1..10, etc)
    -dictfile <s> Put name of dict file into the first line comment
    -nocomment    eliminate the first line comment

    -tstall       runs a 'simple' test for all known types.
    -genall       generates all hashes with random salts.
    -nrgenall     gererates all hashes (non-random, repeatable)

    -help         shows this help screen.
UsageHelp
}

if ($arg_tstall != 0) {
	tst_all();
	exit(0);
}

if ($arg_nrgenall != 0) { $arg_genall = 1; }

if (@ARGV == 0 && $arg_genall == 0) {
	die usage();
}

if ($arg_utf8) {
	#@ARGV = map { decode_utf8($_, 1) } @ARGV;
	$argsalt = decode_utf8($argsalt, 1);
	$arg_codepage="UTF-8";
}

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

if ($arg_genall != 0) {
	while (<STDIN>) {
		next if (/^#!comment/);
		chomp;
		s/\r$//;  # strip CR for non-Windows
		#my $line_len = length($_);
		my $line_len = jtr_unicode_corrected_length($_);
		next if $line_len > $arg_maxlen || $line_len < $arg_minlen;
		gen_all($_);
	}
	exit(0);
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
	if (substr($arg,0,8) eq "dynamic_") { substr($arg,0,8)="dynamic="; }
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
				#my $line_len = length($_);
				my $line_len = jtr_unicode_corrected_length($_);
				next if $line_len > $arg_maxlen || $line_len < $arg_minlen;
				$arg =~ s/-/_/g;
				no strict 'refs';
				&$arg($_, word_encode($_));
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
		if (substr($arg,0,8) eq "dynamic_") { substr($arg,0,8)="dynamic="; }
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
					#my $line_len = length($_);
					my $line_len = jtr_unicode_corrected_length($_);
					next if $line_len > $arg_maxlen || $line_len < $arg_minlen;
					no strict 'refs';
					&$arg($_, word_encode($_));
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
# these 3 functions (the pp_pbkdf2/pp_pbkdf2_hex are the 'exported' functions,
# the other is just a hmac 'helper') replace all requirements on the
# Crypt::PBKDF2 module. this code is VERY simple, and at least as fast as the
# Crypt::PBKDF2, and is MUCH more simple to use (IMHO).  The entire interface
# is in the single function call pp_pbkdf2($pass,$salt,$itr,$algo,$bytes_out)
# pp_pbkdf2_hex() is a simple hex function wrapper function.
#############################################################################
sub hmac_pad {
	my ($pass, $ch, $algo, $pad_len) = @_;
	my $pad;  # ipad or opad, depending upon ch passed in.
	no strict 'refs';
	$pad = &$algo("a");
	$pad = $ch x $pad_len;
	if (length($pass) > $pad_len) { $pass = &$algo($pass); }
	use strict;
	$pad ^= $pass;
	return $pad;
}
sub pp_pbkdf2 {
	my ($pass, $orig_salt, $iter, $algo, $bytes, $pad_len) = @_;
	my $ipad = hmac_pad($pass, '6', $algo, $pad_len);  # 6 is \x36 for an ipad
	my $opad = hmac_pad($pass, '\\', $algo, $pad_len); # \ is \x5c for an opad
	my $final_out=""; my $i=1;
	my $slt;
	while (length($final_out) < $bytes) {
		$slt = $orig_salt . Uint32BERaw($i);
		$i += 1;
		no strict 'refs';
		$slt = &$algo($opad.&$algo($ipad.$slt));
		my $out = $slt;
		for (my $i = 1; $i < $iter; $i += 1) {
			$slt = &$algo($opad.&$algo($ipad.$slt));
			$out ^= $slt;
		}
		use strict;
		if (length($final_out)+length($out) > $bytes) {
			$out = substr($out, 0, $bytes-length($final_out));
		}
		$final_out .= $out;
	}
	return $final_out;
}
sub pp_pbkdf2_hex {
	my ($pass, $slt, $iter, $algo, $bytes, $pad_len) = @_;
	return unpack("H*",pp_pbkdf2($pass,$slt,$iter,$algo,$bytes,$pad_len));
}

#############################################################################
# these functions will encode words 'properly', or at least try to, based upon
# things like -utf8 mode, and possible MS code pages understood by JtR.
#############################################################################
sub ms_word_encode_uc {
    my $s = uc($_[0]);
    if ($arg_utf8) {
        eval { $s = encode("CP850", uc($_[0]), Encode::FB_CROAK); };
        if (!$@) { goto MS_enc_Found; }
        eval { $s = encode("CP437", uc($_[0]), Encode::FB_CROAK); };
        if (!$@) { goto MS_enc_Found; }
        eval { $s = encode("CP852", uc($_[0]), Encode::FB_CROAK); };
        if (!$@) { goto MS_enc_Found; }
        eval { $s = encode("CP858", uc($_[0]), Encode::FB_CROAK); };
        if (!$@) { goto MS_enc_Found; }
        eval { $s = encode("CP866", uc($_[0]), Encode::FB_CROAK); };
        if (!$@) { goto MS_enc_Found; }
        eval { $s = encode("CP737", uc($_[0]), Encode::FB_CROAK); };
        if ($@) {
            print STDERR "UTF-8 input for LM must be encodable in CP850/CP437/CP852/CP858/CP866/CP737.  Use non-UTF8 input with --codepage=xx instead   Word was:  $_[0]\n";
            $s = uc($_[0]);
        }
        MS_enc_Found:;
    } elsif ($arg_codepage) {
        $s = encode($arg_codepage, uc($_[0]));
    }
    return $s;
}
sub word_encode {
    my $s = $_[0];
	if ($arg_codepage) {
        $s = encode($arg_codepage, $_[0]);
    }
    return $s;
}
#############################################################################
# this function does the LM hash in pure perl. It uses an existing
# setup_des_key we were using for the net_ntlm stuff.
#############################################################################
sub LANMan {
	require Crypt::DES;
	my $LMConst = 'KGS!@#$%';
	my $s = ms_word_encode_uc($_[0]);
	if (length($s)>14) { $s = substr($s,0,14); }
	while (length ($s) < 14) { $s .= "\0"; }
	my $des0 = new Crypt::DES setup_des_key(substr($s,0,7));
	my $des1 = new Crypt::DES setup_des_key(substr($s,7,7));
	return $des0->encrypt($LMConst).$des1->encrypt($LMConst);
}

#############################################################################
# This function does PHPass/Wordpress algorithm.
#############################################################################
sub PHPass_hash {
	my ($pw, $cost, $salt) = @_;
	$cost = 1<<$cost;
	my $h = md5($salt.$pw);
	while ($cost-- > 0) {
		$h = md5($h.$pw);
	}
	return $h;
}
# this helper converts 11 into 9, 12 into A, 13 into B, etc. This is the byte
# signature for PHPass, which ends up being 1<<num (num being 7 to 31)
sub to_phpbyte {
	if ($_[0] <= 11) {
		return 0+($_[0]-2);
	}
	return "A"+($_[0]-12);
}


#############################################################################
# this function is 'like' the length($s) function, BUT it has special processing
# needed by JtR.  The only problems we are seeing, is that 4 byte utf-8 (or 5
# byte, etc), end up requiring 4 bytes of buffer, while 3 byte utf-8 only require
# 2 bytes. We have assumption that 1 utf8 char is 2 bytes long. So if we find
# 4 byte characters used for a single utf8 char, then we have to say it is 2
# characters long.  Sounds complicated, and the length is 'not' the proper
# character length, but we have to make this choice, since the low level functions
# in jtr do NOT know unicode, then only know bytes, AND we have to fit things
# into proper buffer length constraints.
#############################################################################
sub jtr_unicode_corrected_length {
	my $base_len = length($_[0]);
	if ($arg_codepage ne "UTF-8") { return $base_len; }
	# We need to check each letter, and see if it takes 4 bytes to store. If
	# so then we charge an extra character to that char (from 1 to 2 utf-16
	# chars). The 1 or 2 byte characters were already handled by length(),
	# we just have to add 'extra' characters for any 4 byte unicode chars.
	my $final_len = $base_len;
	for (my $i = 0; $i < $base_len; $i += 1) {
		my $s = substr($_[0], $i, 1);
		my $ch_bytes = Encode::encode_utf8($s);
		if (length($ch_bytes) > 3) { $final_len += 1; }
	}
	return $final_len;
}

#############################################################################
# if the 'magic' option -tstall is used, we simply call a function that calls
# ALL of the functions which is used to test if all CPAN modules are installed.
#############################################################################
sub tst_all {
	$u = 1;
	my $cnt = 0;
	$arg_hidden_cp = "iso-8859-1";
	foreach my $f (@funcs) {
		no strict 'refs';
		$f = lc $f;
		$f =~ s/-/_/g;
		if ($f ne "dynamic") {&$f("password", word_encode("password")); $cnt += 1;}
		use strict;
	}
	# now test all 'simple' dyna which we have defined (number only)
	for (my $i = 0; $i < 10000; $i += 1) {
		my $f = dynamic_compile($i);
		no strict 'refs';
		$f = lc $f;
		if (defined(&{$f})) {&$f("password", word_encode("password")); $cnt += 1;}
		use strict;
	}
	print STDERR "\nAll formats were able to be run ($cnt total formats). All CPAN modules installed\n";
}

sub gen_all {
	$u = 1;
	$arg_hidden_cp = "iso-8859-1";
	srand(666);
	foreach my $f (@funcs) {
		no strict 'refs';
		$f = lc $f;
		$f =~ s/-/_/g;
		if ($f ne "dynamic") {&$f($_[0], word_encode($_[0]));}
		use strict;
	}
	# now test all 'simple' dyna which we have defined (number only)
	for (my $i = 0; $i < 10000; $i += 1) {
		my $f = dynamic_compile($i);
		no strict 'refs';
		$f = lc $f;
		if (defined(&{$f})) {&$f($_[0], word_encode($_[0]));}
		use strict;
	}
}

#############################################################################
# used to get salts.  Call with randstr(count[,array of valid chars] );   array is 'optional'  Default is AsciiText (UPloCase,  nums, _ )
#############################################################################
sub randstr {
	my @chr = defined($_[1]) ? @{$_[1]} : @chrAsciiTextNum;
	my $s="";
	if ($arg_nrgenall != 0) { srand(666); }
	foreach (1..$_[0]) {
		$s.=$chr[rand @chr];
	}
	return $s;
}
sub randusername {
	my $num = shift;
	if ($arg_nrgenall != 0) { srand(666); }
	my $user = $userNames[rand @userNames];
	if (defined($num) && $num > 0) {
		while (length($user) > $num) {
			$user = $userNames[rand @userNames];
		}
	}
	return $user;
}
# this will return the same LE formated buffer as 'uint32_t i' would on Intel
sub Uint32LERaw {
	my $i = $_[0];
	return chr($i&0xFF).chr(($i>>8)&0xFF).chr(($i>>16)&0xFF).chr(($i>>24)&0xFF);
}
# this will return the same BE formated buffer as 'uint32_t i' would on Motorola
sub Uint32BERaw {
	my $i = $_[0];
	return chr(($i>>24)&0xFF).chr(($i>>16)&0xFF).chr(($i>>8)&0xFF).chr($i&0xFF);
}

sub net_ssl_init {
	if ($net_ssl_init_called == 1) { return; }
	$net_ssl_init_called = 1;
	require Net::SSLeay;
	import Net::SSLeay qw(die_now die_if_ssl_error);
	Net::SSLeay::load_error_strings();
	Net::SSLeay::SSLeay_add_ssl_algorithms();    # Important!
	Net::SSLeay::ENGINE_load_builtin_engines();  # If you want built-in engines
	Net::SSLeay::ENGINE_register_all_complete(); # If you want built-in engines
	Net::SSLeay::OpenSSL_add_all_digests();
}
############################################################################################
# returns salt.  Usage:  get_salt(len [,argsalt_len [,@character_set]] )
# if len is negative, then we want a random salt len that is int(rand(-len))+1 bytes long
# if argsalt_len is missing, then argsalt_len is set to len (after it is set positive)
# if argsalt_len is there, it is used. If it is -1, then any length argsalt is ok, if it is
#   negative (not -1), then only argsalts <= -argsalt_len are used.
# if the length of the salt is 2*aslen, and the argsalt is hex, then it is first converted
#   into raw before it is later used.  One caveat is you can not do a hex argsalt that is for
#   a variable length salt, since there is no way to check that length is 2x what it should be.
# the 3rd param (optional), is the character set.  @chrAsciiTextNum is default.
############################################################################################
sub get_salt {
	my $len = $_[0];
	my $randlen = 0;
	if ($len < 0) { $randlen = 1; $len *= -1; }
	my $aslen = $len;
	if (defined $_[1] && $_[1]+0 eq $_[1]) { $aslen = $_[1]; }
	my @chr = defined($_[2]) ? @{$_[2]} : @chrAsciiTextNum;
	if (defined $argsalt && length ($argsalt)==$aslen*2 && length(pack("H*",$argsalt))==$aslen) {
		$argsalt = pack("H*",$argsalt);
	}
	if (defined $argsalt && ($aslen == -1 || ($aslen < -1 && length($argsalt) <= -1*$aslen) || length ($argsalt)==$aslen) ) {
		return ($argsalt);
	}
	if (@chr == @userNames) { return randusername($len); }
	elsif ($randlen == 0) { return randstr($len, \@chr); }
	if ($len > 8) {
		my $l = int(rand(8))+int(rand($len-8))+1;
		if ($l > $len) { $l = $len; }
		return randstr($l, \@chr);
	}
	return randstr(int(rand($len))+1, \@chr);
}
sub get_iv {
	my $len = $_[0];
	my @chr = defined($_[1]) ? @{$_[1]} : @chrAsciiTextNum;
	if (defined $argiv && length ($argiv)==$len*2 && length(pack("H*",$argiv))==$len) {
		$argiv = pack("H*",$argiv);
	}
	if (defined $argiv && length ($argiv)==$len) {
		return ($argiv);
	}
	return randstr($len, \@chr);
}
sub get_content {
	my $len = $_[0];
	my $randlen = 0;
	if ($len < 0) { $randlen = 1; $len *= -1; }
	my $aslen = $len;
	if (defined $_[1] && $_[1]+0 eq $_[1]) { $aslen = $_[1]; }
	my @chr = defined($_[2]) ? @{$_[2]} : @chrAsciiTextNum;
	if (defined $argcontent && ($aslen == -1 || ($aslen < -1 && length($argcontent) <= -1*$aslen) || length ($argcontent)==$aslen) ) {
		return ($argcontent);
	}
	if ($randlen == 0) { return randstr($len, \@chr); }
	if ($len > 32) {
		my $l = int(rand(32))+int(rand($len-32))+1;
		if ($l > $len) { $l = $len; }
		return randstr($l, \@chr);
	}
	return randstr(int(rand($len))+1, \@chr);
}

############################################################################################
# we need a getter function for $iv also (and content??, and possibly others) that are
# modeled after get_salt()
############################################################################################

# helper function needed by md5crypt_a (or md5crypt if we were doing that one)
sub to64 #unsigned long v, int n)
{
	my $str, my $n = $_[1], my $v = $_[0];
	while (--$n >= 0) {
		$str .= $i64[$v & 0x3F];
		$v >>= 6;
	}
	return $str;
}
# uses encode_64, but replaces all + with .  NOT sure why, but that is what it does.
# used in at least pbkdf2-hmac-sha256. Probably others.
sub base64pl {
	my $ret = encode_base64($_[0]);
	$ret =~ s/\+/./g;
	chomp $ret;
	return $ret;
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
	#print "\n".unpack("H*",$final)."\n";
	my $len = length $final;
	my $mod = $len%3;
	my $cnt = ($len-$mod)/3;
	my $out = "";
	my $l;
	for ($i = 0; $i < $cnt; $i++) {
		$l = (ord(substr($final, $i*3, 1))) | (ord(substr($final, $i*3+1, 1)) << 8) | (ord(substr($final, $i*3+2, 1))<<16);
		_crypt_to64($out, $l, 4);
	}
	if ($mod == 2) { $l = ord(substr($final, $i*3, 1)) | (ord(substr($final, $i*3+1, 1)) << 8); _crypt_to64($out, $l, 4); }
	if ($mod == 1) { $l = ord(substr($final, $i*3, 1));                                         _crypt_to64($out, $l, 4); }
	return $out;
}

# the encoding used for JtR wpapsk is strange enough, I had to make my own version.
# base64i 'worked' but the data output was out of order (I think it was LE vs BE building).
sub _crypt_to64_wpa {
	my $itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	my ($v, $n) = ($_[1], $_[2]);
	while (--$n >= 0) {
		$_[0] .= substr($itoa64, ($v & 0xFC0000)>>18, 1);
		$v <<= 6;
	}
}
sub base64_wpa {
	my $final = $_[0];
	my $len = length $final;
	my $mod = $len%3;
	my $cnt = ($len-$mod)/3;
	my $out = "";
	my $l;
	for ($i = 0; $i < $cnt; $i++) {
		$l = (ord(substr($final, $i*3, 1))<<16) | (ord(substr($final, $i*3+1, 1)) << 8) | (ord(substr($final, $i*3+2, 1)));
		_crypt_to64_wpa($out, $l, 4);
	}
	if ($mod == 2) { $l = (ord(substr($final, $i*3, 1))<<16) | (ord(substr($final, $i*3+1, 1))<<8); _crypt_to64_wpa($out, $l, 3); }
	if ($mod == 1) { $l = (ord(substr($final, $i*3, 1))<<16);                                       _crypt_to64_wpa($out, $l, 2); }
	return $out;
}
# aix was like wpa, byte swapped, but it also swaps the end result chars (4 byte swap), and odd last limb gets all 4, swaps and then trims.
sub base64_aix {
	my $final = $_[0];
	my $len = length $final;
	my $mod = $len%3;
	my $cnt = ($len-$mod)/3;
	my $out = "";
	my $l;
	for ($i = 0; $i < $cnt; $i++) {
		$l = (ord(substr($final, $i*3, 1))<<16) | (ord(substr($final, $i*3+1, 1)) << 8) | (ord(substr($final, $i*3+2, 1)));
		my $x="";
		_crypt_to64_wpa($x, $l, 4);
		$out .= substr($x,3,1);
		$out .= substr($x,2,1);
		$out .= substr($x,1,1);
		$out .= substr($x,0,1);
	}
	if ($mod == 2) {
		$l = (ord(substr($final, $i*3, 1))<<16) | (ord(substr($final, $i*3+1, 1))<<8);
		my $x="";
		_crypt_to64_wpa($x, $l, 4);
		$out .= substr($x,3,1);
		$out .= substr($x,2,1);
		$out .= substr($x,1,1);
	}
	if ($mod == 1) {
		$l = (ord(substr($final, $i*3, 1))<<16);
		my $x="";
		_crypt_to64_wpa($x, $l, 4);
		$out .= substr($x,3,1);
		$out .= substr($x,2,1);
	}
	return $out;
}

sub whirlpool_hex {
	require Digest;
	my $whirlpool = Digest->new('Whirlpool');
	$whirlpool->add( $_[0] );
	return $whirlpool->hexdigest;
}
sub whirlpool_base64 {
	require Digest;
	my $whirlpool = Digest->new('Whirlpool');
	$whirlpool->add( $_[0] );
	return $whirlpool->b64digest;
}
sub whirlpool {
	require Digest;
	my $whirlpool = Digest->new('Whirlpool');
	$whirlpool->add( $_[0] );
	return $whirlpool->digest;
}

sub haval256 {
	require Digest::Haval256;
	my $hash = new Digest::Haval256;
	$hash->add( $_[0] );
	my $h = $hash->digest;
	return $h;
}
sub haval256_hex {
	require Digest::Haval256;
	my $hash = new Digest::Haval256;
	$hash->add( $_[0] );
	return $hash->hexdigest;
}
sub haval256_base64 {
	require Digest::Haval256;
	my $hash = new Digest::Haval256;
	$hash->add( $_[0] );
	return $hash->base64digest;
}
sub tiger_hex {
	require Digest::Tiger;
	return lc Digest::Tiger::hexhash($_[0]);
}
sub tiger {
	my $h = tiger_hex($_[0]);
	my $ret = pack "H*", $h;
	return $ret;
}
sub tiger_base64 {
	require Digest::Tiger;
	my $bin = pack "H*", lc Digest::Tiger::hexhash($_[0]);
	return encode_base64($bin);
}
# these all come from CryptX usage.
sub ripemd128_hex {
	# these come from CryptX which is very hard to get working under Cygwin, but the only place
	# to find RIPEMD128, RIPEMD266, RIPEMD320.  We use the Crypt::Digest usage, instead of
	# loading each Digest type (4 of them, at least)
	require Crypt::Digest::RIPEMD128;
	Crypt::Digest::RIPEMD128::ripemd128_hex($_[0]);
}
sub ripemd128 {
	require Crypt::Digest::RIPEMD128;
	Crypt::Digest::RIPEMD128::ripemd128($_[0]);
}
sub ripemd128_base64 {
	require Crypt::Digest::RIPEMD128;
	Crypt::Digest::RIPEMD128::ripemd128_base64($_[0]);
}
sub ripemd160_hex {
	require Crypt::Digest::RIPEMD160;
	Crypt::Digest::RIPEMD160::ripemd160_hex($_[0]);
}
sub ripemd160 {
	require Crypt::Digest::RIPEMD160;
	Crypt::Digest::RIPEMD160::ripemd160($_[0]);
}
sub ripemd160_base64 {
	require Crypt::Digest::RIPEMD160;
	Crypt::Digest::RIPEMD160::ripemd160_base64($_[0]);
}
sub ripemd256_hex {
	require Crypt::Digest::RIPEMD256;
	Crypt::Digest::RIPEMD256::ripemd256_hex($_[0]);
}
sub ripemd256 {
	require Crypt::Digest::RIPEMD256;
	Crypt::Digest::RIPEMD256::ripemd256($_[0]);
}
sub ripemd256_base64 {
	require Crypt::Digest::RIPEMD256;
	Crypt::Digest::RIPEMD256::ripemd256_base64($_[0]);
}
sub ripemd320_hex {
	require Crypt::Digest::RIPEMD320;
	Crypt::Digest::RIPEMD320::ripemd320_hex($_[0]);
}
sub ripemd320 {
	require Crypt::Digest::RIPEMD320;
	Crypt::Digest::RIPEMD320::ripemd320($_[0]);
}
sub ripemd320_base64 {
	require Crypt::Digest::RIPEMD320;
	Crypt::Digest::RIPEMD320::ripemd320_base64($_[0]);
}

############################################################################
# Here are the encryption subroutines.
#  the format of ALL of these is:    function(password)
#  all salted formats choose 'random' salts, in one way or another.
#############################################################################
sub descrypt {
	require Crypt::UnixCrypt_XS;
	$salt = get_salt(2,2,\@i64);
	print "u$u-descrypt:", Crypt::UnixCrypt_XS::crypt($_[1], $salt), ":$u:0:$_[0]::\n";
}
sub bigcrypt {
	require Crypt::UnixCrypt_XS;
	if (length($_[0]) > 8) {
		$salt = get_salt(2,2,\@i64);
		my $pw = $_[0];
		while (length($pw)%8!= 0) { $pw .= "\0"; }
		my $lastlimb = Crypt::UnixCrypt_XS::crypt(substr($pw,0,8), $salt);
		print "u$u-DES_BigCrypt:", $lastlimb;
		$pw = substr($pw,8);
		while (length($pw)) {
			$lastlimb = Crypt::UnixCrypt_XS::crypt(substr($pw,0,8), substr($lastlimb,2,2));
			print substr($lastlimb, 2);
			$pw = substr($pw,8);
		}
		print ":$u:0:$_[0]::\n";
	} else {
		descrypt(@_);
	}
}
sub bsdicrypt {
	require Crypt::UnixCrypt_XS;
	my $block = "\0\0\0\0\0\0\0\0";
	my $rounds = 725;
	$salt = get_salt(4,4,\@i64);
	my $h = Crypt::UnixCrypt_XS::crypt_rounds(Crypt::UnixCrypt_XS::fold_password($_[1]),$rounds,Crypt::UnixCrypt_XS::base64_to_int24($salt),$block);
	print "u$u-BSDIcrypt:_", Crypt::UnixCrypt_XS::int24_to_base64($rounds), $salt, Crypt::UnixCrypt_XS::block_to_base64($h), ":$u:0:$_[0]::\n";
}
sub md5crypt {
	if (length($_[1]) > 15) { print STDERR "Warning, john can only handle 15 byte passwords for this format!\n"; }
	$salt = get_salt(8);
	$h = md5crypt_hash($_[1], $salt, "\$1\$");
	print "u$u-md5crypt:$h:$u:0:$_[0]::\n";
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
sub bcryptx {
	my $fixed_pass = bfx_fix_pass($_[1]);
	require Crypt::Eksblowfish::Bcrypt;
	$salt = get_salt(16,16,\@i64);
	my $hash = Crypt::Eksblowfish::Bcrypt::bcrypt_hash({key_nul => 1, cost => 5, salt => $salt, }, $fixed_pass);
	print "u$u-BCRYPT:\$2x\$05\$", Crypt::Eksblowfish::Bcrypt::en_base64($salt), Crypt::Eksblowfish::Bcrypt::en_base64($hash), ":$u:0:$_[0]::\n";
}
sub bcrypt {
	require Crypt::Eksblowfish::Bcrypt;
	$salt = get_salt(16,16,\@i64);
	my $hash = Crypt::Eksblowfish::Bcrypt::bcrypt_hash({key_nul => 1, cost => 5, salt => $salt, }, $_[1]);
	print "u$u-BCRYPT:\$2a\$05\$", Crypt::Eksblowfish::Bcrypt::en_base64($salt), Crypt::Eksblowfish::Bcrypt::en_base64($hash), ":$u:0:$_[0]::\n";
}
sub _bfegg_en_base64($) {
	my($bytes) = @_;
	my $digits = "";
	my $b64_digits = "./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	foreach my $word (reverse unpack("N*", $bytes)) {
		for(my $i = 6; $i--; $word >>= 6) {
			$digits .= substr($b64_digits, $word & 0x3f, 1);
		}
	}
	return $digits;
}
sub bfegg {
	require Crypt::Eksblowfish::Uklblowfish;
	if (length($_[1]) > 0) {
		my $cipher = Crypt::Eksblowfish::Uklblowfish->new($_[1]);
		my $h = $cipher->encrypt("\xde\xad\xd0\x61\x23\xf6\xb0\x95");
		print "u$u-BFegg:+", _bfegg_en_base64($h), ":$u:0:$_[0]::\n";
	}
}
sub raw_md5 {
	print "u$u-Raw-MD5:", md5_hex($_[1]), ":$u:0:$_[0]::\n";
}
sub raw_md5u {
	print "u$u-Raw-MD5-unicode:", md5_hex(encode("UTF-16LE",$_[0])), ":$u:0:$_[0]::\n";
}
sub raw_sha1 {
	print "u$u-Raw-SHA1:", sha1_hex($_[1]), ":$u:0:$_[0]::\n";
}
sub raw_sha1u {
	print "u$u-Raw-SHA1-unicode:", sha1_hex(encode("UTF-16LE",$_[0])), ":$u:0:$_[0]::\n";
}
sub raw_sha256 {
	print "u$u-Raw-SHA256:", sha256_hex($_[1]), ":$u:0:$_[0]::\n";
}
sub cisco4 {
	print "u$u-cisco4:\$cisco4\$", base64_wpa(sha256($_[1])), ":$u:0:$_[0]::\n";
}
sub raw_sha224 {
	print "u$u-Raw-SHA224:", sha224_hex($_[1]), ":$u:0:$_[0]::\n";
}
sub raw_sha384 {
	print "u$u-Raw-SHA384:", sha384_hex($_[1]), ":$u:0:$_[0]::\n";
}
sub raw_sha512 {
	print "u$u-Raw-SHA512:", sha512_hex($_[1]), ":$u:0:$_[0]::\n";
}
sub cisco8 {
	$salt = get_salt(14,14,\@i64);
	my $h = pp_pbkdf2($_[1],$salt,20000,"sha256",32,64);
	my $s = base64_wpa($h);
	print "u-cisco8:\$8\$$salt\$$s:$u:0:$_[0]::\n";
}
sub cisco9 {
	require Crypt::ScryptKDF;
	import Crypt::ScryptKDF qw(scrypt_raw);
	$salt = get_salt(14,14,\@i64);
	my $h = scrypt_raw($_[1],$salt,16384,1,1,32);
	my $s = base64_wpa($h);
	print "u-cisco9:\$9\$$salt\$$s:$u:0:$_[0]::\n";
}
sub dragonfly3_32 {
	$salt = get_salt(-8, -8);
	my $final = sha256($_[1]."\$3\$\0".$salt);
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
	$salt = get_salt(-8, -8);
	my $final = sha512($_[1]."\$4\$\0".$salt);
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
	$salt = get_salt(-8, -8);
	my $final = sha256($_[1]."\$3\$\0sha5".$salt);
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
	$salt = get_salt(-8, -8);
	my $final = sha512($_[1]."\$4\$\0/etc".$salt);
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
	$salt = get_salt(19,-19,\@userNames);
	print "$salt:", md4_hex(md4(encode("UTF-16LE",$_[0])).encode("UTF-16LE", lc($salt))),
			":$u:0:$_[0]:mscash (uname is salt):\n";
}

sub krb5_18 {
	# algorith gotten by working with kbr5-1.13 sources, and using lots of dump_stuff_msg()
	# calls to figure out what was happening. The constant being used here was found by
	# dump_stuff_msg() calls, and appears to be the end result that is used.
	$salt = get_salt(12,-64);
	my $pbk = pp_pbkdf2($_[0], $salt, 4096, "sha1",32,64);
	require Crypt::OpenSSL::AES;
	my $crypt = Crypt::OpenSSL::AES->new($pbk);
	# 6b65726265726f737b9b5b2b93132b93 == 'kerberos' and 8 other bytes
	my $output1 = $crypt->encrypt(pack("H*","6b65726265726f737b9b5b2b93132b93"));
	my $output2 = $crypt->encrypt($output1);
	print "u$u-krb5-18:\$krb18\$$salt\$".unpack("H*",$output1).unpack("H*",$output2).":$u:0:$_[0]::\n";
}

sub odf {
	my $iv; my $content;
	$salt = get_salt(16);
	$iv =  get_iv(8);
	$content = get_content(-1024, -4095);
	my $s = sha1($_[0]);
	my $key = pp_pbkdf2($s, $salt, 1024, "sha1", 16,64);
	require Crypt::OpenSSL::Blowfish::CFB64;
	my $crypt = Crypt::OpenSSL::Blowfish::CFB64->new($key, $iv);
	my $output = $crypt->decrypt($content);
	$s = sha1($output);

	print "u$u-odf:\$odf\$*0*0*1024*16*".unpack("H*",$s)."*8*".unpack("H*",$iv)."*16*".unpack("H*",$salt)."*0*".unpack("H*",$content).":$u:0:$_[0]::\n";
}
sub odf_1 {
	# odf cipher type 1 (AES instead of blowfish, and some sha256, pbkdf2 is still sha1, but 32 byte of output)
	my $iv; my $content;
	$salt = get_salt(16);
	$iv =  get_iv(16);
	$content = get_content(-1024, -4095);
	while (length($content)%16 != 0) { $content .= "\x0" } # must be even 16 byte padded.
	my $s = sha256($_[0]);
	my $key = pp_pbkdf2($s, $salt, 1024, "sha1", 32,64);
	require Crypt::OpenSSL::AES;
	require Crypt::CBC;
	# set -padding to 'none'. Otherwise a Crypt::CBC->decrypt() padding removal will bite us, and possibly strip off bytes.
	my $crypt = Crypt::CBC->new(-literal_key => 1, -key => $key, -iv => $iv, -cipher => "Crypt::OpenSSL::AES", -header => 'none', -padding => 'none');
	my $output = $crypt->decrypt($content);
	$s = sha256($output);
	print "u$u-odf:\$odf\$*1*1*1024*32*".unpack("H*",$s)."*16*".unpack("H*",$iv)."*16*".unpack("H*",$salt)."*0*".unpack("H*",$content).":$u:0:$_[0]::\n";
}
# the inverse of the DecryptUsingSymmetricKeyAlgorithm() in the JtR office format
sub _office_2k10_EncryptUsingSymmetricKeyAlgorithm {
	my ($key, $data, $len, $keysz) = @_;
	# we handle ALL padding.
	while (length($data)<$len) {$data.="\0";} $data = substr($data,0,$len);
	while (length($key)<$keysz) {$key.="\0";} $key = substr($key,0,$keysz);
	require Crypt::OpenSSL::AES;
	require Crypt::CBC;
	my $crypt = Crypt::CBC->new(-literal_key => 1, -keysize => $keysz, -key => $key, -iv => $salt, -cipher => "Crypt::OpenSSL::AES", -header => 'none', -padding => 'none');
	return $crypt->encrypt($data);
}
# same function as the GenerateAgileEncryptionKey[512]() in the JtR office format
sub _office_2k10_GenerateAgileEncryptionKey {
	# 2 const values for office 2010/2013
	my $encryptedVerifierHashInputBlockKey = pack("H*", "fea7d2763b4b9e79");
	my $encryptedVerifierHashValueBlockKey = pack("H*", "d7aa0f6d3061344e");
	my $p = encode("UTF-16LE", $_[0]);
	my $spincount = $_[1];
	my $hash_func = $_[2];	# should be sha1 or sha512
	no strict 'refs';
	my $h = &$hash_func($salt.$p);
	for (my $i = 0; $i < $spincount; $i += 1) { $h = &$hash_func(Uint32LERaw($i).$h); }
	$_[3] = &$hash_func($h.$encryptedVerifierHashInputBlockKey);
	$_[4] = &$hash_func($h.$encryptedVerifierHashValueBlockKey);
	use strict;
}
sub office_2010 {
	$salt = get_salt(16);
	my $randdata = get_iv(16);
	my $spincount = 100000;
	my $hash1; my $hash2;
	_office_2k10_GenerateAgileEncryptionKey($_[1], $spincount, \&sha1, $hash1, $hash2);
	my $encryptedVerifier = _office_2k10_EncryptUsingSymmetricKeyAlgorithm($hash1, $randdata, 16, 128/8);
	my $encryptedVerifierHash = _office_2k10_EncryptUsingSymmetricKeyAlgorithm($hash2, sha1($randdata), 32, 128/8);
	print "u$u-office10:\$office\$*2010*$spincount*128*16*".unpack("H*",$salt)."*".unpack("H*",$encryptedVerifier)."*".unpack("H*",$encryptedVerifierHash).":$u:0:$_[0]::\n";
}
sub office_2013 {
	$salt = get_salt(16);
	my $randdata = get_iv(16);
	my $spincount = 100000;
	my $hash1; my $hash2;
	_office_2k10_GenerateAgileEncryptionKey($_[1], $spincount, \&sha512, $hash1, $hash2);
	my $encryptedVerifier = _office_2k10_EncryptUsingSymmetricKeyAlgorithm($hash1, $randdata, 16, 256/8);
	my $encryptedVerifierHash = _office_2k10_EncryptUsingSymmetricKeyAlgorithm($hash2, sha512($randdata), 32, 256/8);
	print "u$u-office13:\$office\$*2013*$spincount*256*16*".unpack("H*",$salt)."*".unpack("H*",$encryptedVerifier)."*".unpack("H*",$encryptedVerifierHash).":$u:0:$_[0]::\n";
}
sub office_2007 {
	$salt = get_salt(16);
	my $randdata = get_iv(16);
	my $p = encode("UTF-16LE", $_[1]);
	my $h = sha1($salt.$p);
	for (my $i = 0; $i < 50000; $i += 1) {
		$h = sha1(Uint32LERaw($i).$h);
	}
	$h = sha1($h."\0\0\0\0");
	$h = substr(sha1($h^"6666666666666666666666666666666666666666666666666666666666666666"),0,16);
	require Crypt::OpenSSL::AES;
	my $crypt = Crypt::OpenSSL::AES->new($h);
	my $hash = $crypt->encrypt(substr(sha1(substr($crypt->decrypt($randdata),0,16)),0,16));
	print "u$u-office07:\$office\$*2007*20*128*16*".unpack("H*",$salt)."*".unpack("H*",$randdata)."*".unpack("H*",$hash)."00000000:$u:0:$_[0]::\n";
}
sub _tc_build_buffer {
	# build a special TC buffer.  448 bytes, 2 spots have CRC32.  Lots of null, etc.
	my $buf = 'TRUE'."\x00\x05\x07\x00". "\x00"x184 . randstr(64) . "\x00"x192;
	require String::CRC32;
	import String::CRC32 qw(crc32);
	my $crc1 = crc32(substr($buf, 192, 256));
	substr($buf, 8, 4) = Uint32BERaw($crc1);
	my $crc2 = crc32(substr($buf, 0, 188));
	substr($buf, 188, 4) = Uint32BERaw($crc2);
	return $buf;
}
# I looked high and low for a Perl implementation of AES-256-XTS and
# could not find one.  This may be the first implementation in Perl, ever.
sub _tc_aes_256_xts {
	# a dodgy, but working XTS implementation. (encryption). To do decryption
	# simply do $cipher1->decrypt($tmp) instead of encrypt. That is the only diff.
	my $key1 = substr($_[0],0,32); my $key2 = substr($_[0],32,32);
	my $d; my $c = $_[1]; # $c=cleartext MUST be a multiple of 16.
	my $num = length($c) / 16;
	my $t = $_[2];	# tweak (must be provided)
	require Crypt::OpenSSL::AES;
	my $cipher1 = new Crypt::OpenSSL::AES($key1);
	my $cipher2 = new Crypt::OpenSSL::AES($key2);
	$t = $cipher2->encrypt($t);
	for (my $cnt = 0; ; ) {
		my $tmp = substr($c, 16*$cnt, 16);
		$tmp ^= $t;
		$tmp = $cipher1->encrypt($tmp);
		$tmp ^= $t;
		$d .= $tmp;
		$cnt += 1;
		if ($cnt == $num) { return ($d); }
		# do the mulmod in GF(2)
		my $Cin=0; my $Cout; my $x;
		for ($x = 0; $x < 16; $x += 1) {
			$Cout = ((ord(substr($t,$x,1)) >> 7) & 1);
			substr($t,$x,1) =  chr(((ord(substr($t,$x,1)) << 1) + $Cin) & 0xFF);
			$Cin = $Cout;
		}
		if ($Cout != 0) {
			substr($t,0,1) = chr(ord(substr($t,0,1))^135);
		}
	}
}
sub tc_ripemd160 {
	$salt = get_salt(64);
	my $h = pp_pbkdf2($_[0], $salt, 2000, \&ripemd160, 64, 64);
	my $d = _tc_build_buffer();
	my $tweak = "\x00"x16;	#first block of file
	$h = _tc_aes_256_xts($h,$d,$tweak);
	print "tc_ripe160:truecrypt_RIPEMD_160\$".unpack("H*",$salt).unpack("H*",$h).":$u:0:$_[0]::\n";
}
sub tc_sha512 {
	$salt = get_salt(64);
	my $h = pp_pbkdf2($_[0], $salt, 1000, \&sha512, 64, 128);
	my $d = _tc_build_buffer();
	my $tweak = "\x00"x16;	#first block of file
	$h = _tc_aes_256_xts($h,$d,$tweak);
	print "tc_sha512:truecrypt_SHA_512\$".unpack("H*",$salt).unpack("H*",$h).":$u:0:$_[0]::\n";
}
sub tc_whirlpool {
	$salt = get_salt(64);
	my $h = pp_pbkdf2($_[0], $salt, 1000, \&whirlpool, 64, 64);	# note, 64 byte ipad/opad (oSSL is buggy?!?!)
	my $d = _tc_build_buffer();
	my $tweak = "\x00"x16;	#first block of file
	$h = _tc_aes_256_xts($h,$d,$tweak);
	print "tc_whirlpool:truecrypt_WHIRLPOOL\$".unpack("H*",$salt).unpack("H*",$h).":$u:0:$_[0]::\n";
}
sub pdf {
}
sub pkzip {
}
sub zip {
	# NOTE ,the zip contents are garbage, but we do not care.  We simply
	# run the hmac-sha1 over it and compare to the validator (in JtR), so
	# we simply have designed this to build hashes that are 'jtr' valid.
	my $mode; my $sl; my $kl; my $chksum; my $content; my $hexlen;
	if (defined $argmode) {$mode=$argmode;} else { $mode=int(rand(3))+1; }
	if ($mode==1) { $sl = 8; }
	elsif ($mode==2) { $sl = 12; }
	else { $mode = 3; $sl = 16; }
	$kl = $sl*2;
	$salt = get_salt($sl);
	$content = get_content(96,-4096);
	$h = pp_pbkdf2($_[0], $salt, 1000, "sha1", 2*$kl+2, 64);
	$chksum = substr($h,2*$kl,2);
	my $bin = _hmac_shas(\&sha1, 64, substr($h,$kl,$kl), $content);
	$hexlen = sprintf("%x", length($content));
	print "u$u-zip:\$zip2\$*0*$mode*0*".unpack("H*",$salt)."*".unpack("H*",$chksum)."*$hexlen*".unpack("H*",$content)."*".substr(unpack("H*",$bin),0,20)."*\$/zip2\$:$u:0:$_[0]::\n";
}
sub rar5 {
}
sub _gen_key_rar4 {
	# return final output generated by rar4.
	my ($pw, $salt, $raw_input, $iv, $raw, $i) = ($_[0], $_[1], $_[2], "", "", 0);
	for (my $k = 0; $k < length($_[0]); $k += 1) { $raw .= substr($_[0], $k, 1); $raw .= "\0"; }
	$raw .= $salt;
	my $ctx = Digest::SHA->new('SHA1');
	while ($i < 0x40000) {
		# this could probably be done faster by simply modifying bytes,
		# of the $i in BE format, but it is not too bad, and this 'works'
		my $work = $raw;
		$work .= chr($i & 0xFF);
		$work .= chr( ($i>>8) & 0xFF);
		$work .= chr( ($i>>16) & 0xFF);
		$ctx->add($work);
		if ( ($i&0x3fff) == 0) { # first and every 16384 loops, grab 1 byte of IV from that digest
			$h = $ctx->clone->digest; # we MUST use clone() to not modify the ctx
			$iv .= substr($h, 19,1);
		}
		$i += 1;
	}
	my $key = substr($ctx->digest, 0, 16); # key is first 16 bytes (swapped)
	$key = pack("V*", unpack("N*",$key));  # swap the 4 uint32_t values.

	require Crypt::OpenSSL::AES;
	require Crypt::CBC;
	my $crypt = Crypt::CBC->new(-literal_key => 1, -key => $key, -keysize => 16, -iv => $iv, -cipher => 'Crypt::OpenSSL::AES', -header => 'none');
	while (length($raw_input) % 16 != 0) { $raw_input .= "\x00"; }
	return $crypt->encrypt($raw_input);
}
sub rar {
	# for rar version 4 archives (both -p (compressed or stored) and -hp)
	my $content; my $contentlen; my $contentpacklen; my $crc; my $type = "33";
	$salt = get_salt(8);
	my $rnd = int(rand(10));
	my @ar;
	if (defined $argmode) { $rnd = $argmode; }
	# first 7 are compressed files. 8th is stored file.  9-10 are type -hp
	# using command line arg: '-content=7' would force only doing stored file -content=2 would force file 2,
	# and -content=xxx or anything other than 0 to 7 would force -hp mode.
	if ($rnd == 0) {
		# the format of the string is crc~len~rarpackbuffer  the rarpackbuffer is NOT encrypted.  We put that into an array, and later pull it out.
		@ar = split("~", "b54415c5~46~0bc548bdd40d37b8578f5b39a3c022c11115d2ce1fb3d8f9c548bbddb5dfb7a56c475063d6eef86f2033f6fe7e20a4a24590e9f044759c4f0761dbe4");
	} elsif ($rnd == 1) {
		@ar = split("~", "e90c7d49~28~0c0108be90bfb0a204c9dce07778e0700dfdbffeb056af47a8d305370ec39e95c87c7d");
	} elsif ($rnd == 2) {
		@ar = split("~", "d3ec3a5e~54~09414c8fe50fbb85423de8e4694b222827da16cdfef463c52e29ef6ad1608b42e72884766c17f8527cefabb68c8f1daed4c6079ea715387c80");
	} elsif ($rnd == 3) {
		@ar = split("~", "d85f3c19~142~0951148d3e11372f0a41e03270586689a203a24de9307ec104508af7f842668c4905491270ebabbbae53775456cf7b8795496201243e397cb8c6c0f78cb235303dd513853ffad6afc9bf5806e9cd6e0e3db4f82fc72b4ff10488beb8cdc2b6a545159260e47e891ec8");
	} elsif ($rnd == 4) {
		@ar = split("~", "b1e45656~82~090010cbe4cee6615e497b83a208d0a308ca5abc48fc2404fa204dfdbbd80e00e09d6f6a8c9c4fa2880ef8bb86bc5ba60fcb676a398a99f44ccaefdb4c498775f420be69095f25a09589b1aaf1");
	} elsif ($rnd == 5) {
		@ar = split("~", "965f1453~47~09414c93e4cef985416f472549220827da3ba6fed8ad28e29ef6ad170ad53a69051e9b06f439ef6da5df8670181f7eb2481650");
	} elsif ($rnd == 6) {
		@ar = split("~", "51699729~27~100108be8cb7614409939cf2298079cbedfdbfec5e33d2b148c388be230259f57ddbe8");
	} elsif ($rnd == 7) {
		$type = "30";
		$content = randstr(int(rand(32))+int(rand(32))+16);
		$contentlen=length($content);
		require String::CRC32;
		import String::CRC32 qw(crc32);
		my $crcs = sprintf("%08x", crc32($content));  # note, rar_fmt/rar2john F's up the byte order!! so we have to match what it expects.
		$crc = substr($crcs,6).substr($crcs,4,2).substr($crcs,2,2).substr($crcs,0,2);
		@ar = ($crc, $contentlen, unpack("H*", $content));
	} else {
		# do -hp type here.
		my $output = _gen_key_rar4($_[0], $salt, "\xc4\x3d\x7b\x00\x40\x07\x00");
		print "u$u-rarhp:\$RAR3\$*0*".unpack("H*",$salt)."*".unpack("H*",substr($output,0,16)).":$u:0:$_[0]::\n";
		return;
	}
	# common final processing for -p rar (-hp returns before getting here).
	$crc = $ar[0];
	$contentlen = $ar[1];
	$content = pack("H*", $ar[2]);
	$contentpacklen = length($content) + 16-length($content)%16;
	my $output = _gen_key_rar4($_[0], $salt, $content);
	print "u$u-rar:\$RAR3\$*1*".unpack("H*",$salt)."*$crc*$contentpacklen*$contentlen*1*".unpack("H*",substr($output,0,$contentpacklen))."*$type:$u:0:$_[0]::\n";
}
sub ecryptfs {
	my $rndsalt=0;
	if ($u % 5 == 0) { # every 5th hash gets a random salt.
		$rndsalt = 1;
		$salt = get_salt(8);
	} else { $salt = pack("H*", "0011223344556677"); }
	$h = sha512($salt.$_[0]);
	for (my $i = 0; $i < 65536; $i += 1) {
		$h = sha512($h);
	}
	if ($rndsalt == 0) { print "u$u-ecryptfs:".'$ecryptfs$0$'.substr(unpack("H*",$h),0,16).":$u:0:$_[0]::\n"; }
	else { print "u$u-ecryptfs:".'$ecryptfs$0$1$'.unpack("H*",$salt).'$'.substr(unpack("H*",$h),0,16).":$u:0:$_[0]::\n"; }
}
sub ssh {
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
sub cloudkeychain {
}
sub agilekeychain {
}
sub haval_256 {
	print "u$u-haval256_3:".haval256_hex($_[0]).":$u:0:$_[0]::\n";
}
sub mozilla {
	$salt = get_salt(20);
	# use -iv=xxx to pass in global_salt by user.
	my $gsalt = get_iv(20);

	my $h2 = sha1(sha1($gsalt.$_[0]).$salt);
	my $h4 = Digest::SHA::hmac_sha1($salt, $h2);
	my $h3 = Digest::SHA::hmac_sha1($salt.$salt, $h2) . Digest::SHA::hmac_sha1($h4.$salt, $h2);

	require Crypt::DES_EDE3;
	require Crypt::CBC;
	my $chk_key = "password-check";
	my $cbc = Crypt::CBC->new(	-key => substr($h3,0,24),
								-cipher => "DES_EDE3",
								-iv => substr($h3,32,8),
								-literal_key => 1,
								-header => "none");
	my $enc = $cbc->encrypt($chk_key);
	print "u$u-mozilla:\$mozilla\$*3*20*1*".unpack("H*",$salt)."*11*2a864886f70d010c050103*16*".unpack("H*",$enc)."*20*".unpack("H*",$gsalt),":$u:0:$_[0]::\n";
}
sub keychain {
	require Crypt::DES_EDE3;
	require Crypt::CBC;
	my $iv; my $data; my $key; my $h;
	$salt = get_salt(20);
	$iv = get_iv(8);

#	With this $salt and $iv, "password" generates proper (same) hash as found in keychain_fmt_plug.c
#	$salt = "\x10\xf7\x44\x5c\x85\x10\xfa\x40\xd9\xef\x6b\x4e\x0f\x8c\x77\x2a\x9d\x37\xe4\x49";
#	$iv = "\xf3\xd1\x9b\x2a\x45\xcd\xcc\xcb";

	# NOTE, this data came from decryption of the sample hash in jtr's keychain_fmt_plug.c.
	# So we will just keep using it. We know (think) it is valid.
	$data = "\x85\x6e\xef\x45\x56\xb5\x85\x8c\x15\x47\x7d\xb1\x7b\x95\xc5\xcb\x01\x5d" .
			"\x51\x0b\x9f\x37\x10\xce\x9d\x44\xf6\x5d\x8b\x6c\xbd\x5d\xa0\x66\xee\x9d" .
			"\xd0\x85\xc2\x0d\xfa\x53\x78\x25\x04\x04\x04\x04";
	$key = pp_pbkdf2($_[1], $salt, 1000,"sha1",24, 64);
	my $cbc = Crypt::CBC->new(	-key => $key,
								-cipher => "DES_EDE3",
								-iv => $iv,
								-literal_key => 1,
								-header => "none");
	$h = $cbc->encrypt($data);
	# $h is 8 bytes longer than in the JtR sample hash. BUT the first 48 bytes ARE the same.  We just trim them.
	print "u$u-keychain:\$keychain\$*".unpack("H*",$salt)."*".unpack("H*",$iv)."*".substr(unpack("H*",$h),0,48*2),":$u:0:$_[0]::\n";
}
sub wpapsk {
	require Digest::HMAC_MD5;
	# max ssid is 32 bytes
	# min password is 8 bytes.  Max is 63 bytes
	if (length($_[1]) < 8 || length($_[1]) > 63) { return; }

	my $ssid; my $nonce1; my $nonce2; my $mac1; my $mac2; my $eapol; my $eapolsz;
	my $keyver; my $keymic; my $data; my $prf; my $inpdat; my $i;
	# load ssid
	$ssid = get_salt(32,-32,\@userNames);

	# Compute the pbkdf2-sha1(4096) for 32 bytes
	my $wpaH = pp_pbkdf2($_[1],$ssid,4096,"sha1",32, 64);

	# load some other 'random' values, for the other data.
	$nonce1 = randstr(32,\@chrRawData);
	$nonce2 = randstr(32,\@chrRawData);
	$mac1 = randstr(6,\@chrRawData);
	$mac2 = randstr(6,\@chrRawData);
	$eapolsz = 92 + rand (32);
	$eapol = randstr($eapolsz,\@chrRawData);
	$keyver = (rand(32) / 6) + 1; # more chance of a keyver1
	if ($keyver > 2) { $keyver = 2; }
	if ($keyver < 2) { $keyver = 1; }

	# ok, keymic now needs to be computed.
	# for keyver=1 we use md5, for keyver=2 we use sha1
	# (see wpapsk.h wpapsk_postprocess() for information)
	Load_MinMax($data, $mac1, $mac2);
	Load_MinMax($data, $nonce1, $nonce2);

	# in JtR prf_512($wpaH, $data, $prf), but we simply do it inline.
	$data = "Pairwise key expansion" . chr(0) . $data . chr(0);
	$prf = Digest::SHA::hmac_sha1($data, $wpaH);

	if ($keyver == 1) {
		$prf = substr($prf, 0, 16);
		$keymic = Digest::HMAC_MD5::hmac_md5($eapol, $prf);
	} else {
		$prf = substr($prf, 0, 16);
		$keymic = Digest::SHA::hmac_sha1($eapol, $prf);
		$keymic = substr($keymic, 0, 16);
	}
	# ok, now we have the keymic.

	############################################################
	# Now build the data for JtR's hccap_t structure.
	############################################################
	$inpdat = $mac1 . $mac2 . $nonce1 . $nonce2 . $eapol;      # first 4 parts easy.  Simply append them AND data we have for eapol
	for ($i = $eapolsz; $i < 256; ++$i) { $inpdat .= chr(0); } # pad eapol data to 256 bytes.
	$inpdat .= chr($eapolsz).chr(0).chr(0).chr(0);             # put eapolsz, and keyver into a LE 4 byte integers
	$inpdat .= chr($keyver).chr(0).chr(0).chr(0);
	$inpdat .= $keymic;                                        # now append the keymic

	# drop out the JtR hash.  NOTE, base64_wpa() is specialzed for this hash.
	print "u$u-wpapsk:\$WPAPSK\$$ssid#",base64_wpa($inpdat),":$u:0:$_[0]::\n";
}

# used by wpapsk, to load the MAC1/MAC2 and NONCE1/NONCE2. It loads the smallest of
# the two, first, then loads the larger one.  All data is appended to the first param
sub Load_MinMax {
	my ($v1, $v2) = ($_[1], $_[2]);
	my $c1; my $c2; my $off;
	for ($off = 0; $off < length($v1); ++$off) {
		$c1 = substr($v1, $off, 1);
		$c2 = substr($v2, $off, 1);
		if (ord($c1) > ord($c2)) {
			$_[0] .= $v2.$v1;
			return;
		}
		if (ord($c2) > ord($c1)) {
			$_[0] .= $v1.$v2;
			return;
		}
	}
	# same??
	$_[0] .= $v1.$v2;
}
sub mscash2 {
	# max username (salt) length is supposed to be 19 characters (in John)
	# max password length is 27 characters (in John)
	# the algorithm lowercases the salt
	my $iter = 10240;
	my $user = get_salt(22,-27,\@userNames);
	$salt = encode("UTF-16LE", lc($user));
	my $key = md4(md4(encode("UTF-16LE",$_[0])).$salt);
	print "$user:", '$DCC2$', "$iter#$user#", pp_pbkdf2_hex($key,$salt,$iter,"sha1",16,64), ":$u:0:$_[0]:mscash2:\n";
}
sub lm {
	my $p = $_[0];
	if (length($p)>14) { $p = substr($p,0,14);}
	print "u$u-LM:$u:", unpack("H*",LANMan($p)), ":$u:0:", uc $p, "::\n";
}
sub nt { #$utf8mode=0, $utf8_pass;
	print "u$u-NT:\$NT\$", unpack("H*",md4(encode("UTF-16LE", $_[0]))), ":$u:0:$_[0]::\n";
}
sub pwdump {
	my $lm = unpack("H*",LANMan(length($_[0]) <= 14 ? $_[0] : ""));
	my $nt = unpack("H*",md4(encode("UTF-16LE", $_[0])));
	print "u$u-pwdump:$u:$lm:$nt:$_[0]::\n";
}
sub raw_md4 {
	print "u$u-Raw-MD4:", md4_hex($_[1]), ":$u:0:$_[0]::\n";
}
sub mediawiki {
	$salt = get_salt(8);
	print "u$u-mediawiki:\$B\$" . $salt . "\$" . md5_hex($salt . "-" . md5_hex($_[1])) . ":$u:0:$_[0]::\n";
}
sub osc {
	$salt = get_salt(2);
	print "u$u-osc:\$OSC\$" . unpack("H*",$salt) . "\$" . md5_hex($salt. $_[1]) . ":$u:0:$_[0]::\n";
}
sub formspring {
	$salt = get_salt(2,2,\@chrAsciiNum);
	print "u$u-formspring:" . sha256_hex($salt. $_[1]) . "\$$salt:$u:0:$_[0]::\n";
}
sub phpass {
	$salt = get_salt(8);
	my $h = PHPass_hash($_[1], 11, $salt);
	print "u$u-PHPass:\$P\$", to_phpbyte(11), $salt,  substr(base64i($h),0,22), ":$u:0:$_[0]::\n";
}
sub po {
	if (defined $argsalt) {
		$salt = md5_hex($argsalt);
	} else {
		$salt=randstr(32, \@chrHexLo);
	}
	print "u$u-PO:", md5_hex($salt . "Y" . $_[1] . "\xF7" . $salt), "$salt:$u:0:$_[0]::\n";
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
sub md5crypt_hash {
	my $b, my $c, my $tmp;
	my $type = $_[2];
	$salt = $_[1];
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
sub md5crypt_a {
	if (length($_[1]) > 15) { print STDERR "Warning, john can only handle 15 byte passwords for this format!\n"; }
	$salt = get_salt(8);
	$h = md5crypt_hash($_[1], $salt, "\$apr1\$");
	print "u$u-md5crypt_a:$h:$u:0:$_[0]::\n";
}
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
	$salt = $_[1];
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
	$salt = get_salt(16);
	$salt = "\$md5\$rounds=904\$".$salt;
	my $c = _sunmd5_hash($_[1], $salt);
	my $h = _md5_crypt_to_64($c);
	print "u$u-sunmd5:$salt\$$h:$u:0:$_[0]::\n";
}
sub wowsrp {
	require Math::BigInt;
	$salt = get_salt(16);
	my $usr = uc randusername();

	my $h = sha1($salt, sha1($usr,":",uc $_[1]));

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
sub _hmacmd5 {
	my ($key, $data) = @_;
	my $ipad; my $opad;
	if (length($key) > 64) {
	    $key = md5($key);
	}
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
sub hmac_md5 {
	$salt = get_salt(32);
	my $bin = _hmacmd5($_[1], $salt);
	print "u$u-hmacMD5:$salt#", unpack("H*",$bin), ":$u:0:$_[0]::\n";
}
sub _hmac_shas {
	my ($func, $pad_sz, $key, $data) = @_;
	my $ipad; my $opad;
	if (length($key) > $pad_sz) {
	    $key = $func->($key);
	}
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
	$salt = get_salt(24);
	my $bin = _hmac_shas(\&sha1, 64, $_[1], $salt);
	print "u$u-hmacSHA1:$salt#", unpack("H*",$bin), ":$u:0:$_[0]::\n";
}
sub hmac_sha224 {
	$salt = get_salt(32);
	my $bin = _hmac_shas(\&sha224, 64, $_[1], $salt);
	print "u$u-hmacSHA224:$salt#", unpack("H*",$bin), ":$u:0:$_[0]::\n";
}
sub hmac_sha256 {
	$salt = get_salt(32);
	my $bin = _hmac_shas(\&sha256, 64, $_[1], $salt);
	print "u$u-hmacSHA256:$salt#", unpack("H*",$bin), ":$u:0:$_[0]::\n";
}
sub hmac_sha384 {
	$salt = get_salt(32);
	my $bin = _hmac_shas(\&sha384, 128, $_[1], $salt);
	print "u$u-hmacSHA384:$salt#", unpack("H*",$bin), ":$u:0:$_[0]::\n";
}
sub hmac_sha512 {
	$salt = get_salt(32);
	my $bin = _hmac_shas(\&sha512, 128, $_[1], $salt);
	print "u$u-hmacSHA512:$salt#", unpack("H*",$bin), ":$u:0:$_[0]::\n";
}
sub rakp {
	my $user = randstr(rand(63) + 1);
	$salt = randstr(56,\@chrRawData) . $user;
	my $bin = _hmac_shas(\&sha1, 64, $_[1], $salt);
	print "$user:", unpack("H*",$salt), "\$", unpack("H*",$bin), ":$u:0:$_[0]::\n";
}
sub _sha_crypts {
	my $a; my $b, my $c, my $tmp; my $i; my $ds; my $dp; my $p; my $s;
	my ($func, $bits, $key, $salt) = @_;
	my $bytes = $bits/8;
	my $loops = $arg_loops != -1 ? $arg_loops : 5000;

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
	# now we do 5000 iterations of SHA2 (256 or 512)
	for ($i = 0; $i < $loops; ++$i) {
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
	$salt = get_salt(16);
	my $bin = _sha_crypts(\&sha256, 256, $_[1], $salt);
	if ($arg_loops != -1) {
	print "u$u-sha256crypt:\$5\$rounds=${arg_loops}\$$salt\$$bin:$u:0:$_[0]::\n";
	} else {
	print "u$u-sha256crypt:\$5\$$salt\$$bin:$u:0:$_[0]::\n";
	}
}
sub sha512crypt {
	$salt = get_salt(16);
	my $bin = _sha_crypts(\&sha512, 512, $_[1], $salt);
	if ($arg_loops != -1) {
	print "u$u-sha512crypt:\$6\$rounds=${arg_loops}\$$salt\$$bin:$u:0:$_[0]::\n";
	} else {
	print "u$u-sha512crypt:\$6\$$salt\$$bin:$u:0:$_[0]::\n";
	}
}
sub xsha512 {
# simple 4 byte salted crypt.  No separator char, just raw hash. Also 'may' have $LION$.  We alternate, and every other
# hash get $LION$ (all even ones)
	$salt = get_salt(4);
	print "u$u-XSHA512:";
	if ($u&1) { print ("\$LION\$"); }
	print "" . unpack("H*", $salt) . sha512_hex($salt . $_[1]) . ":$u:0:$_[0]::\n";
}
sub krb5pa_md5 {
	require Crypt::RC4;
	import Crypt::RC4 qw(RC4);
	my $password = $_[1];
	my $datestring = sprintf('20%02u%02u%02u%02u%02u%02uZ', rand(100), rand(12)+1, rand(31)+1, rand(24), rand(60), rand(60));
	my $timestamp = randstr(14,\@chrRawData) . $datestring . randstr(7,\@chrRawData);
	my $K = md4(encode("UTF-16LE", $password));
	my $K1 = _hmacmd5($K, pack('N', 0x01000000));
	my $K2 = _hmacmd5($K1, $timestamp);
	my $K3 = _hmacmd5($K1, $K2);
	my $encrypted = RC4($K3, $timestamp);
	printf("%s:\$krb5pa_md5\$\$\$%s\$%s:::%s:%s\n", "u$u-krb5pa_md5", unpack("H*",$K2), unpack("H*",$encrypted), $_[1], $datestring);
}
sub ipb2 {
	$salt = get_salt(5);
	print "u$u-IPB2:\$IPB2\$", unpack("H*",$salt), "\$", md5_hex(md5_hex($salt), md5_hex($_[1])), ":$u:0:$_[0]::\n";

}
sub phps {
	$salt = get_salt(3);
	print "u$u-PHPS:\$PHPS\$", unpack("H*",$salt), "\$", md5_hex(md5_hex($_[1]), $salt), ":$u:0:$_[0]::\n";
}
sub md4p {
	$salt = get_salt(8);
	print "u$u-MD4p:\$MD4p\$$salt\$", md4_hex($salt, $_[1]), ":$u:0:$_[0]::\n";;
}
sub md4s {
	$salt = get_salt(8);
	print "u$u-MD4s:\$MD4s\$$salt\$", md4_hex($_[1], $salt), ":$u:0:$_[0]::\n";;
}
sub sha1p {
	$salt = get_salt(8);
	print "u$u-SHA1p:\$SHA1p\$$salt\$", sha1_hex($salt, $_[1]), ":$u:0:$_[0]::\n";;
}
sub sha1s {
	$salt = get_salt(8);
	print "u$u-SHA1s:\$SHA1s\$$salt\$", sha1_hex($_[1], $salt), ":$u:0:$_[0]::\n";;
}
sub mysql_sha1 {
	print "u$u-mysql_sha1:*", sha1_hex(sha1($_[1])), ":$u:0:$_[0]::\n";
}
sub mysql{
	my $nr=0x50305735;
	my $nr2=0x12345671;
	my $add=7;
	for (my $i = 0; $i < length($_[1]); ++$i) {
		my $ch = substr($_[1], $i, 1);
		if ( !($ch eq ' ' || $ch eq '\t') ) {
			my $charNum = ord($ch);
			# since perl is big num, we need to force some 32 bit truncation
			# at certain 'points' in the algorithm, by doing &= 0xffffffff
			$nr ^= ((($nr & 63)+$add)*$charNum) + (($nr << 8)&0xffffffff);
			$nr2 += ( (($nr2 << 8)&0xffffffff) ^ $nr);
			$add += $charNum;
		}
	}
	printf("u%d-mysql:%08x%08x:%d:0:%s::\n", $u, ($nr & 0x7fffffff), ($nr2 & 0x7fffffff), $u, $_[0]);
}
sub pixmd5 {
	my $pass = $_[1];
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
	print "u$u-pixmd5:$h:$u:0:", $_[0], "::\n";
}
sub mssql12 {
	$salt = get_salt(4);
	print "u$u-mssql12:0x0200", uc unpack("H*",$salt), uc sha512_hex(encode("UTF-16LE", $_[0]).$salt), ":$u:0:$_[0]::\n";
}
sub mssql05 {
	$salt = get_salt(4);
	print "u$u-mssql05:0x0100", uc unpack("H*",$salt), uc sha1_hex(encode("UTF-16LE", $_[0]).$salt), ":$u:0:$_[0]::\n";
}
sub mssql {
	$salt = get_salt(4);
	my $t = uc $_[1];
	if (length($_[1]) == length($t)) {
		print "u$u-mssql:0x0100", uc unpack("H*",$salt), uc sha1_hex(encode("UTF-16LE", $_[0]).$salt) . uc sha1_hex(encode("UTF-16LE", $t).$salt), ":$u:0:" . $t . ":" . $_[0] . ":\n";
	}
}
sub mssql_no_upcase_change {
	$salt = get_salt(4);
	# converts $c into utf8, from $enc code page, and 'sets' the 'flag' in perl that $c IS a utf8 char.
	# since we are NOT doing case changes in this function, it is ASSSUMED that we have been given a properly upcased dictionary
	if (!defined $arg_hidden_cp) { print STDERR "ERROR, for this format, you MUST use -hiddencp=CP to set the proper code page conversion\n"; exit(1); }
	my $PASS = Encode::decode($arg_hidden_cp, $_[0]);
	print "u$u-mssql:0x0100", uc unpack("H*",$salt), uc sha1_hex(encode("UTF-16LE", $PASS).$salt) . uc sha1_hex(encode("UTF-16LE", $PASS).$salt), ":$u:0:" . $_[0] . ":" . $_[0] . ":\n";
}

sub nsldap {
	$h = sha1($_[1]);
	#print "u$u-nsldap:{SHA}", ns_base64(6,1), ":$u:0:$_[0]::\n";
	print "u$u-nsldap:{SHA}", base64($h), ":$u:0:$_[0]::\n";
}
sub nsldaps {
	$salt = get_salt(8);
	$h = sha1($_[1],$salt);
	$h .= $salt;
	#print "u$u-nsldap:{SSHA}", ns_base64(9,2), ":$u:0:$_[0]::\n";
	print "u$u-nsldap:{SSHA}", base64($h), ":$u:0:$_[0]::\n";
}
sub openssha {
	$salt = get_salt(4);
	$h = sha1($_[1],$salt);
	$h .= $salt;
	#print "u$u-openssha:{SSHA}", ns_base64(7,0), ":$u:0:$_[0]::\n";
	print "u$u-openssha:{SSHA}", base64($h), ":$u:0:$_[0]::\n";
}
sub salted_sha1 {
	$salt = get_salt(-16, -128);
	$h = sha1($_[1],$salt);
	$h .= $salt;
	print "u$u-openssha:{SSHA}", base64($h), ":$u:0:$_[0]::\n";
}
sub ns {
	$salt = get_salt(7, -7, \@chrHexLo);
	$h = md5($salt, ":Administration Tools:", $_[1]);
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
	$salt = get_salt(4);
	print "u$u-xsha:", uc unpack("H*",$salt), uc sha1_hex($salt, $_[1]), ":$u:0:$_[0]::\n";
}
sub oracle {
	require Crypt::CBC;
	# snagged perl source from http://users.aber.ac.uk/auj/freestuff/orapass.pl.txt
	my $username = get_salt(30, -30, \@userNames);
	my $pass = $_[1];
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
	print "$username:", uc(unpack('H*', $hash)), ":$u:0:$_[0]:oracle_des_hash:\n";
}
sub oracle_no_upcase_change {
	require Crypt::CBC;
	# snagged perl source from http://users.aber.ac.uk/auj/freestuff/orapass.pl.txt
	my $username = get_salt(30, -30, \@userNames);
	# converts $c into utf8, from $enc code page, and 'sets' the 'flag' in perl that $c IS a utf8 char.
	# since we are NOT doing case changes in this function, it is ASSSUMED that we have been given a properly upcased dictionary
	if (!defined $arg_hidden_cp) { print STDERR "ERROR, for this format, you MUST use -hiddencp=CP to set the proper code page conversion\n"; exit(1); }

	my $pass = $username . Encode::decode($arg_hidden_cp, $_[0]);

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
	$salt=get_salt(10);
	print "u$u-oracle11:", uc sha1_hex($_[1], $salt), uc unpack("H*",$salt), ":$u:0:$_[0]::\n";
}
sub hdaa {
	# same as dynamic_21
	#  	{"$response$679066476e67b5c7c4e88f04be567f8b$user$myrealm$GET$/$8c12bd8f728afe56d45a0ce846b70e5a$00000001$4b61913cec32e2c9$auth", "nocode"},
	my $user = randusername(20);
	my $realm = randusername(10);
	my $url = randstr(rand(64)+1);
	my $nonce = randstr(rand(32)+1, \@chrHexLo);
	my $clientNonce = randstr(rand(32)+1, \@chrHexLo);
	my $h1 = md5_hex($user, ":".$realm.":", $_[1]);
	my $h2 = md5_hex("GET:/$url");
	my $resp = md5_hex($h1, ":", $nonce, ":00000001:", $clientNonce, ":auth:", $h2);
	print "u$u-HDAA:\$response\$$resp\$$user\$$realm\$GET\$/$url\$$nonce\$00000001\$$clientNonce\$auth:$u:0:$_[0]::\n";
}
sub setup_des_key {
	# ported from the ntlmv1_mschap2_fmt_plug.c by magnum. Changed to
	# use (& 254) by JimF so that all parity bits are 0. It did work
	# with parity bits being mixed 0 and 1, but when all bits are set
	# to 0, we can see that the function is correct.
	my @key_56 = split(//, shift);
	my $key = "";
	$key  = chr(  ord($key_56[0])                                 & 254);
	$key .= chr(((ord($key_56[0]) << 7) | (ord($key_56[1]) >> 1)) & 254);
	$key .= chr(((ord($key_56[1]) << 6) | (ord($key_56[2]) >> 2)) & 254);
	$key .= chr(((ord($key_56[2]) << 5) | (ord($key_56[3]) >> 3)) & 254);
	$key .= chr(((ord($key_56[3]) << 4) | (ord($key_56[4]) >> 4)) & 254);
	$key .= chr(((ord($key_56[4]) << 3) | (ord($key_56[5]) >> 5)) & 254);
	$key .= chr(((ord($key_56[5]) << 2) | (ord($key_56[6]) >> 6)) & 254);
	$key .= chr( (ord($key_56[6]) << 1)                           & 254);
	return $key;
}
# This produces only NETNTLM ESS hashes, in L0phtcrack format
sub netntlm_ess {
	require Crypt::ECB;
	import Crypt::ECB qw(encrypt PADDING_AUTO PADDING_NONE);
	my $password = $_[1];
	my $domain = randstr(rand(15)+1);
	my $nthash = md4(encode("UTF-16LE", $password));
	$nthash .= "\x00"x5;
	my $s_challenge = randstr(8,\@chrRawData);
	my $c_challenge = randstr(8,\@chrRawData);
	my $challenge = substr(md5($s_challenge.$c_challenge), 0, 8);
	my $ntresp = Crypt::ECB::encrypt(setup_des_key(substr($nthash, 0, 7)), 'DES', $challenge, PADDING_NONE());
	$ntresp .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 7, 7)), 'DES', $challenge, PADDING_NONE());
	$ntresp .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 14, 7)), 'DES', $challenge, PADDING_NONE());
	my $type = "ntlm ESS";
	my $lmresp = $c_challenge . "\0"x16;
	printf("%s\\%s:::%s:%s:%s::%s:%s\n", $domain, "u$u-netntlm", unpack("H*",$lmresp), unpack("H*",$ntresp), unpack("H*",$s_challenge), $_[0], $type);
}
# Alias for l0phtcrack
sub netntlm {
	l0phtcrack(@_);
}
# This produces NETHALFLM, NETLM and non-ESS NETNTLM hashes in L0pthcrack format
sub l0phtcrack {
	require Crypt::ECB;
	import Crypt::ECB qw(encrypt PADDING_AUTO PADDING_NONE);
	my $password = $_[1];
	my $domain = randstr(rand(15)+1);
	my $nthash = md4(encode("UTF-16LE", $password));
	$nthash .= "\x00"x5;
	my $lmhash; my $lmresp;
	my $challenge = randstr(8,\@chrRawData);
	my $ntresp = Crypt::ECB::encrypt(setup_des_key(substr($nthash, 0, 7)), 'DES', $challenge, PADDING_NONE());
	$ntresp .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 7, 7)), 'DES', $challenge, PADDING_NONE());
	$ntresp .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 14, 7)), 'DES', $challenge, PADDING_NONE());
	my $type;
	if (length($password) > 14) {
		$type = "ntlm only";
		$lmresp = $ntresp;
	} else {
		$type = "lm and ntlm";
		$lmhash = LANMan($password);
		$lmhash .= "\x00"x5;
		$lmresp = Crypt::ECB::encrypt(setup_des_key(substr($lmhash, 0, 7)), 'DES', $challenge, PADDING_NONE());
		$lmresp .= Crypt::ECB::encrypt(setup_des_key(substr($lmhash, 7, 7)), 'DES', $challenge, PADDING_NONE());
		$lmresp .= Crypt::ECB::encrypt(setup_des_key(substr($lmhash, 14, 7)), 'DES', $challenge, PADDING_NONE());
	}
	printf("%s\\%s:::%s:%s:%s::%s:%s\n", $domain, "u$u-netntlm", unpack("H*",$lmresp), unpack("H*",$ntresp), unpack("H*",$challenge), $_[0], $type);
}
sub netlmv2 {
	my $pwd = $_[1];
	my $nthash = md4(encode("UTF-16LE", $pwd));
	my $domain = randstr(rand(15)+1);
	my $user = randusername(20);
	my $identity = Encode::encode("UTF-16LE", uc($user).$domain);
	my $s_challenge = randstr(8,\@chrRawData);
	my $c_challenge = randstr(8,\@chrRawData);
	my $lmresponse = _hmacmd5(_hmacmd5($nthash, $identity), $s_challenge.$c_challenge);
	printf("%s\\%s:::%s:%s:%s::%s:netlmv2\n", $domain, $user, unpack("H*",$s_challenge), unpack("H*",$lmresponse), unpack("H*",$c_challenge), $_[0]);
}
sub netntlmv2 {
	my $pwd = $_[1];
	my $nthash = md4(encode("UTF-16LE", $pwd));
	my $user;
	my $domain;
	if (defined $argsalt) {
	    $domain = "workgroup";
	    $user = $argsalt;
	} else {
	    $domain = randstr(rand(15)+1);
	    $user = randusername(20);
	}
	my $identity = Encode::encode("UTF-16LE", uc($user).$domain);
	my $s_challenge = randstr(8,\@chrRawData);
	my $c_challenge = randstr(8,\@chrRawData);
	my $temp = '\x01\x01' . "\x00"x6 . randstr(8,\@chrRawData) . $c_challenge . "\x00"x4 . randstr(int(rand(20))+1,\@chrRawData) . '\x00';
	my $ntproofstr = _hmacmd5(_hmacmd5($nthash, $identity), $s_challenge.$temp);
	# $ntresponse = $ntproofstr.$temp but we separate them with a :
	printf("%s\\%s:::%s:%s:%s::%s:netntlmv2\n", $domain, $user, unpack("H*",$s_challenge), unpack("H*",$ntproofstr), unpack("H*",$temp), $_[0]);
}
sub mschapv2 {
	require Crypt::ECB;
	import Crypt::ECB qw(encrypt PADDING_AUTO PADDING_NONE);
	my $pwd = $_[1];
	my $nthash = md4(encode("UTF-16LE", $pwd));
	my $user = randusername();
	my $a_challenge = randstr(16,\@chrRawData);
	my $p_challenge = randstr(16,\@chrRawData);
	my $ctx = Digest::SHA->new('sha1');
	$ctx->add($p_challenge);
	$ctx->add($a_challenge);
	$ctx->add($user);
	my $challenge = substr($ctx->digest, 0, 8);
	my $response = Crypt::ECB::encrypt(setup_des_key(substr($nthash, 0, 7)), 'DES', $challenge, PADDING_NONE());
	$response .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 7, 7)), 'DES', $challenge, PADDING_NONE());
	$response .= Crypt::ECB::encrypt(setup_des_key(substr($nthash . "\x00" x 5, 14, 7)), 'DES', $challenge, PADDING_NONE());
	printf("%s:::%s:%s:%s::%s:mschapv2\n", $user, unpack("H*",$a_challenge), unpack("H*",$response), unpack("H*",$p_challenge), $_[0]);
}
sub crc_32 {
	require String::CRC32;
	import String::CRC32 qw(crc32);
	my $pwd = $_[1];
	if (rand(256) > 245) {
		my $init = rand(2000000000);
		printf("$u-crc32:\$crc32\$%08x.%08x:0:0:100:%s:\n", $init, crc32($pwd,$init), $_[0]);
	} else {
		printf("$u-crc32:\$crc32\$00000000.%08x:0:0:100:%s:\n", crc32($pwd), $_[0]);
	}
}
sub dummy {
    print "$u-dummy:", '$dummy$', unpack('H*', $_[1]), "\n";
}
sub raw_gost {
	require Digest::GOST;
	import Digest::GOST qw(gost gost_hex gost_base64);
	printf("$u-gost:\$gost\$%s:0:0:100:%s:\n", gost_hex($_[1]), $_[0]);
}
sub raw_gost_cp {
	# HMMM.  Not sure how to do this at this time in perl.
	print STDERR "raw_gost_cp : THIS ONE STILL LEFT TO DO\n";
}
sub pwsafe {
	$salt=get_salt(32);
	my $digest = sha256($_[1],$salt);
	my $i;
	for ($i = 0; $i <= 2048; ++$i) {
		$digest = sha256($digest);
	}
	print "u$u-pwsafe:\$pwsafe\$\*3\*", unpack('H*', $salt), "\*2048\*", unpack('H*', $digest), ":$u:0:$_[0]::\n";
}
sub django {
	$salt=get_salt(12,-32);
	print "u$u-django:\$django\$\*1\*pbkdf2_sha256\$10000\$$salt\$", base64(pp_pbkdf2($_[1], $salt, 10000, "sha256", 32, 64)), ":$u:0:$_[0]::\n";
}
sub django_scrypt {
	require Crypt::ScryptKDF;
	import Crypt::ScryptKDF qw(scrypt_b64);
	$salt=get_salt(12,12,\@i64);
	my $N=14; my $r=8; my $p=1; my $bytes=64;
	my $h = scrypt_b64($_[1],$salt,1<<$N,$r,$p,$bytes);
	print "u$u-django_scrypt:scrypt\$$salt\$$N\$$r\$$p\$$bytes\$$h:$u:0:", $_[0], "::\n";
}
sub scrypt {
	require Crypt::ScryptKDF;
	import Crypt::ScryptKDF qw(scrypt_raw);
	$salt=get_salt(12,-64,\@i64);
	my $N=14; my $r=8; my $p=1; my $bytes=32;
	my $h = base64i(scrypt_raw($_[1],$salt,1<<$N,$r,$p,$bytes));
	# C is 14, 6.... is 8 and /.... is 1  ($N, $r, $p)
	if (length($h) > 43) { $h = substr($h,0,43); }
	print "u$u-scrypt:\$7\$C6..../....$salt\$".$h.":$u:0:", $_[0], "::\n";
}
sub aix_ssha1 {
	$salt=get_salt(16);
	print "u$u-aix-ssha1:{ssha1}06\$$salt\$", base64_aix(pp_pbkdf2($_[1],$salt,(1<<6),"sha1",20, 64)) ,":$u:0:", $_[0], "::\n";
}
sub aix_ssha256 {
	$salt=get_salt(16);
	print "u$u-aix-ssha256:{ssha256}06\$$salt\$", base64_aix(pp_pbkdf2($_[1],$salt,(1<<6),"sha256",32, 64)) ,":$u:0:", $_[0], "::\n";
}
sub aix_ssha512 {
	$salt=get_salt(16);
	print "u$u-aix-ssha512:{ssha512}06\$$salt\$", base64_aix(pp_pbkdf2($_[1],$salt,(1<<6),"sha512",64, 128)) ,":$u:0:", $_[0], "::\n";
}
# there are many 'formats' handled, but we just do the cannonical $pbkdf2-hmac-sha512$ one.
# there could also be $ml$ and grub.pbkdf2.sha512. as the signatures. but within prepare() of pbkdf2-hmac-sha512_fmt,
# they all get converted to this one, so that is all I plan on using.
sub pbkdf2_hmac_sha512 {
	$salt=get_salt(16,-32);
	my $itr = 10000;
	if ($arg_loops > 0) { $itr = $arg_loops; }
	print "u$u-pbkdf2-hmac-sha512:\$pbkdf2-hmac-sha512\$${itr}.".unpack("H*", $salt).".", pp_pbkdf2_hex($_[1],$salt,$itr,"sha512",64, 128) ,":$u:0:", $_[0], "::\n";
}
sub pbkdf2_hmac_sha256 {
	$salt=get_salt(16);
	my $itr = 1000;
	if ($arg_loops > 0) { $itr = $arg_loops; }
	my $s64 = base64pl($salt);
	my $h64 = substr(base64pl(pack("H*",pp_pbkdf2_hex($_[1],$salt,$itr,"sha256",32, 64))),0,43);
	print "u$u-pbkdf2-hmac-sha256:\$pbkdf2-sha256\$${itr}\$${s64}\$${h64}:$u:0:", $_[0], "::\n";
}
sub pbkdf2_hmac_sha1 {
	$salt=get_salt(16);
	my $itr = 1000;
	if ($arg_loops > 0) { $itr = $arg_loops; }
	print "u$u-pbkdf2-hmac-sha1:\$pbkdf2-hmac-sha1\$${itr}.".unpack("H*", $salt).".", pp_pbkdf2_hex($_[1],$salt,$itr,"sha1",20, 64) ,":$u:0:", $_[0], "::\n";
}
sub drupal7 {
	$salt=get_salt(8,-8);
	# We only handle the 'C' count (16384)
	my $h = sha512($salt.$_[1]);
	my $i = 16384;
	do { $h = sha512($h.$_[1]); } while (--$i > 0);
	print "u$u-drupal:\$S\$C",$salt,substr(base64i($h),0,43),":$u:0:$_[0]::\n";
}
sub epi {
	$salt=get_salt(30);
	print "u$u-epi:0x", uc(unpack("H*", $salt))," 0x",uc(sha1_hex(substr($salt,0,29),$_[1], "\0")),":$u:0:$_[0]::\n";
}
sub episerver_sha1 {
	$salt=get_salt(16);
	print "u$u-episvr-v0:\$episerver\$\*0\*", base64($salt), "\*", sha1_base64($salt, Encode::encode("UTF-16LE", $_[0])), ":$u:0:$_[0]::\n";
}
sub episerver_sha256 {
	$salt=get_salt(16);
	print "u$u-episvr-v1:\$episerver\$\*1\*", base64($salt), "\*", sha256_base64($salt, Encode::encode("UTF-16LE", $_[0])), ":$u:0:$_[0]::\n";
}
sub hmailserver {
	$salt=get_salt(6,6,\@chrHexLo);
	print "u$u-hmailserver:$salt",sha256_hex($salt,$_[1]),":$u:0:$_[0]::\n";
}
sub nukedclan {
	$salt=get_salt(20, 20, \@chrAsciiTextNum);
	my $decal=randstr(1, \@chrHexLo);
	my $pass_hash = sha1_hex($_[1]);
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
sub skey_fold {
    my $a; my $b;
	if ($_[1] == 4) {
		my( $f0, $f1, $f2, $f3) = unpack('I4', $_[0]);
		$a = pack('I', $f0) ^ pack('I', $f2);
		$b = pack('I', $f1) ^ pack('I', $f3);
	} else {
		my( $f0, $f1, $f2, $f3, $f4) = unpack('I5', $_[0]);
		$a = pack('I', $f0) ^ pack('I', $f2) ^ pack('I', $f4);
		$b = pack('I', $f1) ^ pack('I', $f3);
	}
	return $a.$b;
}
sub skey_md5 {
	$salt=get_salt(8, 8, \@chrAsciiTextNumLo);
	$salt = lc $salt;
	my $cnt=randstr(3, \@chrAsciiNum);
	my $h = md5($salt.$_[1]);
	$h = skey_fold($h, 4);
	my $i = $cnt;
	while ($i-- > 0) {
		$h = md5($h);
		$h = skey_fold($h, 4)
	}
	print "u$u-SKEY-md5:md5 $cnt $salt ",unpack("H*", $h),":$u:0:$_[0]::\n";
}
sub skey_md4 {
	$salt=get_salt(8, 8, \@chrAsciiTextNumLo);
	$salt = lc $salt;
	my $cnt=randstr(3, \@chrAsciiNum);
	my $h = md4($salt.$_[1]);
	$h = skey_fold($h, 4);
	my $i = $cnt;
	while ($i-- > 0) {
		$h = md4($h);
		$h = skey_fold($h, 4)
	}
	print "u$u-SKEY-md4:md4 $cnt $salt ",unpack("H*", $h),":$u:0:$_[0]::\n";
}
sub skey_sha1 {
	$salt=get_salt(8, 8, \@chrAsciiTextNumLo);
	$salt = lc $salt;
	my $cnt=randstr(3, \@chrAsciiNum);
	my $h = sha1($salt.$_[1]);
	$h = skey_fold($h, 5);
	my $i = $cnt;
	while ($i-- > 0) {
		$h = sha1($h);
		$h = skey_fold($h, 5)
	}
	print "u$u-SKEY-sha1:sha1 $cnt $salt ",unpack("H*", $h),":$u:0:$_[0]::\n";
}
sub skey_rmd160 {
	$salt=get_salt(8, 8, \@chrAsciiTextNumLo);
	$salt = lc $salt;
	my $cnt=randstr(3, \@chrAsciiNum);
	my $h = ripemd160($salt.$_[1]);
	$h = skey_fold($h, 5);
	my $i = $cnt;
	while ($i-- > 0) {
		$h = ripemd160($h);
		$h = skey_fold($h, 5)
	}
	print "u$u-SKEY-rmd160:rmd160 $cnt $salt ",unpack("H*", $h),":$u:0:$_[0]::\n";
}
sub radmin {
	my $pass = $_[1];
	while (length($pass) < 100) { $pass .= "\0"; }
	print "u$u-radmin:\$radmin2\$",md5_hex($pass),":$u:0:$_[0]::\n";
}
sub raw_sha {
# this method sux, but I can find NO sha0 anywhere else in perl.
# It does exist in "openssl dgst -sha"  however. Slow, but works.
	#$h = `echo -n '$_[1]' | openssl dgst -sha`;
	#chomp($h);
	#if (substr($h,0,9) eq "(stdin)= ") { $h = substr($h,9); }
	#if (substr($h,0,8) eq "(stdin)=") { $h = substr($h,8); }
	#print "u$u-raw_sha:$h:$u:0:$_[0]::\n";

	# found a way :)
	net_ssl_init;
	my $md = Net::SSLeay::EVP_get_digestbyname("sha");
	$h = Net::SSLeay::EVP_Digest($_[1], $md);
	print "u$u-raw_sha:".unpack("H*",$h).":$u:0:$_[0]::\n";
}
sub sybasease {
	$salt=get_salt(8, 8, \@chrAsciiTextNum);
	my $h = Encode::encode("UTF-16BE", $_[0]);
	while (length($h) < 510) { $h .= "\0\0"; }
	print "u$u-SybaseAES:0xc007", unpack("H*",$salt), sha256_hex($h.$salt),":$u:0:$_[0]::\n";
}
sub wbb3 {
	# Simply 'dynamic' format:  sha1($s.sha1($s.sha1($p)))
	$salt=get_salt(40, 40, \@chrHexLo);
	print "u$u-wbb3:\$wbb3\$\*1\*$salt\*",sha1_hex($salt,sha1_hex($salt,sha1_hex($_[1]))),":$u:0:$_[0]::\n";
}
############################################################
#  DYNAMIC code.  Quite a large block.  Many 'fixed' formats, and then a parser
############################################################
sub pad16 { # used by pad16($p)  This will null pad a string to 16 bytes long
	my $p = $_[0];
	while (length($p) < 16) {
		$p .= "\0";
	}
	return $p;
}
sub pad20 { # used by pad20($p)  This will null pad a string to 20 bytes long
	my $p = $_[0];
	while (length($p) < 20) {
		$p .= "\0";
	}
	return $p;
}
# used by pad_md64($p)  This will null pad a string to 64 bytes long, appends the 0x80 after current length, and puts length
# 'bits' (i.e. length << 3) in proper place for md5 processing.  HSRP format uses this.
sub pad_md64 {
	my $p = $_[0];
	my $len = length($p);
	$p .= "\x80";
	while (length($p) < 56) {
		$p .= "\0";
	}
	$p .= chr(($len*8)&0xFF);
	$p .= chr(($len*8)/256);
	while (length($p) < 64) {
		$p .= "\0";
	}
	return $p;
}

sub dynamic_7 { #dynamic_7 --> md5(md5($p).$s)
	if (defined $argsalt) { $salt = $argsalt; } else { $salt = randstr(3);}
	print "u$u-dynamic_7"."\x1F"."\$dynamic_7\$", md5_hex(md5_hex($_[1]), $salt), "\$$salt"."\x1F"."$u"."\x1F"."0"."\x1F"."$_[0]"."\x1F"."\x1F"."\n";
}
sub dynamic_17 { #dynamic_17 --> phpass ($P$ or $H$)	phpass
	if (defined $argsalt) { $salt = md5_hex($argsalt); } else { $salt=randstr(8); }
	my $h = PHPass_hash($_[1], 11, $salt);
	print "u$u-dynamic_17:\$dynamic_17\$", substr(base64i($h),0,22), "\$", to_phpbyte(11), $salt, ":$u:0:$_[0]::\n";
}
sub dynamic_19 { #dynamic_19 --> Cisco PIX (MD5)
	my $pass;
	if (length($_[1])>16) { $pass = substr($_[1],0,16); } else { $pass = $_[1]; }
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
	print "u$u-dynamic_19:\$dynamic_19\$$h:$u:0:", $_[0], "::\n";
}
sub dynamic_20 { #dynamic_20 --> Cisco PIX (MD5 salted)
	if (defined $argsalt) { $salt = $argsalt; if (length($salt) > 4) { $salt = substr($salt,0,4); } } else { $salt = randstr(4); }
	my $pass;
	if (length($_[1])>12) { $pass = substr($_[1],0,12); } else { $pass = $_[1]; }
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
	print "u$u-dynamic_20:\$dynamic_20\$$h\$$salt:$u:0:", $_[0], "::\n";
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
	my $h1 = md5_hex($user, ":myrealm:", $_[1]);
	my $h2 = md5_hex("GET:/");
	my $resp = md5_hex($h1, ":", $nonce, ":00000001:", $clientNonce, ":auth:", $h2);
	print "$user:\$dynamic_21\$$resp\$$nonce\$\$U$user\$\$F2myrealm\$\$F3GET\$/\$\$F400000001\$$clientNonce\$auth:$u:0:$_[0]::\n";
}
sub dynamic_27 { #dynamic_27 --> OpenBSD MD5
	if (length($_[1]) > 15) { print STDERR "Warning, john can only handle 15 byte passwords for this format!\n"; }
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(8); }
	$h = md5crypt_hash($_[1], $salt, "\$1\$");
	print "u$u-dynamic_27:\$dynamic_27\$", substr($h,15), "\$$salt:$u:0:$_[0]::\n";
}
sub dynamic_28 { # Apache MD5
	if (length($_[1]) > 15) { print STDERR "Warning, john can only handle 15 byte passwords for this format!\n"; }
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(8); }
	$h = md5crypt_hash($_[1], $salt, "\$apr1\$");
	print "u$u-dynamic_28:\$dynamic_28\$", substr($h,15), "\$$salt:$u:0:$_[0]::\n";
}
sub dynamic_compile {
	require Digest::Haval256;
	my $dynamic_args = $_[0];
	if (length($dynamic_args) == 0) {
		print STDERR "usage: $0 [-h|-?] HashType ... [ < wordfile ]\n";
		print STDERR "\n";
		print STDERR "NOTE, for DYNAMIC usage:   here are the possible formats:\n";
		print STDERR "    dynamic_#   # can be any of the built in dynamic values. So,\n";
		print STDERR "                dynamic_0 will output for md5(\$p) format\n";
		print STDERR "\n";
		print STDERR "    dynamic=num=#,format=FMT_EXPR[,saltlen=#][,salt=true|ashex|tohex]\n";
		print STDERR "         [,pass=uni][,salt2len=#][,const#=value][,usrname=true|lc|uc|uni]\n";
		print STDERR "         [,single_salt=1][passcase=uc|lc]]\n";
		print STDERR "\n";
		print STDERR "The FMT_EXPR is somewhat 'normal' php type format, with some extensions.\n";
		print STDERR "    A format such as md5(\$p.\$s.md5(\$p)) is 'normal'.  Dots must be used\n";
		print STDERR "    where needed. Also, only a SINGLE expression is valid.  Using an\n";
		print STDERR "    expression such as md5(\$p).md5(\$s) is not valid.\n";
		print STDERR "    The extensions are:\n";
		print STDERR "        Added \$s2 (if 2nd salt is defined),\n";
		print STDERR "        Added \$c1 to \$c9 for constants (must be defined in const#= values)\n";
		print STDERR "        Added \$u if user name (normal, upper/lower case or unicode convert)\n";
		print STDERR "        Handle md5, sha1, md4 sha2 (sha224,sha256,sha384,sha512) gost whirlpool tiger and haval crypts.\n";
		print STDERR "        Handle MD5, SHA1, MD4 SHA2 (all uc(sha2) types) GOST WHILRPOOL TIGER HAVAL which output hex in uppercase.\n";
		print STDERR "        Handle md5u, sha1u md4u, sha2*u gostu whirlpoolu tigeru havalu which encode to UTF16LE.\n";
		print STDERR "          prior to hashing. Warning, be careful with md5u and usrname=uni,\n";
		print STDERR "          they will 'clash'\n";
		print STDERR "        Handle md5_64, sha1_64, md4_64, sha2*_64 gost_64 whirlpool_64 tiger_64 haval_64 which output in\n";
		print STDERR "          'standard' base-64 which is \"./0-9A-Za-z\"\n";
		print STDERR "        Handle md5_64e, sha1_64e, md4_64e, sha2*_64e goste, whirlpoole which output in\n";
		print STDERR "          'standard' base-64 which is \"./0-9A-Za-z\" with '=' padding up to even\n";
		print STDERR "          4 character (similar to mime-base64\n";
		print STDERR "        Handle md5_raw, sha1_raw, md4_raw, sha2*_raw gost_raw whirlpool_raw which output\n";
		print STDERR "          is the 'binary' 16 or 20 bytes of data.  CAN not be used as 'outside'\n";
		print STDERR "           function\n";
		print STDERR "    User names are handled by usrname=  if true, then \'normal\' user names\n";
		print STDERR "    used, if lc, then user names are converted to lowercase, if uc then\n";
		print STDERR "    they are converted to UPPER case. if uni they are converted into unicode\n";
		print STDERR "    If constants are used, then they have to start from const1= and can \n";
		print STDERR "    go up to const9= , but they need to be in order, and start from one (1).\n";
		print STDERR "    So if there are 3 constants in the expression, then the line needs to\n";
		print STDERR "    contain const1=v1,const2=v2,const3=v3 (v's replaced by proper constants)\n";
		print STDERR "    if pw=uni is used, the passwords are converted into unicode before usage\n";
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
			$dynamic_args==39 && do {$fmt='md5($s.pad16($p)),saltlen=60';	last SWITCH; };
			$dynamic_args==40 && do {$fmt='sha1($s.pad20($p)),saltlen=60';	last SWITCH; };
			$dynamic_args==50 && do {$fmt='sha224($p)';					last SWITCH; };
			$dynamic_args==51 && do {$fmt='sha224($s.$p),saltlen=6';	last SWITCH; };
			$dynamic_args==52 && do {$fmt='sha224($p.$s)';				last SWITCH; };
			$dynamic_args==53 && do {$fmt='sha224(sha224($p))';			last SWITCH; };
			$dynamic_args==54 && do {$fmt='sha224(sha224_raw($p))';	    last SWITCH; };
			$dynamic_args==55 && do {$fmt='sha224(sha224($p).$s),saltlen=6';            last SWITCH; };
			$dynamic_args==56 && do {$fmt='sha224($s.sha224($p)),saltlen=6';            last SWITCH; };
			$dynamic_args==57 && do {$fmt='sha224(sha224($s).sha224($p)),saltlen=6';	last SWITCH; };
			$dynamic_args==58 && do {$fmt='sha224(sha224($p).sha224($p))';				last SWITCH; };
			$dynamic_args==60 && do {$fmt='sha256($p)';					last SWITCH; };
			$dynamic_args==61 && do {$fmt='sha256($s.$p),saltlen=6';	last SWITCH; };
			$dynamic_args==62 && do {$fmt='sha256($p.$s)';				last SWITCH; };
			$dynamic_args==63 && do {$fmt='sha256(sha256($p))';			last SWITCH; };
			$dynamic_args==64 && do {$fmt='sha256(sha256_raw($p))';	    last SWITCH; };
			$dynamic_args==65 && do {$fmt='sha256(sha256($p).$s),saltlen=6';            last SWITCH; };
			$dynamic_args==66 && do {$fmt='sha256($s.sha256($p)),saltlen=6';            last SWITCH; };
			$dynamic_args==67 && do {$fmt='sha256(sha256($s).sha256($p)),saltlen=6';	last SWITCH; };
			$dynamic_args==68 && do {$fmt='sha256(sha256($p).sha256($p))';				last SWITCH; };
			$dynamic_args==70 && do {$fmt='sha384($p)';					last SWITCH; };
			$dynamic_args==71 && do {$fmt='sha384($s.$p),saltlen=6';	last SWITCH; };
			$dynamic_args==72 && do {$fmt='sha384($p.$s)';				last SWITCH; };
			$dynamic_args==73 && do {$fmt='sha384(sha384($p))';			last SWITCH; };
			$dynamic_args==74 && do {$fmt='sha384(sha384_raw($p))';	    last SWITCH; };
			$dynamic_args==75 && do {$fmt='sha384(sha384($p).$s),saltlen=6';            last SWITCH; };
			$dynamic_args==76 && do {$fmt='sha384($s.sha384($p)),saltlen=6';            last SWITCH; };
			$dynamic_args==77 && do {$fmt='sha384(sha384($s).sha384($p)),saltlen=6';	last SWITCH; };
			$dynamic_args==78 && do {$fmt='sha384(sha384($p).sha384($p))';				last SWITCH; };
			$dynamic_args==80 && do {$fmt='sha512($p)';					last SWITCH; };
			$dynamic_args==81 && do {$fmt='sha512($s.$p),saltlen=6';	last SWITCH; };
			$dynamic_args==82 && do {$fmt='sha512($p.$s)';				last SWITCH; };
			$dynamic_args==83 && do {$fmt='sha512(sha512($p))';			last SWITCH; };
			$dynamic_args==84 && do {$fmt='sha512(sha512_raw($p))';	    last SWITCH; };
			$dynamic_args==85 && do {$fmt='sha512(sha512($p).$s),saltlen=6';            last SWITCH; };
			$dynamic_args==86 && do {$fmt='sha512($s.sha512($p)),saltlen=6';            last SWITCH; };
			$dynamic_args==87 && do {$fmt='sha512(sha512($s).sha512($p)),saltlen=6';	last SWITCH; };
			$dynamic_args==88 && do {$fmt='sha512(sha512($p).sha512($p))';				last SWITCH; };
			$dynamic_args==90 && do {$fmt='gost($p)';					last SWITCH; };
			$dynamic_args==91 && do {$fmt='gost($s.$p),saltlen=6';		last SWITCH; };
			$dynamic_args==92 && do {$fmt='gost($p.$s)';				last SWITCH; };
			$dynamic_args==93 && do {$fmt='gost(gost($p))';			    last SWITCH; };
			$dynamic_args==94 && do {$fmt='gost(gost_raw($p))';	        last SWITCH; };
			$dynamic_args==95 && do {$fmt='gost(gost($p).$s),saltlen=6';        last SWITCH; };
			$dynamic_args==96 && do {$fmt='gost($s.gost($p)),saltlen=6';        last SWITCH; };
			$dynamic_args==97 && do {$fmt='gost(gost($s).gost($p)),saltlen=6';	last SWITCH; };
			$dynamic_args==98 && do {$fmt='gost(gost($p).gost($p))';			last SWITCH; };
			$dynamic_args==100 && do {$fmt='whirlpool($p)';					last SWITCH; };
			$dynamic_args==101 && do {$fmt='whirlpool($s.$p),saltlen=6';	last SWITCH; };
			$dynamic_args==102 && do {$fmt='whirlpool($p.$s)';				last SWITCH; };
			$dynamic_args==103 && do {$fmt='whirlpool(whirlpool($p))';		last SWITCH; };
			$dynamic_args==104 && do {$fmt='whirlpool(whirlpool_raw($p))';	last SWITCH; };
			$dynamic_args==105 && do {$fmt='whirlpool(whirlpool($p).$s),saltlen=6';				last SWITCH; };
			$dynamic_args==106 && do {$fmt='whirlpool($s.whirlpool($p)),saltlen=6';				last SWITCH; };
			$dynamic_args==107 && do {$fmt='whirlpool(whirlpool($s).whirlpool($p)),saltlen=6';	last SWITCH; };
			$dynamic_args==108 && do {$fmt='whirlpool(whirlpool($p).whirlpool($p))';			last SWITCH; };
			$dynamic_args==110 && do {$fmt='tiger($p)';					last SWITCH; };
			$dynamic_args==111 && do {$fmt='tiger($s.$p),saltlen=6';	last SWITCH; };
			$dynamic_args==112 && do {$fmt='tiger($p.$s)';				last SWITCH; };
			$dynamic_args==113 && do {$fmt='tiger(tiger($p))';		last SWITCH; };
			$dynamic_args==114 && do {$fmt='tiger(tiger_raw($p))';	last SWITCH; };
			$dynamic_args==115 && do {$fmt='tiger(tiger($p).$s),saltlen=6';				last SWITCH; };
			$dynamic_args==116 && do {$fmt='tiger($s.tiger($p)),saltlen=6';				last SWITCH; };
			$dynamic_args==117 && do {$fmt='tiger(tiger($s).tiger($p)),saltlen=6';	last SWITCH; };
			$dynamic_args==118 && do {$fmt='tiger(tiger($p).tiger($p))';			last SWITCH; };
			$dynamic_args==120 && do {$fmt='ripemd128($p)';					last SWITCH; };
			$dynamic_args==121 && do {$fmt='ripemd128($s.$p),saltlen=6';	last SWITCH; };
			$dynamic_args==122 && do {$fmt='ripemd128($p.$s)';				last SWITCH; };
			$dynamic_args==123 && do {$fmt='ripemd128(ripemd128($p))';		last SWITCH; };
			$dynamic_args==124 && do {$fmt='ripemd128(ripemd128_raw($p))';	last SWITCH; };
			$dynamic_args==125 && do {$fmt='ripemd128(ripemd128($p).$s),saltlen=6';				last SWITCH; };
			$dynamic_args==126 && do {$fmt='ripemd128($s.ripemd128($p)),saltlen=6';				last SWITCH; };
			$dynamic_args==127 && do {$fmt='ripemd128(ripemd128($s).ripemd128($p)),saltlen=6';	last SWITCH; };
			$dynamic_args==128 && do {$fmt='ripemd128(ripemd128($p).ripemd128($p))';			last SWITCH; };
			$dynamic_args==130 && do {$fmt='ripemd160($p)';					last SWITCH; };
			$dynamic_args==131 && do {$fmt='ripemd160($s.$p),saltlen=6';	last SWITCH; };
			$dynamic_args==132 && do {$fmt='ripemd160($p.$s)';				last SWITCH; };
			$dynamic_args==133 && do {$fmt='ripemd160(ripemd160($p))';		last SWITCH; };
			$dynamic_args==134 && do {$fmt='ripemd160(ripemd160_raw($p))';	last SWITCH; };
			$dynamic_args==135 && do {$fmt='ripemd160(ripemd160($p).$s),saltlen=6';				last SWITCH; };
			$dynamic_args==136 && do {$fmt='ripemd160($s.ripemd160($p)),saltlen=6';				last SWITCH; };
			$dynamic_args==137 && do {$fmt='ripemd160(ripemd160($s).ripemd160($p)),saltlen=6';	last SWITCH; };
			$dynamic_args==138 && do {$fmt='ripemd160(ripemd160($p).ripemd160($p))';			last SWITCH; };
			$dynamic_args==140 && do {$fmt='ripemd256($p)';					last SWITCH; };
			$dynamic_args==141 && do {$fmt='ripemd256($s.$p),saltlen=6';	last SWITCH; };
			$dynamic_args==142 && do {$fmt='ripemd256($p.$s)';				last SWITCH; };
			$dynamic_args==143 && do {$fmt='ripemd256(ripemd256($p))';		last SWITCH; };
			$dynamic_args==144 && do {$fmt='ripemd256(ripemd256_raw($p))';	last SWITCH; };
			$dynamic_args==145 && do {$fmt='ripemd256(ripemd256($p).$s),saltlen=6';				last SWITCH; };
			$dynamic_args==146 && do {$fmt='ripemd256($s.ripemd256($p)),saltlen=6';				last SWITCH; };
			$dynamic_args==147 && do {$fmt='ripemd256(ripemd256($s).ripemd256($p)),saltlen=6';	last SWITCH; };
			$dynamic_args==148 && do {$fmt='ripemd256(ripemd256($p).ripemd256($p))';			last SWITCH; };
			$dynamic_args==150 && do {$fmt='ripemd320($p)';			last SWITCH; };
			$dynamic_args==151 && do {$fmt='ripemd320($s.$p),saltlen=6';	last SWITCH; };
			$dynamic_args==152 && do {$fmt='ripemd320($p.$s)';				last SWITCH; };
			$dynamic_args==153 && do {$fmt='ripemd320(ripemd320($p))';		last SWITCH; };
			$dynamic_args==154 && do {$fmt='ripemd320(ripemd320_raw($p))';	last SWITCH; };
			$dynamic_args==155 && do {$fmt='ripemd320(ripemd320($p).$s),saltlen=6';				last SWITCH; };
			$dynamic_args==156 && do {$fmt='ripemd320($s.ripemd320($p)),saltlen=6';				last SWITCH; };
			$dynamic_args==157 && do {$fmt='ripemd320(ripemd320($s).ripemd320($p)),saltlen=6';	last SWITCH; };
			$dynamic_args==158 && do {$fmt='ripemd320(ripemd320($p).ripemd320($p))';			last SWITCH; };

			# 7, 17, 19, 20, 21, 27, 28 are still handled by 'special' functions.

			# since these are in dynamic.conf, and treatly 'like' builtins, we might as well put them here.
			$dynamic_args==1001 && do {$fmt='md5(md5(md5(md5($p))))';	last SWITCH; };
			$dynamic_args==1002 && do {$fmt='md5(md5(md5(md5(md5($p)))))';	last SWITCH; };
			$dynamic_args==1003 && do {$fmt='md5(md5($p).md5($p))';		last SWITCH; };
			$dynamic_args==1004 && do {$fmt='md5(md5(md5(md5(md5(md5($p))))))';	last SWITCH; };
			$dynamic_args==1005 && do {$fmt='md5(md5(md5(md5(md5(md5(md5($p)))))))';	last SWITCH; };
			$dynamic_args==1006 && do {$fmt='md5(md5(md5(md5(md5(md5(md5(md5($p))))))))';	last SWITCH; };
			$dynamic_args==1007 && do {$fmt='md5(md5($p).$s),saltlen=3';	last SWITCH; };
			$dynamic_args==1008 && do {$fmt='md5($p.$s),saltlen=16';	last SWITCH; };
			$dynamic_args==1009 && do {$fmt='md5($s.$p),saltlen=16';	last SWITCH; };
			# dyna-1010 not handled yet (the pad null to 100 bytes)
			$dynamic_args==1011 && do {$fmt='md5($p.md5($s)),saltlen=6';	last SWITCH; };
			$dynamic_args==1012 && do {$fmt='md5($p.md5($s)),saltlen=6';	last SWITCH; };
			# dyna_1013 not handled, since we have no way to precompute md5(u) and add that as a 32 byte salt.
			# $dynamic_args==1013 && do {$fmt='md5($p.md5($u)),username';	last SWITCH; };
			$dynamic_args==1014 && do {$fmt='md5($p.$s),saltlen=56';	last SWITCH; };
			$dynamic_args==1015 && do {$fmt='md5(md5($p.$u).$s),saltlen=6,username';	last SWITCH; };
			$dynamic_args==1018 && do {$fmt='md5(sha1(sha1($p)))';	last SWITCH; };
			$dynamic_args==1019 && do {$fmt='md5(sha1(sha1(md5($p))))';	last SWITCH; };
			$dynamic_args==1020 && do {$fmt='md5(sha1(md5($p)))';	last SWITCH; };
			$dynamic_args==1021 && do {$fmt='md5(sha1(md5(sha1($p))))';	last SWITCH; };
			$dynamic_args==1022 && do {$fmt='md5(sha1(md5(sha1(md5($p)))))';	last SWITCH; };
			$dynamic_args==1023 && do {$fmt='trunc32(sha1($p))';	last SWITCH; };
			$dynamic_args==1024 && do {$fmt='trunc32(sha1(md5($p)))';	last SWITCH; };
			$dynamic_args==1025 && do {$fmt='trunc32(sha1(md5(md5($p))))';	last SWITCH; };
			$dynamic_args==1026 && do {$fmt='trunc32(sha1(sha1($p)))';	last SWITCH; };
			$dynamic_args==1027 && do {$fmt='trunc32(sha1(sha1(sha1($p))))';	last SWITCH; };
			$dynamic_args==1028 && do {$fmt='trunc32(sha1(sha1_raw($p)))';	last SWITCH; };
			$dynamic_args==1029 && do {$fmt='trunc32(sha256($p))';	last SWITCH; };
			$dynamic_args==1030 && do {$fmt='trunc32(whirlpool($p))';	last SWITCH; };
			$dynamic_args==1031 && do {$fmt='trunc32(gost($p))';	last SWITCH; };
			$dynamic_args==1300 && do {$fmt='md5(md5_raw($p))';	last SWITCH; };
			$dynamic_args==1350 && do {$fmt='md5(md5($s.$p).$c1.$s),saltlen=2,const1=:';	last SWITCH; };

			$dynamic_args==2000 && do {$fmt='md5($p)';					last SWITCH; };
			$dynamic_args==2001 && do {$fmt='md5($p.$s),saltlen=32';	last SWITCH; };
			$dynamic_args==2002 && do {$fmt='md5(md5($p))';				last SWITCH; };
			$dynamic_args==2003 && do {$fmt='md5(md5(md5($p)))';		last SWITCH; };
			$dynamic_args==2004 && do {$fmt='md5($s.$p),saltlen=2';		last SWITCH; };
			$dynamic_args==2005 && do {$fmt='md5($s.$p.$s)';			last SWITCH; };
			$dynamic_args==2006 && do {$fmt='md5(md5($p).$s)';			last SWITCH; };
			$dynamic_args==2008 && do {$fmt='md5(md5($s).$p)';			last SWITCH; };
			$dynamic_args==2009 && do {$fmt='md5($s.md5($p))';			last SWITCH; };
			$dynamic_args==2010 && do {$fmt='md5($s.md5($s.$p))';		last SWITCH; };
			$dynamic_args==2011 && do {$fmt='md5($s.md5($p.$s))';		last SWITCH; };
			$dynamic_args==2014 && do {$fmt='md5($s.md5($p).$s)';		last SWITCH; };

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
	require Digest::Haval256;
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
		if ($stmp eq "1") { push(@gen_toks, "1"); if (!defined($gen_c[0])) {print STDERR "\$c1 found, but no constant1 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "2") { push(@gen_toks, "2"); if (!defined($gen_c[1])) {print STDERR "\$c2 found, but no constant2 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "3") { push(@gen_toks, "3"); if (!defined($gen_c[2])) {print STDERR "\$c3 found, but no constant3 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "4") { push(@gen_toks, "4"); if (!defined($gen_c[3])) {print STDERR "\$c4 found, but no constant4 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "5") { push(@gen_toks, "5"); if (!defined($gen_c[4])) {print STDERR "\$c5 found, but no constant5 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "6") { push(@gen_toks, "6"); if (!defined($gen_c[5])) {print STDERR "\$c6 found, but no constant6 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "7") { push(@gen_toks, "7"); if (!defined($gen_c[6])) {print STDERR "\$c7 found, but no constant7 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "8") { push(@gen_toks, "8"); if (!defined($gen_c[7])) {print STDERR "\$c8 found, but no constant8 loaded\n"; die; } return substr($exprStr, 3); }
		if ($stmp eq "9") { push(@gen_toks, "9"); if (!defined($gen_c[8])) {print STDERR "\$c9 found, but no constant9 loaded\n"; die; } return substr($exprStr, 3); }
		push(@gen_toks, "X");
		return $exprStr;
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
	if (substr($exprStr, 0,13) eq "whirlpool_raw") { push(@gen_toks, "fwrlpr");return substr($exprStr, 13); }
	if (substr($exprStr, 0, 9) eq "tiger_raw")     { push(@gen_toks, "ftigr"); return substr($exprStr, 9); }
	if (substr($exprStr, 0,13) eq "ripemd128_raw") { push(@gen_toks, "frip128r"); return substr($exprStr,13); }
	if (substr($exprStr, 0,13) eq "ripemd160_raw") { push(@gen_toks, "frip160r"); return substr($exprStr,13); }
	if (substr($exprStr, 0,13) eq "ripemd256_raw") { push(@gen_toks, "frip256r"); return substr($exprStr,13); }
	if (substr($exprStr, 0,13) eq "ripemd320_raw") { push(@gen_toks, "frip320r"); return substr($exprStr,13); }
	if (substr($exprStr, 0,12) eq "haval256_raw")  { push(@gen_toks, "fhavr"); return substr($exprStr,12); }
	if (substr($exprStr, 0,5)  eq "pad16")         { push(@gen_toks, "fpad16"); return substr($exprStr,5); }
	if (substr($exprStr, 0,5)  eq "pad20")         { push(@gen_toks, "fpad20"); return substr($exprStr,5); }
	if (substr($exprStr, 0,7)  eq "padmd64")       { push(@gen_toks, "fpadmd64"); return substr($exprStr,7); }

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
	} elsif ($stmp eq "TIG") {
		if (substr($exprStr, 0, 9) eq "tiger_64e")  { push(@gen_toks, "ftige"); return substr($exprStr, 9); }
		if (substr($exprStr, 0, 8) eq "tiger_64")   { push(@gen_toks, "ftig6"); return substr($exprStr, 8); }
		if (substr($exprStr, 0, 6) eq "tigeru")     { push(@gen_toks, "ftigu"); return substr($exprStr, 6); }
		if (substr($exprStr, 0, 5) eq "TIGER")      { push(@gen_toks, "ftigH"); return substr($exprStr, 5); }
		if (substr($exprStr, 0, 5) eq "tiger")      { push(@gen_toks, "ftigh"); return substr($exprStr, 5); }
	} elsif ($stmp eq "RIP") {
		if (substr($exprStr, 0,13) eq "ripemd128_64e")  { push(@gen_toks, "frip128e"); return substr($exprStr,13); }
		if (substr($exprStr, 0,12) eq "ripemd128_64")   { push(@gen_toks, "frip1286"); return substr($exprStr,12); }
		if (substr($exprStr, 0,10) eq "ripemd128u")     { push(@gen_toks, "frip128u"); return substr($exprStr,10); }
		if (substr($exprStr, 0, 9) eq "RIPEMD129")      { push(@gen_toks, "frip128H"); return substr($exprStr, 9); }
		if (substr($exprStr, 0, 9) eq "ripemd128")      { push(@gen_toks, "frip128h"); return substr($exprStr, 9); }
		if (substr($exprStr, 0,13) eq "ripemd160_64e")  { push(@gen_toks, "frip160e"); return substr($exprStr,13); }
		if (substr($exprStr, 0,12) eq "ripemd160_64")   { push(@gen_toks, "frip1606"); return substr($exprStr,12); }
		if (substr($exprStr, 0,10) eq "ripemd160u")     { push(@gen_toks, "frip160u"); return substr($exprStr,10); }
		if (substr($exprStr, 0, 9) eq "RIPEMD160")      { push(@gen_toks, "frip160H"); return substr($exprStr, 9); }
		if (substr($exprStr, 0, 9) eq "ripemd160")      { push(@gen_toks, "frip160h"); return substr($exprStr, 9); }
		if (substr($exprStr, 0,13) eq "ripemd256_64e")  { push(@gen_toks, "frip256e"); return substr($exprStr,13); }
		if (substr($exprStr, 0,12) eq "ripemd256_64")   { push(@gen_toks, "frip2566"); return substr($exprStr,12); }
		if (substr($exprStr, 0,10) eq "ripemd256u")     { push(@gen_toks, "frip256u"); return substr($exprStr,10); }
		if (substr($exprStr, 0, 9) eq "RIPEMD129")      { push(@gen_toks, "frip256H"); return substr($exprStr, 9); }
		if (substr($exprStr, 0, 9) eq "ripemd256")      { push(@gen_toks, "frip256h"); return substr($exprStr, 9); }
		if (substr($exprStr, 0,13) eq "ripemd320_64e")  { push(@gen_toks, "frip320e"); return substr($exprStr,13); }
		if (substr($exprStr, 0,12) eq "ripemd320_64")   { push(@gen_toks, "frip3206"); return substr($exprStr,12); }
		if (substr($exprStr, 0,10) eq "ripemd320u")     { push(@gen_toks, "frip320u"); return substr($exprStr,10); }
		if (substr($exprStr, 0, 9) eq "RIPEMD129")      { push(@gen_toks, "frip320H"); return substr($exprStr, 9); }
		if (substr($exprStr, 0, 9) eq "ripemd320")      { push(@gen_toks, "frip320h"); return substr($exprStr, 9); }
	} elsif ($stmp eq "HAV") {
		if (substr($exprStr, 0,12) eq "haval256_64e")  { push(@gen_toks, "fhave"); return substr($exprStr,12); }
		if (substr($exprStr, 0,11) eq "haval256_64")   { push(@gen_toks, "fhav6"); return substr($exprStr,11); }
		if (substr($exprStr, 0, 9) eq "haval256u")     { push(@gen_toks, "fhavu"); return substr($exprStr, 9); }
		if (substr($exprStr, 0, 8) eq "HAVEL256")      { push(@gen_toks, "fhavH"); return substr($exprStr, 8); }
		if (substr($exprStr, 0, 8) eq "haval256")      { push(@gen_toks, "fhavh"); return substr($exprStr, 8); }
	} elsif ($stmp eq "TRU") {
		if (substr($exprStr, 0,7) eq "trunc32")  { push(@gen_toks, "ftr32"); return substr($exprStr, 7); }
	}

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
		print STDERR "The expression MUST start with an md5/md4/sha1 type function.  This one starts with: $_[0]\n";  die;
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
	if (!defined ($gen_num )) { print STDERR "Error, num=# is REQUIRED for dynamic\n"; die; }
	my $v = $hash{"format"};
	if (!defined ($v)) { print STDERR "Error, format=EXPR is REQUIRED for dynamic\n"; die; }

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
	unless (@gen_toks > 3) { print STDERR "Error, the format= of the expression was missing, or NOT valid\n"; die; }

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

		print STDERR "Error, invalid, can NOT create this expression (trying to build sample test buffer\n";
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
#  Here are the ACTUAL pCode primitive functions.  These handle pretty
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
sub dynamic_ftr32  { $h = pop @gen_Stack; $h = substr($h,0,32);  $gen_Stack[@gen_Stack-1] .= $h; return $h; }
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
sub dynamic_fgosth { require Digest::GOST; import Digest::GOST qw(gost gost_hex gost_base64); $h = pop @gen_Stack; $h = gost_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgostH { require Digest::GOST; import Digest::GOST qw(gost gost_hex gost_base64); $h = pop @gen_Stack; $h = uc gost_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgost6 { require Digest::GOST; import Digest::GOST qw(gost gost_hex gost_base64); $h = pop @gen_Stack; $h = gost_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgoste { require Digest::GOST; import Digest::GOST qw(gost gost_hex gost_base64); $h = pop @gen_Stack; $h = gost_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgostu { require Digest::GOST; import Digest::GOST qw(gost gost_hex gost_base64); $h = pop @gen_Stack; $h = gost_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgostr { require Digest::GOST; import Digest::GOST qw(gost gost_hex gost_base64); $h = pop @gen_Stack; $h = gost($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlph { $h = pop @gen_Stack; $h = whirlpool_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlpH { $h = pop @gen_Stack; $h = uc whirlpool_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlp6 { $h = pop @gen_Stack; $h = whirlpool_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlpe { $h = pop @gen_Stack; $h = whirlpool_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlpu { $h = pop @gen_Stack; $h = whirlpool_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlpr { $h = pop @gen_Stack; $h = whirlpool($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_ftigh  { $h = pop @gen_Stack; $h = tiger_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_ftigH  { $h = pop @gen_Stack; $h = uc tiger_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_ftig6  { $h = pop @gen_Stack; $h = tiger_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_ftige  { $h = pop @gen_Stack; $h = tiger_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_ftigu  { $h = pop @gen_Stack; $h = tiger_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_ftigr  { $h = pop @gen_Stack; $h = tiger($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip128h  { $h = pop @gen_Stack; $h = ripemd128_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip128H  { $h = pop @gen_Stack; $h = uc ripemd128_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip1286  { $h = pop @gen_Stack; $h = ripemd128_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip128e  { $h = pop @gen_Stack; $h = ripemd128_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip128u  { $h = pop @gen_Stack; $h = ripemd128_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip128r  { $h = pop @gen_Stack; $h = ripemd128($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip160h  { $h = pop @gen_Stack; $h = ripemd160_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip160H  { $h = pop @gen_Stack; $h = uc ripemd160_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip1606  { $h = pop @gen_Stack; $h = ripemd160_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip160e  { $h = pop @gen_Stack; $h = ripemd160_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip160u  { $h = pop @gen_Stack; $h = ripemd160_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip160r  { $h = pop @gen_Stack; $h = ripemd160($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip256h  { $h = pop @gen_Stack; $h = ripemd256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip256H  { $h = pop @gen_Stack; $h = uc ripemd256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip2566  { $h = pop @gen_Stack; $h = ripemd256_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip256e  { $h = pop @gen_Stack; $h = ripemd256_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip256u  { $h = pop @gen_Stack; $h = ripemd256_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip256r  { $h = pop @gen_Stack; $h = ripemd256($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip320h  { $h = pop @gen_Stack; $h = ripemd320_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip320H  { $h = pop @gen_Stack; $h = uc ripemd320_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip3206  { $h = pop @gen_Stack; $h = ripemd320_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip320e  { $h = pop @gen_Stack; $h = ripemd320_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip320u  { $h = pop @gen_Stack; $h = ripemd320_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip320r  { $h = pop @gen_Stack; $h = ripemd320($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fhavh  { require Digest::Haval256; $h = pop @gen_Stack; $h = haval256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fhavH  { require Digest::Haval256; $h = pop @gen_Stack; $h = uc haval256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fhav6  { require Digest::Haval256; $h = pop @gen_Stack; $h = haval256_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fhave  { require Digest::Haval256; $h = pop @gen_Stack; $h = haval256_base64($h); while (length($h)%4) { $h .= "="; } $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fhavu  { require Digest::Haval256; $h = pop @gen_Stack; $h = haval256_hex(encode("UTF-16LE",$h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fhavr  { require Digest::Haval256; $h = pop @gen_Stack; $h = haval256($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fpad16 { $h = pop @gen_Stack; $h = pad16($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fpad20 { $h = pop @gen_Stack; $h = pad20($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fpadmd64 { $h = pop @gen_Stack; $h = pad_md64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
