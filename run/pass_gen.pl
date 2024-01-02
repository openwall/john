#!/usr/bin/env perl

use warnings;
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
		Raw-MD4 phpass PO hmac-MD5 IPB2 PHPS MD4p MD4s SHA1p SHA1s
		mysql-sha1 pixMD5 MSSql05 MSSql12 netntlm cisco4 cisco8 cisco9
		nsldap nsldaps ns XSHA krb5pa-md5 krb5-18 mysql mssql_no_upcase_change
		mssql oracle oracle_no_upcase_change oracle11 hdaa netntlm_ess
		openssha l0phtcrack netlmv2 netntlmv2 mschapv2 mscash2 mediawiki
		crc_32 Dynamic dummy raw-sha224 raw-sha256 raw-sha384 raw-sha512
		dragonfly3-32 dragonfly4-32 dragonfly3-64 dragonfly4-64
		salted-sha1 raw_gost raw_gost_cp hmac-sha1 hmac-sha224 mozilla
		hmac-sha256 hmac-sha384 hmac-sha512 sha1crypt sha256crypt sha512crypt
		XSHA512 dynamic_27 dynamic_28 pwsafe django drupal7 epi zip
		episerver_sha1 episerver_sha256 hmailserver ike keepass
		keychain nukedclan radmin raw-SHA sip sip_qop SybaseASE
		wbb3 wpapsk sunmd5 wowsrp django-scrypt aix-ssha1 aix-ssha256
		aix-ssha512 pbkdf2-hmac-sha512 pbkdf2-hmac-sha256 scrypt
		rakp osc formspring skey-md5 pbkdf2-hmac-sha1 odf odf-1 office_2007
		skey-md4 skey-sha1 skey-rmd160 cloudkeychain agilekeychain
		rar ecryptfs office_2010 office_2013 tc_ripemd160 tc_sha512
		tc_whirlpool SAP-H rsvp pbkdf2-hmac-sha1-p5k2
		pbkdf2-hmac-sha1-pkcs5s2 md5crypt-smd5 ripemd-128 ripemd-160
		raw-tiger raw-whirlpool hsrp known-hosts chap bb-es10 citrix-ns10
		clipperz-srp dahua fortigate lp lastpass rawmd2 mongodb mysqlna
		o5logon postgres pst raw-blake2 raw-keccak raw-keccak256 siemens-s7
		ssha512 tcp-md5 strip bitcoin blockchain
		rawsha3-512 rawsha3-224 rawsha3-256 rawsha3-384 AzureAD vdi_256 vdi_128
		qnx_md5 qnx_sha512 qnx_sha256 sxc vnc vtp keystore pbkdf2-hmac-md4
		pbkdf2-hmac-md5 racf zipmonster asamd5 mongodb_scram has160 fgt iwork
		palshop snefru_128 snefru_256 keyring efs mdc2 eigrp as400ssha1 leet
		sapg sapb bitlocker money_md5 money_sha1
		));

# todo: sapfg ike keepass cloudkeychain pfx pdf pkzip rar5 ssh raw_gost_cp cq dmg dominosec encfs fde gpg haval-128 Haval-256 krb4 krb5 krb5pa-sha1 kwallet luks pfx afs ssh oldoffice openbsd-softraid openssl-enc openvms panama putty ssh-ng sybase-prop tripcode whirlpool0 whirlpool1
#       raw-skein-256 raw-skein-512 _7z axcrypt bks dmd5 dominosec8 krb5_tgs lotus5 lotus85 net_md5 net_sha1 netlmv2 netsplitlm openssl_enc oracle12c pem po pomelo stribog

my $i; my $h; my $u; my $salt;  my $out_username; my $out_extras; my $out_uc_pass; my $l0pht_fmt;
my $qnx_sha512_warning=0; my $is_mdc2_valid = -1;
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
my $arg_utf8 = 0; my $arg_codepage = ""; my $arg_minlen = 0; my $arg_maxlen = 128; my $arg_maxuserlen = 20; my $arg_dictfile = "stdin";
my $arg_count = 1500, my $argsalt, my $argiv, my $argcontent; my $arg_nocomment = 0; my $arg_hidden_cp; my $arg_loops=-1;
my $arg_tstall = 0; my $arg_genall = 0; my $arg_nrgenall = 0; my $argmode; my $arguser; my $arg_usertab; my $arg_outformat="normal";
my $arg_help = 0;
# these are 'converted' from whatever the user typed in for $arg_outformat
my $bVectors = 0; my $bUserIDs=1; my $bFullNormal=1;

GetOptions(
	'codepage=s'       => \$arg_codepage,
	'hiddencp=s'       => \$arg_hidden_cp,
	'utf8!'            => \$arg_utf8,
	'nocomment!'       => \$arg_nocomment,
	'minlength=n'      => \$arg_minlen,
	'maxlength=n'      => \$arg_maxlen,
	'maxuserlen=n'     => \$arg_maxuserlen,
	'salt=s'           => \$argsalt,
	'iv=s'             => \$argiv,
	'content=s'        => \$argcontent,
	'mode=s'           => \$argmode,
	'count=n'          => \$arg_count,
	'loops=n'          => \$arg_loops,
	'dictfile=s'       => \$arg_dictfile,
	'tstall!'          => \$arg_tstall,
	'genall!'          => \$arg_genall,
	'nrgenall!'        => \$arg_nrgenall,
	'outformat=s'      => \$arg_outformat,
	'user=s'           => \$arguser,
	'usertab!'         => \$arg_usertab,
	'help+'            => \$arg_help
	) || usage();

if ($arg_help != 0) {die usage();}

if ($arg_outformat eq substr("vectors", 0, length($arg_outformat))) {
	$bVectors = 1;
	$bUserIDs=0;
	$bFullNormal=0;
	$arg_nocomment = 1;
} elsif ($arg_outformat eq substr("raw", 0, length($arg_outformat))) {
	$bUserIDs=0;
	$bFullNormal=0;
	$arg_nocomment = 1;
}  elsif ($arg_outformat eq substr("user", 0, length($arg_outformat))) {
	$bFullNormal=0;
	$arg_nocomment = 1;
}  elsif ($arg_outformat eq substr("uhp", 0, length($arg_outformat))) {
	$bFullNormal=2;
	$arg_nocomment = 1;
}

sub pretty_print_hash_names {
	my ($wchar, $hchar, $wpixels, $hpixels);
	$wchar = 80;	# default IF Term::ReadKey lib not found.
	if (eval "require Term::ReadKey") {
		# note, if Term::ReadKey is not installed, the script
		# does not abort, but uses 80 columns for width of terminal.
		import Term::ReadKey qw(GetTerminalSize);
		($wchar, $hchar, $wpixels, $hpixels) = GetTerminalSize();
	}
	#if ($wchar > 120) {$wchar = 121;}
	--$wchar;
	my $s; my $s2; my $i;
	my @sorted_funcs = sort {lc($a) cmp lc($b)} @funcs;
	$s2 = "  ";
	for ($i = 0; $i < scalar @sorted_funcs; ++$i) {
		if (length($s2)+length($sorted_funcs[$i]) > $wchar) {
			$s .= $s2."\n";
			$s2 = "  ";
		}
		$s2 .= $sorted_funcs[$i]." ";
	}
	return $s.$s2."\n";
}

sub usage {
	my $hash_str = pretty_print_hash_names();
	my $hidden_opts = "    -help         shows this screen (-help -help shows hidden options)";
	my $name = $0;
	my $pos = rindex($name, "/");
	if ($pos != -1) {
		$name = substr($name, $pos+1);
	} elsif (($pos = rindex($name, "\\")) != -1) {
		$name = substr($name, $pos+1);
	}
	if ($arg_help > 1) { $hidden_opts =
"    -dictfile <s> Put name of dict file into the first line comment
    -nocomment    eliminate the first line comment
    -tstall       runs a 'simple' test for all known types.
    -genall       generates all hashes with random salts.
    -nrgenall     generates all hashes (non-random, repeatable)";
	}
	die <<"UsageHelp";
usage: $name [-codepage=CP] [-option[s]] HashType [...] [<wordfile]
  Options can be abbreviated!

  Default is to read and write files as binary, no conversions
    -utf8         shortcut to -codepage=UTF-8.
    -codepage=CP  Read and write files in CP encoding.

  Options are:
    -minlen <n>   Discard lines shorter than <n> characters  [0]
    -maxlen <n>   Discard lines longer than <n> characters   [125]
    -count <n>    Stop when we have produced <n> hashes      [1500]
    -loops <n>    Some formats have a loop count. This allows overriding.
    -salt <s>     Force a single salt
    -iv <s>       Force a single iv
    -content <s>  Force a single content
    -mode <s>     Force mode (zip, mode 1..3, rar4 modes 1..10, etc)
    -user <s>     Provide a fixed user name, vs random user name.
    -usertab      Input lines are <user>\\t<password> instead of <password>
    -outformat<s> output format. 'normal' 'vectors' 'raw' 'user' 'uhp' [normal]
$hidden_opts

HashType is one or more (space separated) from the following list:
$hash_str
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

if ($bVectors == 1 && (@ARGV != 1 || $arg_genall != 0)) {
	print STDERR "\n\nNOTE, if using --outformat=vector you must ONLY be processing for a single format\n\n";
	die usage();
}

#if not a redirected file, prompt the user
if (-t STDIN) {
	print STDERR "\nEnter words to hash, one per line.\n";
	if (@ARGV != 1) { print STDERR "When all entered ^D starts the processing.\n\n"; }
	$arg_nocomment = 1;  # we do not output further 'comment' lines if reading from stdin.
}

if ($arg_genall != 0) {
	while (<STDIN>) {
		next if (/^#!comment/);
		chomp;
		s/\r$//;  # strip CR for non-Windows
		#my $line_len = length($_);
		my $line_len = utf16_len($_);
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
	my $orig_arg = $ARGV[0];
	my $arg = lc $ARGV[0];
	if (substr($arg,0,8) eq "dynamic_") { substr($arg,0,8)="dynamic="; }
	if ($arg eq "dynamic") { dynamic_compile("") }
	if (substr($arg,0,8) eq "dynamic=") {
		@funcs = ();
		my $dyn="";
		if (length($orig_arg)>8) { $dyn=substr($orig_arg,8); }
		push(@funcs, $arg = dynamic_compile($dyn));
	}

	my $have_something = 0;
	foreach (@funcs) {
		if ($arg eq lc $_) {
			$have_something = 1;
			if (!$arg_nocomment) {
				print "\n#!comment: ** Here are the ";
				print $bVectors ? "test vectors" : "hashes";
				print " for format $orig_arg **\n";
			}
			$arg =~ s/-/_/g;
			while (<STDIN>) {
				next if (/^#!comment/);
				chomp;
				s/\r$//;  # strip CR for non-Windows
				my $real_arguser;
				if ($arg_usertab)
				{
					my ($this_user, $this_plain) = split(/\t/, $_, 2);
					next unless defined($this_plain);
					$arguser = $this_user;
					$_ = $this_plain;
				}
				elsif ($arguser and $arguser =~ /([0-9]+)?\+\+/)
				{
					my $usernum = $1 ? $1 : 0;
					$usernum += $u;
					$real_arguser = $arguser;
					$arguser =~ s/([0-9]+)?\+\+/$usernum/;
				}
				#my $line_len = length($_);
				my $line_len = utf16_len($_);
				next if $line_len > $arg_maxlen || $line_len < $arg_minlen;
				reset_out_vars();
				no strict 'refs';
				my $hash = &$arg($_, word_encode($_));
				use strict;
				if (defined($hash) && length($hash) > 4) {
					output_hash($hash, $_, word_encode($_));
				}
				++$u;
				if ($u >= $arg_count) {
					print STDERR "Got $arg_count, not processing more. Use -count to bump limit.\n";
					last;
				}
				if ($real_arguser)
				{
					$arguser = $real_arguser;
				}
			}
			last;
		}
	}
	if (!$have_something) {
		print STDERR "hash type [$orig_arg] is not supported\n";
		exit(1);
	}
} else {
	#slurp the wordlist words from stdin.  We  have to, to be able to run the same words multiple
	# times, and not interleave the format 'types' in the file.  Doing this allows us to group them.
	my @lines = <STDIN>;

	foreach (@ARGV) {
		$u = 0;
		my $orig_arg = $_;
		my $arg = lc $_;
		if ($arg eq "dynamic") { dynamic_compile(""); }
		if (substr($arg,0,8) eq "dynamic_") { substr($arg,0,8)="dynamic="; }
		if (substr($arg,0,8) eq "dynamic=") {
			my $dyn="";
			if (length($orig_arg)>8) { $dyn=substr($orig_arg,8); }
			push(@funcs, $arg = dynamic_compile($dyn));
		}
		my $have_something = 0;
		foreach (@funcs) {
			if ($arg eq lc $_) {
				$have_something = 1;
				if (!$arg_nocomment) { print "\n#!comment: ** Here are the hashes for format $orig_arg **\n"; }
				$arg =~ s/-/_/g;
				foreach (@lines) {
					next if (/^#!comment/);
					chomp;
					s/\r$//;  # strip CR for non-Windows
					#my $line_len = length($_);
					my $line_len = utf16_len($_);
					next if $line_len > $arg_maxlen || $line_len < $arg_minlen;
					reset_out_vars();
					no strict 'refs';
					my $hash = &$arg($_, word_encode($_));
					use strict;
					if (defined($hash) && length($hash) > 4) {
						output_hash($hash, $_, word_encode($_));
					}
					++$u;
					last if $u >= $arg_count;
				}
				last;
			}
		}
		if (!$have_something) {
			print STDERR "hash type [$orig_arg] is not supported\n";
			exit(1);
		}
	}
}

#############################################################################
# these variables modify outout in output_hash, for 'some' formats. We might
# upcase the password. The hash may return multple fields in its 'hash' that
# is returned, so that means we add fewer 'extra' fields prior to the password.
# also, we may have to insert the user name as field 1.  This function sets
# 'proper' defaults, so if a hash function does not set anything, it will
# output in proper format.
#############################################################################
sub reset_out_vars {
	$out_username = "";
	$out_extras = 2;
	$out_uc_pass = 0;
	$l0pht_fmt = 0;
}
#############################################################################
#   sub output_hash($hash, $pass, $encoded_pass)
# a 'common' output function. This right now is just a stub, but laster we
# can have some command line option(s) that allows control over this function
# to give us ability to change the output format.
#############################################################################
sub output_hash {
	if ($l0pht_fmt == 1) {
		print "$_[0]:$_[1]:\n";
		return;
	}
	elsif ($bVectors) {
		printf("\t{\"%s\", \"%s\"},\n", $_[0], $_[1]);
		return;
	}
	my $p = $_[1];
	if ($out_uc_pass) {$p = uc $p; }
	if ($out_extras == 2)    { $p = "$u:0:".$p;}
	elsif ($out_extras == 1) { $p = "$u:".$p;}
	if (length($out_username)) { print "$out_username:"; } elsif ($bUserIDs == 1) { print "u$u:"; }
	print "$_[0]";
	if ($bFullNormal == 1) {print ":$p:";}
	elsif ($bFullNormal == 2) {print ":$_[1]";}
	print "\n";
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
	my ($pass, $orig_salt, $iter, $algo, $bytes, $pad_len, $pbkdf1, $efscrap) = @_;
	my $ipad = hmac_pad($pass, '6', $algo, $pad_len);  # 6 is \x36 for an ipad
	my $opad = hmac_pad($pass, '\\', $algo, $pad_len); # \ is \x5c for an opad
	my $final_out=""; my $i=1;
	my $slt;
	while (length($final_out) < $bytes) {
		$slt = $orig_salt;
		if (!defined($pbkdf1) || !$pbkdf1) { $slt .= Uint32BERaw($i); $i += 1; }
		no strict 'refs';
		$slt = &$algo($opad.&$algo($ipad.$slt));
		my $out;
		if (!defined($pbkdf1) || !$pbkdf1) { $out = $slt; }
		for (my $x = 1; $x < $iter; $x += 1) {
			$slt = &$algo($opad.&$algo($ipad.$slt));
			if (!defined($pbkdf1) || !$pbkdf1) {
				$out ^= $slt;
				if (defined($efscrap) && $efscrap) {
					$slt = $out;
				}
			}
		}
		use strict;
		if (defined($pbkdf1) && $pbkdf1) {  $out = $slt; }
		if (length($final_out)+length($out) > $bytes) {
			$out = substr($out, 0, $bytes-length($final_out));
		}
		$final_out .= $out;
	}
	return $final_out;
}
sub pp_pbkdf2_hex {
	my ($pass, $slt, $iter, $algo, $bytes, $pad_len, $pbkdf1) = @_;
	return unpack("H*",pp_pbkdf2($pass,$slt,$iter,$algo,$bytes,$pad_len,$pbkdf1));
}

#############################################################################
# pure perl crc32 using table lookup, and 'restart' values.
#    crc32("test this") == crc32(" this", crc32("test"));
#############################################################################
my @crc32_tab = ();
my $crc32_tab_init = 0;

sub init_crc32_tab {
	if (defined($crc32_tab_init) &&  $crc32_tab_init == 1) { return; }
	$crc32_tab_init = 1;
	my $i; my $j; my $byte; my $crc; my $mask;

	for ($byte = 0; $byte <= 255; $byte++) {
		$crc = $byte;
		for ($j = 7; $j >= 0; $j--) {
			$mask = -($crc & 1);
			$crc = ($crc >> 1) ^ (0xEDB88320 & $mask);
		}
		$crc32_tab[$byte] = $crc & 0xffffffff;
	}
}

sub crc32 {
	my $msg = $_[0];
	my $i; my $j; my $byte; my $crc; my $mask;

	init_crc32_tab();	# note, only init's 1 time.
	if (defined($_[1])) {
		$crc = $_[1]^0xFFFFFFFF;
	} else {
		$crc = 0xFFFFFFFF;
	}
	$i = 0;
	while ($i < length($msg)) {
		$byte = ord(substr($msg, $i, 1));
		$crc = ($crc >> 8) ^ $crc32_tab[($crc ^ $byte) & 0xFF];
		++$i;
	}
	return ~ $crc;
}
#############################################################################
# the Crypt::ECB padding interface changed at v2.00 and is not compatible.
# we have to handle this correctly by detecting version, and returning
# proper data for the version being used
#############################################################################
sub ecb_padding_none {
	require Crypt::ECB;
	if (Crypt::ECB->VERSION*1.0 >= 2.00) { return 'none'; }
	import Crypt::ECB qw(PADDING_NONE);
	return PADDING_NONE();
}
#############################################################################
# these functions will encode words 'properly', or at least try to, based upon
# things like -utf8 mode, and possible MS code pages understood by JtR.
#############################################################################
sub ms_word_encode_uc {
	my $s = uc($_[0]);
	if ($arg_codepage eq "UTF-8") {
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
	if ($arg_codepage && $arg_codepage ne "UTF-8") {
		$s = encode($arg_codepage, $_[0]);
	}
	return $s;
}
# sets parity bit to odd. 'truncates' chars to 7 bit before computing odd parity.
sub str_odd_parity {
	my $i;
	my $s = $_[0];
	for ($i = 0; $i < length($s); $i++) {
		my $b = ord(substr($s, $i, 1))&0x7F; #strip off high bit.
		my $b_7bit = $b;
		my $c = 0;
		while ($b) {
			if ($b & 1) { $c++; }
			$b >>= 1;
		}
		if ($c & 1) {
			substr($s, $i, 1) = chr($b_7bit); # already odd
		} else {
			substr($s, $i, 1) = chr($b_7bit+0x80);
		}
	}
	return $s;
}
# sets parity bit to even. 'truncates' chars to 7 bit before computing even parity.
sub str_even_parity {
	my $i;
	my $s = $_[0];
	for ($i = 0; $i < length($s); $i++) {
		my $b = ord(substr($s, $i, 1))&0x7F; #strip off high bit.
		my $b_7bit = $b;
		my $c = 0;
		while ($b) {
			if ($b & 1) { $c++; }
			$b >>= 1;
		}
		if ( ($c & 1) == 0) {
			substr($s, $i, 1) = chr($b_7bit); # already even
		} else {
			substr($s, $i, 1) = chr($b_7bit+0x80);
		}
	}
	return $s;
}
# str_force_length(str, len, padd);  does padding to proper len (or truncation).
sub str_force_length_pad {
	my $str = $_[0];
	while (length($str) < $_[1]) { $str .= $_[2]; }
	$str = substr($str, 0, $_[1]);
	return $str;
}
# every byte of the string has its bits put into reverse order.
# vnc does this for some reason. But I put into a function so if
# needed again, we can do this.
sub str_reverse_bits_in_bytes {
	my $i;
	my $s = $_[0];
	for ($i = 0; $i < length($s); $i++) {
		my $b = ord(substr($s, $i, 1));
		$b = ($b & 0xF0) >> 4 | ($b & 0x0F) << 4;
		$b = ($b & 0xCC) >> 2 | ($b & 0x33) << 2;
		$b = ($b & 0xAA) >> 1 | ($b & 0x55) << 1;
		substr($s, $i, 1) = chr($b);
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
# This function does phpass/WordPress algorithm.
#############################################################################
sub phpass_hash {
	my ($pw, $cost, $salt) = @_;
	$cost = 1<<$cost;
	my $h = md5($salt.$pw);
	while ($cost-- > 0) {
		$h = md5($h.$pw);
	}
	return $h;
}
# this helper converts 11 into 9, 12 into A, 13 into B, etc. This is the byte
# signature for phpass, which ends up being 1<<num (num being 7 to 31)
sub to_phpbyte {
	if ($_[0] <= 11) {
		return 0+($_[0]-2);
	}
	return "A"+($_[0]-12);
}


#############################################################################
# this function is 'like' the length($s) function, BUT it has special
# processing needed for UTF-16 formats.  The problem is that 4-byte UTF-8
# end up requiring 4 bytes of UTF-16 (using a surrogate), while up to 3-byte
# UTF-8 only require 2 bytes. We have assumption that 1 UTF-8 char is 2 bytes
# long. So if we find 4-byte characters used for a single UTF-8 char, then we
# have to say it is 2 characters long.
#############################################################################
sub utf16_len {
	my $base_len = length($_[0]);
	if ($arg_codepage ne "UTF-8") { return $base_len; }
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
		$f = lc $f;
		$f =~ s/-/_/g;
		if ($f ne "dynamic") {
			reset_out_vars();
			no strict 'refs';
			my $hash = &$f("password", word_encode("password"));
			use strict;
			$cnt += 1;
			if (defined($hash) && length($hash) > 4) {
				output_hash($hash, "password", word_encode("password"));
			}
		}
	}
	# now test all 'simple' dyna which we have defined (number only)
	for (my $i = 0; $i < 10000; $i += 1) {
		my $f = dynamic_compile($i);
		$f = lc $f;
		if (defined(&{$f})) {
			reset_out_vars();
			no strict 'refs';
			my $hash = &$f("password", word_encode("password"));
			use strict;
			$cnt += 1;
			if (defined($hash) && length($hash) > 4) {
				output_hash($hash, "password", word_encode("password"));
			}
		}
	}
	print STDERR "\nAll formats were able to be run ($cnt total formats). All CPAN modules installed\n";
}

sub gen_all {
	$u = 1;
	$arg_hidden_cp = "iso-8859-1";
	srand(666);
	foreach my $f (@funcs) {
		$f = lc $f;
		$f =~ s/-/_/g;
		if ($f ne "dynamic") {
			reset_out_vars();
			no strict 'refs';
			my $hash = &$f($_[0], word_encode($_[0]));
			use strict;
			if (defined($hash) && length($hash) > 4) {
				output_hash($hash, $_[0], word_encode($_[0]));
			}
		}
	}
	# now test all 'simple' dyna which we have defined (number only)
	for (my $i = 0; $i < 10000; $i += 1) {
		my $f = dynamic_compile($i);
		$f = lc $f;
		if (defined(&{$f})) {
			reset_out_vars();
			no strict 'refs';
			my $hash = &$f($_[0], word_encode($_[0]));
			use strict;
			if (defined($hash) && length($hash) > 4) {
				output_hash($hash, $_[0], word_encode($_[0]));
			}
		}
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
# this will return the same LE formated buffer as 'uint64_t i' would on Intel
sub Uint64LERaw {
	my $i = $_[0];
	return chr($i&0xFF).chr(($i>>8)&0xFF).chr(($i>>16)&0xFF).chr(($i>>24)&0xFF).chr(($i>>32)&0xFF).chr(($i>>40)&0xFF).chr(($i>>48)&0xFF).chr(($i>>56)&0xFF);
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
#   into raw before it is later used.  If using a var length salt, we still can provide abs
#   hex salt string, we just have to append HEX= to the salt. So HEX=303132333434 would
#   give us a salt of 012344
# the 3rd param (optional), is the character set.  @chrAsciiTextNum is default.
############################################################################################
sub get_salt {
	my $len = $_[0];
	my $randlen = 0;
	if ($len < 0) { $randlen = 1; $len *= -1; }
	my $aslen = $len;
	my @chr = ();
	my $chrset_arg = 1;
	if (defined $_[1] && $_[1]+0 eq $_[1]) {
		$aslen = $_[1];
		$chrset_arg = 2;
	}
	@chr = defined($_[$chrset_arg]) ? @{$_[$chrset_arg]} : @chrAsciiTextNum;
	if (defined $argsalt && length ($argsalt)==$aslen*2 && length(pack("H*",$argsalt))==$aslen) {
		$argsalt = pack("H*",$argsalt);
	} elsif (defined $argsalt && substr($argsalt, 0, 4) eq "HEX=") {
		$argsalt = pack("H*",substr($argsalt,4));
	}
	if (defined $argsalt && ($aslen == -1 || ($aslen < -1 && length($argsalt) <= -1*$aslen) || length ($argsalt)==$aslen || ($randlen == 1 && length($argsalt) <= $len)) ) {
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
	if (defined $argcontent && length ($argcontent)==$len*2 && length(pack("H*",$argcontent))==$len) {
		return pack("H*",$argcontent);
	} elsif (defined $argcontent && substr($argcontent, 0, 4) eq "HEX=") {
		return pack("H*",substr($argcontent, 4));
	}
	if (defined $argcontent && ($aslen == -1 || ($aslen < -1 && length($argcontent) <= -1*$aslen) || length ($argcontent)==$aslen  || ($randlen == 1 && length($argcontent) <= $len)) ) {
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
sub get_username {
	my $len = $_[0];
	if (defined ($arguser) && length($arguser) <= abs($len)) {
		return ($arguser);
	}
	return randusername($len);
}
sub get_loops {
	if ($arg_loops != -1) { return $arg_loops; }
	return $_[0];
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
	my $ret = encode_base64($_[0], "");
	$ret =~ s/\+/./g;
	chomp $ret;
	return $ret;
}
# helper function for nsldap and nsldaps
sub base64 {
	my $ret = encode_base64($_[0], "");
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
# required by the ns hash.  base64 did not work.
sub ns_base64_2 {
	my $ret = "";
	my $n; my @ha = split(//,$h);
	for ($i = 0; $i < $_[0]; ++$i) {
		# the first one gets some unitialized at times..  Same as the fix in ns_base64
		#$n = ord($ha[$i*2+1]) | (ord($ha[$i*2])<<8);
		$n = ord($ha[$i*2])<<8;
		if (@ha > $i*2+1) { $n |= ord($ha[$i*2+1]); }
		$ret .= "$ns_i64[($n>>12)&0xF]";
		$ret .= "$ns_i64[($n>>6)&0x3F]";
		$ret .= "$ns_i64[$n&0x3F]";
	}
	return $ret;
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
	return base64($bin);
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
	return Crypt::UnixCrypt_XS::crypt($_[1], $salt);
}
sub bigcrypt {
	require Crypt::UnixCrypt_XS;
	if (length($_[0]) > 8) {
		my $ret = "";
		$salt = get_salt(2,2,\@i64);
		my $pw = $_[0];
		while (length($pw)%8!= 0) { $pw .= "\0"; }
		my $lastlimb = Crypt::UnixCrypt_XS::crypt(substr($pw,0,8), $salt);
		$ret = $lastlimb;
		$pw = substr($pw,8);
		while (length($pw)) {
			$lastlimb = Crypt::UnixCrypt_XS::crypt(substr($pw,0,8), substr($lastlimb,2,2));
			$ret .= substr($lastlimb, 2);
			$pw = substr($pw,8);
		}
		return $ret;
	}
	return descrypt(@_);
}
sub bsdicrypt {
	require Crypt::UnixCrypt_XS;
	my $block = "\0\0\0\0\0\0\0\0";
	my $rounds = 725;
	$salt = get_salt(4,4,\@i64);
	my $h = Crypt::UnixCrypt_XS::crypt_rounds(Crypt::UnixCrypt_XS::fold_password($_[1]),$rounds,Crypt::UnixCrypt_XS::base64_to_int24($salt),$block);
	return "_".Crypt::UnixCrypt_XS::int24_to_base64($rounds).$salt.Crypt::UnixCrypt_XS::block_to_base64($h);
}
sub md5crypt {
	$out_username = get_username($arg_maxuserlen);
	$salt = get_salt(-8);
	return md5crypt_hash($_[1], $salt, "\$1\$");
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
	$out_username = get_username($arg_maxuserlen);
	my $fixed_pass = bfx_fix_pass($_[1]);
	require Crypt::Eksblowfish::Bcrypt;
	$salt = get_salt(16,16,\@i64);
	my $cost = sprintf("%02d", get_loops(5));
	my $hash = Crypt::Eksblowfish::Bcrypt::bcrypt_hash({key_nul => 1, cost => $cost, salt => $salt, }, $fixed_pass);
	return "\$2x\$${cost}\$".Crypt::Eksblowfish::Bcrypt::en_base64($salt).Crypt::Eksblowfish::Bcrypt::en_base64($hash);
}
sub bcrypt {
	$out_username = get_username($arg_maxuserlen);
	require Crypt::Eksblowfish::Bcrypt;
	$salt = get_salt(16,16,\@i64);
	my $cost = sprintf("%02d", get_loops(5));
	my $hash = Crypt::Eksblowfish::Bcrypt::bcrypt_hash({key_nul => 1, cost => $cost, salt => $salt, }, $_[1]);
	return "\$2a\$${cost}\$".Crypt::Eksblowfish::Bcrypt::en_base64($salt).Crypt::Eksblowfish::Bcrypt::en_base64($hash);
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
		return "+"._bfegg_en_base64($h);
	}
	return undef;
}
sub raw_md5 {
	$out_username = get_username($arg_maxuserlen);
	return md5_hex($_[1]);
}
sub raw_md5u {
	$out_username = get_username($arg_maxuserlen);
	return md5_hex(encode("UTF-16LE",$_[0]));
}
sub raw_sha1 {
	$out_username = get_username($arg_maxuserlen);
	return sha1_hex($_[1]);
}
sub raw_sha1u {
	$out_username = get_username($arg_maxuserlen);
	return sha1_hex(encode("UTF-16LE",$_[0]));
}
sub raw_sha256 {
	$out_username = get_username($arg_maxuserlen);
	return sha256_hex($_[1]);
}
sub cisco4 {
	return "\$cisco4\$".base64_wpa(sha256($_[1]));
}
sub raw_sha224 {
	$out_username = get_username($arg_maxuserlen);
	return sha224_hex($_[1]);
}
sub raw_sha384 {
	$out_username = get_username($arg_maxuserlen);
	return sha384_hex($_[1]);
}
sub raw_sha512 {
	$out_username = get_username($arg_maxuserlen);
	return sha512_hex($_[1]);
}
sub cisco8 {
	$salt = get_salt(14,14,\@i64);
	my $h = pp_pbkdf2($_[1],$salt,20000,"sha256",32,64);
	my $s = base64_wpa($h);
	return "\$8\$$salt\$$s";
}
sub cisco9 {
	require Crypt::ScryptKDF;
	import Crypt::ScryptKDF qw(scrypt_raw);
	$salt = get_salt(14,14,\@i64);
	my $h = scrypt_raw($_[1],$salt,16384,1,1,32);
	my $s = base64_wpa($h);
	return "\$9\$$salt\$$s";
}
sub raw_tiger {
	return "\$tiger\$".tiger_hex($_[1]);
}
sub raw_whirlpool {
	# note we only handle whirlpool, not whirlpool0 or whirlpool1
	return "\$whirlpool\$".whirlpool_hex($_[1]);
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
	return "\$3\$$salt\$$out";
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
	return "\$4\$$salt\$$out";
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
	return "\$3\$$salt\$$out";
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
	return "\$4\$$salt\$$out";
}

sub mscash {
	$out_username = get_salt(19,-19,\@userNames);
	return md4_hex(md4(encode("UTF-16LE",$_[0])).encode("UTF-16LE", lc($out_username)));
}

sub krb5_18 {
	# algorith gotten by working with kbr5-1.13 sources, and using lots of dump_stuff_msg()
	# calls to figure out what was happening. The constant being used here was found by
	# dump_stuff_msg() calls, and appears to be the end result that is used.
	$salt = get_salt(12,-64);
	my $pbk = pp_pbkdf2($_[0], $salt, 4096, "sha1",32,64);
	require Crypt::Cipher::AES;
	my $crypt = Crypt::Cipher::AES->new($pbk);
	# 6b65726265726f737b9b5b2b93132b93 == 'kerberos' and 8 other bytes
	my $output1 = $crypt->encrypt(pack("H*","6b65726265726f737b9b5b2b93132b93"));
	my $output2 = $crypt->encrypt($output1);
	return "\$krb18\$$salt\$".unpack("H*",$output1).unpack("H*",$output2);
}
sub lp {
	$salt = get_salt(32, -32, \@userNames);
	my $pbk = pp_pbkdf2($_[0], $salt, 500, "sha256", 32, 64);
	require Crypt::Cipher::AES;
	my $crypt = Crypt::Cipher::AES->new($pbk);
	$h = unpack("H*", $crypt->encrypt("lastpass rocks\x02\x02"));
	return "\$lp\$$salt\$$h";
}
sub lastpass {
	my $iter = get_loops(500);
	$salt = get_salt(32, -32, \@userNames);
	my $pbk = pp_pbkdf2($_[0], $salt, $iter, "sha256", 32, 64);
	require Crypt::Cipher::AES;
	require Crypt::CBC;
	my $dat = $salt;
	my $iv = "\0"x16;
	my $crypt = Crypt::CBC->new(-literal_key => 1, -key => $pbk, -iv => $iv, -cipher => "Crypt::Cipher::AES", -header => 'none', -padding => 'null');
	$h = base64($crypt->encrypt($dat));
	return "\$lastpass\$$salt\$$iter\$$h";
}

sub odf {
	my $iv; my $content;
	$salt = get_salt(16);
	$iv =  get_iv(8);
	my $itr = get_loops(1024);
	$content = get_content(-1024, -4095);
	my $s = sha1($_[0]);
	my $key = pp_pbkdf2($s, $salt, $itr, "sha1", 16,64);
	require Crypt::Cipher::Blowfish;
	require Crypt::Mode::CFB;
	my $crypt = Crypt::Mode::CFB->new('Blowfish');
	my $output = $crypt->decrypt($content, $key, $iv);
	$s = sha1($output);
	return "\$odf\$*0*0*$itr*16*".unpack("H*",$s)."*8*".unpack("H*",$iv)."*16*".unpack("H*",$salt)."*0*".unpack("H*",$content);
}
sub odf_1 {
	# odf cipher type 1 (AES instead of blowfish, and some sha256, pbkdf2 is still sha1, but 32 byte of output)
	my $iv; my $content;
	$salt = get_salt(16);
	$iv =  get_iv(16);
	my $itr = get_loops(1024);
	$content = get_content(-1024, -4095);
	while (length($content)%16 != 0) { $content .= "\x0" } # must be even 16 byte padded.
	my $s = sha256($_[0]);
	my $key = pp_pbkdf2($s, $salt, $itr, "sha1", 32,64);
	require Crypt::Cipher::AES;
	require Crypt::CBC;
	# set -padding to 'none'. Otherwise a Crypt::CBC->decrypt() padding removal will bite us, and possibly strip off bytes.
	my $crypt = Crypt::CBC->new(-literal_key => 1, -key => $key, -iv => $iv, -cipher => "Crypt::Cipher::AES", -header => 'none', -padding => 'none');
	my $output = $crypt->decrypt($content);
	$s = sha256($output);
	return "\$odf\$*1*1*$itr*32*".unpack("H*",$s)."*16*".unpack("H*",$iv)."*16*".unpack("H*",$salt)."*0*".unpack("H*",$content);
}
# the inverse of the DecryptUsingSymmetricKeyAlgorithm() in the JtR office format
sub _office_2k10_EncryptUsingSymmetricKeyAlgorithm {
	my ($key, $data, $len, $keysz) = @_;
	# we handle ALL padding.
	while (length($data)<$len) {$data.="\0";} $data = substr($data,0,$len);
	while (length($key)<$keysz) {$key.="\0";} $key = substr($key,0,$keysz);
	require Crypt::Cipher::AES;
	require Crypt::CBC;
	my $crypt = Crypt::CBC->new(-literal_key => 1, -keysize => $keysz, -key => $key, -iv => $salt, -cipher => "Crypt::Cipher::AES", -header => 'none', -padding => 'none');
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
	my $spincount = get_loops(100000);
	my $hash1; my $hash2;
	_office_2k10_GenerateAgileEncryptionKey($_[1], $spincount, \&sha1, $hash1, $hash2);
	my $encryptedVerifier = _office_2k10_EncryptUsingSymmetricKeyAlgorithm($hash1, $randdata, 16, 128/8);
	my $encryptedVerifierHash = _office_2k10_EncryptUsingSymmetricKeyAlgorithm($hash2, sha1($randdata), 32, 128/8);
	return "\$office\$*2010*$spincount*128*16*".unpack("H*",$salt)."*".unpack("H*",$encryptedVerifier)."*".unpack("H*",$encryptedVerifierHash);
}
sub office_2013 {
	$salt = get_salt(16);
	my $randdata = get_iv(16);
	my $spincount = get_loops(100000);
	my $hash1; my $hash2;
	_office_2k10_GenerateAgileEncryptionKey($_[1], $spincount, \&sha512, $hash1, $hash2);
	my $encryptedVerifier = _office_2k10_EncryptUsingSymmetricKeyAlgorithm($hash1, $randdata, 16, 256/8);
	my $encryptedVerifierHash = _office_2k10_EncryptUsingSymmetricKeyAlgorithm($hash2, sha512($randdata), 32, 256/8);
	return "\$office\$*2013*$spincount*256*16*".unpack("H*",$salt)."*".unpack("H*",$encryptedVerifier)."*".unpack("H*",$encryptedVerifierHash);
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
	require Crypt::Cipher::AES;
	my $crypt = Crypt::Cipher::AES->new($h);
	my $hash = $crypt->encrypt(substr(sha1(substr($crypt->decrypt($randdata),0,16)),0,16));
	return "\$office\$*2007*20*128*16*".unpack("H*",$salt)."*".unpack("H*",$randdata)."*".unpack("H*",$hash)."00000000";
}
sub rawmd2 {
	require Digest::MD2;
	import Digest::MD2 qw(md2);
	return "\$md2\$".unpack("H*",md2($_[1]));
}
sub mongodb {
	$salt = get_salt(16,16,\@chrHexLo);
	my $user = get_username(128);
	my $type=1;
	if (substr($salt, 2, 1) eq '2') {$type=0;}
	if(defined($argmode)) {$type=$argmode;}
	if ($type==0) {
		$h = md5_hex($user . ":mongo:" . $_[1]);
		return "\$mongodb\$0\$$user\$$h";
	}
	$h = md5_hex($salt.$user.md5_hex($user . ":mongo:" . $_[1]));
	return "\$mongodb\$1\$$user\$$salt\$$h";
}
sub mysqlna {
	$salt = get_salt(20);
	$h = sha1($salt.sha1(sha1($_[1]))) ^ sha1($_[1]);
	return "\$mysqlna\$".unpack("H*",$salt)."*".unpack("H*",$h);
}
sub o5logon {
	$salt = get_salt(10);
	my $crpt = get_content(32);
	my $plain = get_iv(8) .  "\x08\x08\x08\x08\x08\x08\x08\x08";
	my $key = sha1($_[1].$salt) . "\0\0\0\0";
	require Crypt::Cipher::AES;
	require Crypt::CBC;
	my $iv = substr($crpt, 16, 16);
	my $crypt = Crypt::CBC->new(-literal_key => 1, -key => $key, -keysize => 24, -iv => $iv, -cipher => 'Crypt::Cipher::AES', -header => 'none');
	$crpt .= $crypt->encrypt($plain);
	$crpt = substr($crpt, 0, 48);
	$crpt = uc unpack("H*",$crpt);
	$salt = uc unpack("H*",$salt);
	return "\$o5logon\$$crpt*$salt";
}
sub postgres {
	my $user = 'postgres';
	$salt = get_salt(4);
	if (substr($salt,2,1) eq "1") {$user = get_username(64); }
	$h = md5_hex(md5_hex($_[1], $user).$salt);
	$salt = unpack("H*", $salt);
	return "\$postgres\$$user*$salt*$h";
}
sub pst {
	my $pw = $_[0];
	if (length($pw)>8) {$pw = substr($pw, 0, 8); }
	return "\$pst\$".unpack("H*", Uint32BERaw(crc32($pw, 0xffffffff)^0xffffffff));
}
sub raw_blake2 {
	require Digest::BLAKE2;
	import Digest::BLAKE2 qw(blake2b);
	return "\$BLAKE2\$".unpack("H*",blake2b($_[1]));
}
sub rawsha3_224 {
	require Digest::SHA3;
	import Digest::SHA3 qw(sha3_224);
	return unpack("H*",sha3_224($_[1]));
}
sub rawsha3_256 {
	require Digest::SHA3;
	import Digest::SHA3 qw(sha3_256);
	return unpack("H*",sha3_256($_[1]));
}
sub rawsha3_384 {
	require Digest::SHA3;
	import Digest::SHA3 qw(sha3_384);
	return unpack("H*",sha3_384($_[1]));
}
sub rawsha3_512 {
	require Digest::SHA3;
	import Digest::SHA3 qw(sha3_512);
	return unpack("H*",sha3_512($_[1]));
}
sub raw_keccak {
	require Digest::Keccak;
	import Digest::Keccak qw(keccak_512);
	return "\$keccak\$".unpack("H*",keccak_512($_[1]));
}
sub raw_keccak256 {
	require Digest::Keccak;
	import Digest::Keccak qw(keccak_256);
	return "\$keccak256\$".unpack("H*",keccak_256($_[1]));
}
sub leet {
	my $u = get_username($arg_maxuserlen);
	my $h = unpack("H*", sha512($_[0].$u) ^ whirlpool($u.$_[0]));
	$out_username = $u;
	return "$u\$$h";
}
sub siemens_s7 {
	$salt = get_salt(20);
	$h = Digest::SHA::hmac_sha1($salt, sha1($_[1]));
	$salt = unpack("H*",$salt);
	$h = unpack("H*",$h);
	return "\$siemens-s7\$1\$$salt\$$h";
}
sub ssha512 {
	$salt = get_salt(8, -16);
	$h = sha512($_[1].$salt);
	return "{ssha512}".base64($h.$salt);
}
sub tcp_md5 {
	$salt = get_salt(32);
	$h = md5($salt.$_[1]);
	$h = unpack("H*",$h);
	$salt = unpack("H*",$salt);
	return "\$tcpmd5\$$salt\$$h";
}
sub known_hosts {
	# simple hmac-sha1, BUT salt and pw are used in wrong order, and password is usually some host or IP, BUT
	# it does not matter if it is an IP or not. Still works fine regardless.
	$salt = get_salt(20);
	$h = Digest::SHA::hmac_sha1($_[1], $salt);
	$salt = base64($salt);
	$h = base64($h);
	return "\$known_hosts\$|1|$salt|$h";
}
sub strip {
	$salt = get_salt(16);
	my $iv = get_iv(16);
	my $key = pp_pbkdf2($_[0], $salt, 4000, \&sha1, 32, 64);
	# this is the decrypted data from JtR's openwall password test string.
	my $dat = "\x04\0\x01\x01\x10\x40\x20\x20\x1a\x4f\xed\x2b\0\0\0\x2d\0\0\0\0\0\0\0\0\0\0\0\x25\0\0\0\x04\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\0\x07\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x1a\x4f\xed\x2b\x00\x2d\xe2\x24\x05\x00\x00\x00\x0a\x03\xbe\x00\x00\x00\x00\x2c\x03\xeb\x03\xe6\x03\xe1\x03\xdc\x03\xd7\x03\xd2\x03\xcd\x03\xc8\x03\xc3\x03\xbe";
	$dat .= "\0"x828;
	$dat .= "\x00\x2b\x29\x00\x00\x00\x29\x27\x00\x00\x00\x27\x25\x00\x00\x00\x26\x23\x00\x00\x00\x24\x21\x00\x00\x00\x22\x1f\x00\x00\x00\x21\x1d\x00\x00\x00\x18\x1a\x00\x00\x00\x0d\x12\x00\x00\x00\x0a\x08";
	require Crypt::Cipher::AES;
	require Crypt::CBC;
	my $crypt = Crypt::CBC->new(-literal_key => 1, -key => $key, -keysize => 32, -iv => $iv, -cipher => 'Crypt::Cipher::AES', -header => 'none');
	$h = substr($crypt->encrypt($dat), 0, 32+960);
	$salt = unpack("H*",$salt);
	$h = unpack("H*",$h);
	$iv = unpack("H*", $iv);
	return "\$strip\$*$salt$h$iv";
}
sub _tc_build_buffer {
	# build a special TC buffer.  448 bytes, 2 spots have CRC32.  Lots of null, etc.
	my $buf = 'TRUE'."\x00\x05\x07\x00". "\x00"x184 . randstr(64) . "\x00"x192;
	my $crc1 = crc32(substr($buf, 192, 256));
	substr($buf, 8, 4) = Uint32BERaw($crc1);
	my $crc2 = crc32(substr($buf, 0, 188));
	substr($buf, 188, 4) = Uint32BERaw($crc2);
	return $buf;
}
# I looked high and low for a Perl implementation of AES-256-XTS and
# could not find one.  This may be the first implementation in Perl, ever.
sub _aes_xts {
	# a dodgy, but working XTS implementation. (encryption). To do decryption
	# simply do $cipher1->decrypt($tmp) instead of encrypt. That is the only diff.
	# switched to do both 256 and 128 bit AES ($_[3]) and can also handle decryption
	# and not just encryption ($_[4] set to 1 will decrypt)
	my $bytes = 32; # AES 256
	if ($_[3] == 128) { $bytes = 16; }
	my $key1 = substr($_[0],0,$bytes); my $key2 = substr($_[0],$bytes,$bytes);
	my $d; my $c = $_[1]; # $c=cleartext MUST be a multiple of 16.
	my $num = length($c) / 16;
	my $t = $_[2];	# tweak (must be provided)
	my $decr = $_[4];
	if (!defined($decr)) { $decr = 0; }
	require Crypt::Cipher::AES;
	my $cipher1 = new Crypt::Cipher::AES($key1);
	my $cipher2 = new Crypt::Cipher::AES($key2);
	$t = $cipher2->encrypt($t);
	for (my $cnt = 0; ; ) {
		my $tmp = substr($c, 16*$cnt, 16);
		$tmp ^= $t;
		if ($decr != 0) {
			$tmp = $cipher1->decrypt($tmp);
		} else {
			$tmp = $cipher1->encrypt($tmp);
		}
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
sub _tc_aes_128_xts {
	# a dodgy, but working XTS implementation. (encryption). To do decryption
	# simply do $cipher1->decrypt($tmp) instead of encrypt. That is the only diff.
	my $key1 = substr($_[0],0,16); my $key2 = substr($_[0],16,16);
	my $d; my $c = $_[1]; # $c=cleartext MUST be a multiple of 16.
	my $num = length($c) / 16;
	my $t = $_[2];	# tweak (must be provided)
	my $decr = $_[3];
	if (!defined($decr)) { $decr = 0; }
	require Crypt::Cipher::AES;
	my $cipher1 = new Crypt::Cipher::AES($key1);
	my $cipher2 = new Crypt::Cipher::AES($key2);
	$t = $cipher2->encrypt($t);
	for (my $cnt = 0; ; ) {
		my $tmp = substr($c, 16*$cnt, 16);
		$tmp ^= $t;
		if ($decr != 0) {
			$tmp = $cipher1->decrypt($tmp);
		} else {
			$tmp = $cipher1->encrypt($tmp);
		}
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
	$h = _aes_xts($h,$d,$tweak,256);
	return "truecrypt_RIPEMD_160\$".unpack("H*",$salt).unpack("H*",$h);
}
sub tc_sha512 {
	$salt = get_salt(64);
	my $h = pp_pbkdf2($_[0], $salt, 1000, \&sha512, 64, 128);
	my $d = _tc_build_buffer();
	my $tweak = "\x00"x16;	#first block of file
	$h = _aes_xts($h,$d,$tweak,256);
	return "truecrypt_SHA_512\$".unpack("H*",$salt).unpack("H*",$h);
}
sub tc_whirlpool {
	$salt = get_salt(64);
	my $h = pp_pbkdf2($_[0], $salt, 1000, \&whirlpool, 64, 64);	# note, 64 byte ipad/opad (oSSL is buggy?!?!)
	my $d = _tc_build_buffer();
	my $tweak = "\x00"x16;	#first block of file
	$h = _aes_xts($h,$d,$tweak,256);
	return "truecrypt_WHIRLPOOL\$".unpack("H*",$salt).unpack("H*",$h);
}
sub dahua {
	my $h = md5($_[1]);
	# compressor
	my @a = split(//, $h);
	$h = "";
	for (my $i = 0; $i < 16; $i += 2) {
		my $x = (ord($a[$i])+ord($a[$i+1])) % 62;
		if ($x < 10) { $x += 48; }
		elsif ($x < 36) { $x += 55; }
		else { $x += 61; }
		$h .= chr($x);
	}
	return "\$dahua\$$h";
}
sub ripemd_128 {
	return "\$ripemd\$".ripemd128_hex($_[0]);
}
sub ripemd_160 {
	return "\$ripemd\$".ripemd160_hex($_[0]);
}
sub rsvp {
	$salt = get_salt(16, -8192);
	my $mode = 1;
	my $h;
	if (defined $argmode) {$mode=$argmode;} # 1 or 2
	# note, password and salt are 'reversed' in the hmac.
	if ($mode == 1) {
		$h = _hmacmd5($_[0], $salt);
	} else {
		$h = _hmacsha1($_[0], $salt);
	}
	return "\$rsvp\$$mode\$".unpack("H*",$salt).'$'.unpack("H*",$h);
}
sub sap_h {
	$salt = get_salt(12, -16);
	my $mode = "sha1";
	my $iter = get_loops(1024);
	if (defined $argmode) {$mode=$argmode;} # must be sha1 sha256 sha384 or sha512
	my $modestr;
	if ($mode eq "sha1") { $modestr = "sha"; }
	elsif ($mode eq "sha256") { $modestr = "SHA256"; }
	elsif ($mode eq "sha384") { $modestr = "SHA384"; }
	elsif ($mode eq "sha512") { $modestr = "SHA512"; }
	else { print STDERR "invalid mode used for SAP-H  [$mode] is not valid\n"; exit 0; }
	no strict 'refs';
	my $h = &$mode($_[0].$salt);
	for (my $i = 1; $i < $iter; $i++) {
		$h = &$mode($_[0].$h);
	}
	use strict;
	return "{x-is$modestr, $iter}".base64($h.$salt);
}
sub bb_es10 {
	# 101x sha512, Blackberry, es10 server.
	$salt = get_salt(8);
	$h = sha512($_[1].$salt);
	for (my $i = 0; $i < 99; $i++) {
		$h = sha512($h);
	}
	$h = uc unpack("H*",$h);
	return "\$bbes10\$$h\$$salt";
}
sub citrix_ns10 {
	$salt = get_salt(8, 8, \@chrHexLo);
	$h = sha1($salt.$_[0]."\0");
	return "1$salt".unpack("H*",$h);
}
sub chap {
	$salt = get_salt(16);
	my $h = md5("\0" . $_[1] . $salt);
	$salt = unpack("H*",$salt);
	$h = unpack("H*",$h);
	return "\$chap\$0*$salt*$h";
}
sub fortigate {
	$salt = get_salt(12);
	$h = sha1($salt.$_[1]."\xa3\x88\xba\x2e\x42\x4c\xb0\x4a\x53\x79\x30\xc1\x31\x07\xcc\x3f\xa1\x32\x90\x29\xa9\x81\x5b\x70");
	return "AK1".base64($salt.$h);
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
	return "\$zip2\$*0*$mode*0*".unpack("H*",$salt)."*".unpack("H*",$chksum)."*$hexlen*".unpack("H*",$content)."*".substr(unpack("H*",$bin),0,20)."*\$/zip2\$";
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

	require Crypt::Cipher::AES;
	require Crypt::CBC;
	my $crypt = Crypt::CBC->new(-literal_key => 1, -key => $key, -keysize => 16, -iv => $iv, -cipher => 'Crypt::Cipher::AES', -header => 'none');
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
		my $crcs = sprintf("%08x", crc32($content));  # note, rar_fmt/rar2john F's up the byte order!! so we have to match what it expects.
		$crc = substr($crcs,6).substr($crcs,4,2).substr($crcs,2,2).substr($crcs,0,2);
		@ar = ($crc, $contentlen, unpack("H*", $content));
	} else {
		# do -hp type here.
		my $output = _gen_key_rar4($_[0], $salt, "\xc4\x3d\x7b\x00\x40\x07\x00");
		return "\$RAR3\$*0*".unpack("H*",$salt)."*".unpack("H*",substr($output,0,16));
	}
	# common final processing for -p rar (-hp returns before getting here).
	$crc = $ar[0];
	$contentlen = $ar[1];
	$content = pack("H*", $ar[2]);
	$contentpacklen = length($content) + 16-length($content)%16;
	my $output = _gen_key_rar4($_[0], $salt, $content);
	return "\$RAR3\$*1*".unpack("H*",$salt)."*$crc*$contentpacklen*$contentlen*1*".unpack("H*",substr($output,0,$contentpacklen))."*$type";
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
	if ($rndsalt == 0) {
		return '$ecryptfs$0$'.substr(unpack("H*",$h),0,16);
	}
	return '$ecryptfs$0$1$'.unpack("H*",$salt).'$'.substr(unpack("H*",$h),0,16);
}
sub sip {
	my $IPHead = "192.168." . (int(rand(253))+1) . ".";
	my $serverIP = $IPHead . (int(rand(253))+1);
	my $clientIP = $IPHead . (int(rand(253))+1);
	my $user = randstr(5, \@chrAsciiNum);
	my $realm = "asterisk";
	my $method = "REGISTER";
	my $URIpart1 = "sip";
	my $nonce = randstr(8, \@chrHexLo);
	my $uri = "$URIpart1:$clientIP";

	my $static_hash = md5_hex($method.":".$uri);
	my $dynamic_hash_data = "$user:$realm:";
	my $static_hash_data = ":$nonce:$static_hash";
	my $dyna_hash = md5_hex($dynamic_hash_data.$_[0]);
	my $h = md5_hex($dyna_hash.$static_hash_data);
	return "\$sip\$*$serverIP*$clientIP*$user*$realm*$method*$URIpart1*$clientIP**$nonce****MD5*$h";
}

sub sip_qop {
	my $IPHead = "192.168." . (int(rand(253))+1) . ".";
	my $serverIP = $IPHead . (int(rand(253))+1);
	my $clientIP = $IPHead . (int(rand(253))+1);
	my $user = randstr(5, \@chrAsciiNum);
	my $realm = "asterisk";
	my $method = "REGISTER";
	my $URIpart1 = "sip";
	my $nonce = randstr(32, \@chrHexLo);
	my $uri = "$URIpart1:$clientIP";
	my $qop = "auth";
	my $nonce_count = "00000001";
	my $cnonce = randstr(8, \@chrHexLo);

	my $static_hash = md5_hex($method.":".$uri);
	my $dynamic_hash_data = "$user:$realm:";
	my $static_hash_data = ":$nonce:$nonce_count:$cnonce:$qop:$static_hash";
	my $dyna_hash = md5_hex($dynamic_hash_data.$_[0]);
	my $h = md5_hex($dyna_hash.$static_hash_data);
	return "\$sip\$*$serverIP*$clientIP*$user*$realm*$method*$URIpart1*$clientIP**$nonce*$cnonce*$nonce_count*$qop*MD5*$h";
}

sub bitlocker {
	require Crypt::AuthEnc::CCM;
	my $itr = get_loops(1048576);
	my $salt = get_salt(16,16,\@chrHexLo);
	my $iv = get_iv(12);
	# data taken from sample test hash in JtR bitlocker format, after decrypt.
	my $data = pack("H*","9a0bd9fbcb83988509088b435f1058fd2c000000010000000320000029a9df35315149afb5613e97f48ba8efbc9f2a1fd041dd019df1db87a1a29e1f");
	my $pwd = encode("UTF-16LE", $_[1]);
	my $h = sha256($pwd); $h = sha256($h);
	# do kdf code
	my $i;
	my $last = "\0" x 32;
	for ($i = 0; $i < $itr; ++$i) {
		$last = sha256($last, $h, $salt, Uint64LERaw($i));
	}
	$h = $last;
	# end of kdf code
	print unpack("H*", $h)."\n";
	# we have the key.  we have the IV, we have the unenc data. Now we just have
	# to properly encrypt it, then return the proper hash string.

#	my $ae = Crypt::AuthEnc::CCM->new("AES", $h, $iv, $data, $tag_len, $pt_len);
#	my $ct = $ae->encrypt_add('data1');
#	$ct .= $ae->encrypt_add('data2');
#	$ct .= $ae->encrypt_add('data3');
#	my $tag = $ae->encrypt_done();

#	exit(0);
}

sub money_md5 {
	require Crypt::RC4;
	import Crypt::RC4 qw(RC4);
	my $pw = $_[0];
	my $i;
	my $salt = get_salt(8);
	for ($i = 0; $i < length $pw; ++$i) {
		my $c = substr($pw, $i, 1);
		if ( ord($c) >= ord('a') && ord($c) <= ord('z')) {
			 $c = chr(ord($c)-0x20);
		}
		$c = chr(ord($c) % 0x80);
		substr($pw, $i, 1) = $c;
	}
	while (length($pw) < 20) { $pw .= "\0"; }
	$pw = encode("UTF-16LE", $pw);
	my $h = md5($pw);
	my $enc = RC4($h.$salt, substr($salt, 0, 4));
	return "\$money\$0*".unpack("H*", $salt)."*".unpack("H*", $enc);
}
sub money_sha1 {
	require Crypt::RC4;
	import Crypt::RC4 qw(RC4);
	my $pw = $_[0];
	my $i;
	my $salt = get_salt(8);
	for ($i = 0; $i < length $pw; ++$i) {
		my $c = substr($pw, $i, 1);
		if ( ord($c) >= ord('a') && ord($c) <= ord('z')) {
			 $c = chr(ord($c)-0x20);
		}
		$c = chr(ord($c) % 0x80);
		substr($pw, $i, 1) = $c;
	}
	while (length($pw) < 20) { $pw .= "\0"; }
	$pw = encode("UTF-16LE", $pw);
	my $h = sha1($pw);
	my $enc = RC4(substr($h,0,16).$salt, substr($salt, 0, 4));
	return "\$money\$1*".unpack("H*", $salt)."*".unpack("H*", $enc);
}

##############################################################################
# stub functions.  When completed, move the function out of this section
##############################################################################
sub pfx {
}
sub keepass {
}
sub ike {
}
sub afs {
}
sub cq {
}
sub dmg {
}
sub dominosec {
}
#{"$encfs$192*181474*0*20*f1c413d9a20f7fdbc068c5a41524137a6e3fb231*44*9c0d4e2b990fac0fd78d62c3d2661272efa7d6c1744ee836a702a11525958f5f557b7a973aaad2fd14387b4f", "openwall"},
#{"$encfs$128*181317*0*20*e9a6d328b4c75293d07b093e8ec9846d04e22798*36*b9e83adb462ac8904695a60de2f3e6d57018ccac2227251d3f8fc6a8dd0cd7178ce7dc3f", "Jupiter"},
#{"$encfs$256*714949*0*20*472a967d35760775baca6aefd1278f026c0e520b*52*ac3b7ee4f774b4db17336058186ab78d209504f8a58a4272b5ebb25e868a50eaf73bcbc5e3ffd50846071c882feebf87b5a231b6", "Valient Gough"},
#{"$encfs$256*120918*0*20*e6eb9a85ee1c348bc2b507b07680f4f220caa763*52*9f75473ade3887bca7a7bb113fbc518ffffba631326a19c1e7823b4564ae5c0d1e4c7e4aec66d16924fa4c341cd52903cc75eec4", "Alo3San1t@nats"},
#unsigned int keySize;
#unsigned int iterations;
#unsigned int cipher;
#unsigned int saltLen;
#unsigned char salt[40];
#unsigned int dataLen;
#unsigned char data[128];
#unsigned int ivLength;
sub encfs {
	# this format sux. Skipping it :(
	my $salt = get_salt(20);
	$salt = pack("H*","f1c413d9a20f7fdbc068c5a41524137a6e3fb231");
	my $iter = 180000 + int(rand(50000));
	$iter = 181474;
	my $key_sz = 128 + 64*int(rand(3));   # 128, 192, 256
	my $data = pack("H*", "9c0d4e2b990fac0fd78d62c3d2661272efa7d6c1744ee836a702a11525958f5f557b7a973aaad2fd14387b4f");
	my $iv_len = 16;
	my $datlen = length($data);
	$key_sz = 192;
	my $chksum1 = 0;
	for (my $i = 0; $i < 4; ++$i) {
		$chksum1 = ($chksum1<<8) + ord(substr($data, $i, 1));
	}
	my $h = pp_pbkdf2($_[0], $salt,$iter,"sha1",$key_sz/8+$iv_len, 64);

	# setup iv and seed
	my $seed = $chksum1 + 1;
	my $iv = substr($h, $key_sz/8);
	for (my $i = 0; $i < 8; ++$i) {
		$iv .= chr($seed & 0xFF);
		$seed >>= 8;
	}
	$iv = substr(Digest::SHA::hmac_sha1(substr($iv,0,24), substr($h,0,$key_sz/8)), 0, 16);

	require Crypt::Cipher::AES;
	require Crypt::Mode::CFB; # Should be CFB64, not sure how to set?
	$h = substr($h, 0, 24);
	print "key=".unpack("H*",$h)."\n";
	print "iv=".unpack("H*",$iv)."\n";
	my $crypt = Crypt::Mode::CFB->new('AES');
	my $h2 = $crypt->decrypt(substr($data,4), $h, $iv);
	print unpack("H*", substr($data,4))."  ".unpack("H*", $h2)."\n";


	$salt = unpack("H*",$salt); $data = unpack("H*",$data);
	return "\$encfs\$$key_sz*$iter*0*20*$salt*$datlen*$data";
}
sub fde {
}
sub gpg {
}
sub haval_128 {
}
sub haval_256 {
	# NOTE, haval is busted in perl at this time.
	#print "u$u-haval256_3:".haval256_hex($_[0]).":$u:0:$_[0]::\n";
}
sub krb4 {
}
sub krb5 {
}
sub kwallet {
}
sub luks {
}
sub raw_skein_256 {
	# NOTE, uses v1.2 of this hash, while JtR uses v 1.3. They are NOT compatible!
#	require Digest::Skein;
#	import Digest::Skein qw(skein_256);
#	print "u$u:\$skein\$".unpack("H*",skein_256($_[1])).":$u:0:$_[0]::\n";
}
sub raw_skein_512 {
	# NOTE, uses v1.2 of this hash, while JtR uses v 1.3. They are NOT compatible!
#	require Digest::Skein;
#	import Digest::Skein qw(skein_512);
#	print "u$u:\$skein\$".unpack("H*",skein_512($_[1])).":$u:0:$_[0]::\n";
}
sub ssh {
}
sub rar5 {
}
sub pdf {
}
sub pkzip {
}
sub oldoffice {
}
sub openbsd_softraid {
}
sub openssl_enc {
}
sub openvms {
}
sub panama {
}
sub putty {
}
sub ssh_ng {
}
sub sybase_prop {
}
sub tripcode {
}
sub whirlpool0 {
}
sub whirlpool1 {
}
# New ones.
sub _7z {
}
sub axcrypt {
#formats can be:
#$axcrypt$*version*iterations*salt*wrappedkey
#$axcrypt$*version*iterations*salt*wrappedkey*key-file
#$axcrypt$*1*1337*0fd9e7e2f907f480f8af162564f8f94b*af10c88878ba4e2c89b12586f93b7802453121ee702bc362   :  Bab00nmoNCo|\|2$inge
#$axcrypt$*1*38574*ce4f58c1e85df1ea921df6d6c05439b4*3278c3c730f7887b1008e852e59997e2196710a5c6bc1813*66664a6b2074434a4520374d73592055626979204a6b755520736d6b4b20394e694a205548444320524578562065674b33202f42593d : 0v3rgo2|<fc!
#return "\$axcrypt\$*1*$iter*$salt*$h";
}
sub bks {
}
sub dmd5 {
}
sub dominosec8 {
}
sub krb5_tgs {
}
sub lotus5 {
}
sub lotus85 {
}
sub net_md5 {
}
sub net_sha1 {
}
sub netsplitlm {
}
sub oracle12c {
}
sub pem {
}
sub pomelo {
}
sub sapb {
	my $BCODE = "\x14\x77\xf3\xd4\xbb\x71\x23\xd0\x03\xff\x47\x93\x55\xaa\x66\x91".
	            "\xf2\x88\x6b\x99\xbf\xcb\x32\x1a\x19\xd9\xa7\x82\x22\x49\xa2\x51".
	            "\xe2\xb7\x33\x71\x8b\x9f\x5d\x01\x44\x70\xae\x11\xef\x28\xf0\x0d";
	my $TRANS = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".
		    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".
		    "\x3f\x40\x41\x50\x43\x44\x45\x4b\x47\x48\x4d\x4e\x54\x51\x53\x46".
		    "\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x56\x55\x5c\x49\x5d\x4a".
		    "\x42\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
		    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x58\x5b\x59\xff\x52".
		    "\x4c\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f".
		    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x57\x5e\x5a\x4f\xff".
		    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".
		    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".
		    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".
		    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".
		    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".
		    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".
		    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff".
		    "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
	$out_username = uc get_username(12);
	my $pw = $_[1];
	# note length=0 password fails, who cares!
	if (length $pw > 8) { $pw = substr($pw, 0, 8); }
	# convert password into 'translated' password
	my @arp = unpack("C*", $pw);
	my $pass_tr = ""; for ($h = 0; $h < length $pw; ++$h) { $pass_tr .= substr($TRANS, $arp[$h]%256, 1); }
	# convert username (salt) into 'translated' username
	my @ars = unpack("C*", $out_username);
	my $user_tr = ""; for ($h = 0; $h < length $out_username; ++$h) { $user_tr .= substr($TRANS, $ars[$h]%256, 1); }

	$h = md5($pass_tr.$user_tr);

	# wald0rf_magic crap (from sapB_fmt_plug.c)
	my @arh = unpack("C*", $h);
	my $sum20 = $arh[0]%4+$arh[1]%4+$arh[2]%4+$arh[3]%4+$arh[5]%4+0x20;
	my $destArray = "";  # we build $sum20 byts of destArray, using tralated password, username and the BCODE array
	my $I1=0; my $I3=0;  # the I2 variable is simply current length of destArray
	while (length $destArray < $sum20) {
		if ($I1 < length($pw)) {
			if ($arh[15-$I1] % 2) {
				$destArray .= substr($BCODE, 0x30-$I1-1, 1);
			}
			$destArray .= substr($pass_tr, $I1++, 1);
		}
		if ($I3 < length $out_username) {
			$destArray .= substr($user_tr, $I3++, 1);
		}
		$destArray .= substr($BCODE, length($destArray) - $I1 - $I3, 1);
		$destArray .= "\0";
	}
	# note, the wald0r_magic can give us 1 byte too much, for some $sum20 values. Fix if needed.
	if (length $destArray > $sum20) { $destArray = substr($destArray, 0, $sum20); }
	# end of wald0rf_magic crap

	$h = md5($destArray);
	my @ar = unpack("C*", $h);
	$h = "";
	for ($I1 = 0; $I1 < 8; ++$I1) {
		$h .= chr($ar[$I1] ^ $ar[$I1+8]);
	}
	return "$out_username\$". uc unpack("H*",$h);
}
sub sapg {
	my $CODVNG = "\x91\xAC\x51\x14\x9F\x67\x54\x43\x24\xE7\x3B\xE0\x28\x74\x7B\xC2".
	             "\x86\x33\x13\xEB\x5A\x4F\xCB\x5C\x08\x0A\x73\x37\x0E\x5D\x1C\x2F".
		     "\x33\x8F\xE6\xE5\xF8\x9B\xAE\xDD\x16\xF2\x4B\x8D\x2C\xE1\xD4\xDC".
		     "\xB0\xCB\xDF\x9D\xD4\x70\x6D\x17\xF9\x4D\x42\x3F\x9B\x1B\x11\x94".
		     "\x9F\x5B\xC1\x9B\x06\x05\x9D\x03\x9D\x5E\x13\x8A\x1E\x9A\x6A\xE8".
		     "\xD9\x7C\x14\x17\x58\xC7\x2A\xF6\xA1\x99\x63\x0A\xD7\xFD\x70\xC3".
		     "\xF6\x5E\x74\x13\x03\xC9\x0B\x04\x26\x98\xF7\x26\x8A\x92\x93\x25".
		     "\xB0\xA2\x0D\x23\xED\x63\x79\x6D\x13\x32\xFA\x3C\x35\x02\x9A\xA3".
		     "\xB3\xDD\x8E\x0A\x24\xBF\x51\xC3\x7C\xCD\x55\x9F\x37\xAF\x94\x4C".
		     "\x29\x08\x52\x82\xB2\x3B\x4E\x37\x9F\x17\x07\x91\x11\x3B\xFD\xCD";
	$out_username = uc get_username(12);
	my @ar = unpack("C*", sha1($_[1].$out_username));
	my $len = 0; for ($h = 0; $h < 10; ++$h) { $len += $ar[$h] % 6; } $len += 0x20;
	my $off = 0; for ($h = 19; $h > 9; --$h) { $off += $ar[$h] % 8; }
	$h = uc unpack("H*", sha1($_[1].substr($CODVNG, $off, $len).$out_username));
	return "$out_username\$$h";
}
sub stribog {
}

##############################################################################
# stub functions.  When completed, move the function out of this section
##############################################################################
sub as400ssha1 {
	# note, dynamic_1590 is used. this is a 'thin' format.
	$out_username = get_username(10);
	my $uname = uc $out_username;
	while (length($uname) < 10) { $uname .= ' '; }
	return '$as400ssha1$'.uc unpack("H*",sha1(encode("UTF-16BE", $uname.$_[1]))) . '$' . uc $out_username;
}
sub eigrp {
	my $algo = int(rand(120) > 100) + 2;
	#$algo = 2;
	if ($algo == 2) {
		# md5 version
		my $salt = pack("H*","020500000000000000000000000000000000002a000200280002001000000001000000000000000000000000");
		substr($salt, 12,3) = randstr(3);
		my $pw = $_[0];
		while (length($pw) < 16) { $pw .= "\0"; }
		my $salt2 = int(rand(120) > 110) ? randstr(30) : "";
		my $h = md5($salt . $pw . $salt2);
		if ($salt2 ne "") { $salt2 = "\$1\$".unpack("H*",$salt2)."\$"; } else { $salt2 = '$0$x$'; }
		return "\$eigrp\$2\$" . unpack("H*",$salt) . $salt2 . unpack("H*",$h);
	}
	#hmac-256 version.
	my $ip = int(rand(240)+10).".".int(rand(256)).".".int(rand(256)).".".int(rand(256));
	my $pw = "\n$_[0]$ip";
	my $salt = pack("H*","020500000000000000000000000000000000000a00020038000300200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000c010001000000000f000400080f00020000f5000a000000020000");
	substr($salt, 12,3) = randstr(3);
	my $h = Digest::SHA::hmac_sha256($salt, $pw);
	return "\$eigrp\$3\$" . unpack("H*",$salt) . "\$0\$x\$1\$$ip\$" . unpack("H*",$h);
}
sub mdc2 {
	# we should be able to optimize this, but for now this 'works'.
	# note, mdc2 is not in v1.01 but was introduced somewhere in v1.02
	# so a 1 time check has been added.
	if ($is_mdc2_valid == 0) { return undef; }
	if ($is_mdc2_valid == -1) {
		my $s = `echo -n '' | openssl dgst -mdc2 2> /dev/null`;
		chomp $s;
		if (length($s) > 10) { $s = substr($s, 9); }
		if ($s eq "52525252525252522525252525252525") {
			$is_mdc2_valid = 1;
		} else {
			print STDERR "\nmdc2 requires an updated openssl for pass_gen.pl to produce hashes\n\n";
			$is_mdc2_valid = 0;
			return undef;
		}
	}
	if (index($_[0], "'") != -1) { return undef; }
	my $s = `echo -n '$_[0]' | openssl dgst -mdc2`;
	chomp $s;
	$s = substr($s, 9);
	if ($s eq "") { print "_[0] = $_[0]\n"; }
	return "\$mdc2\$$s";
}
sub efs {
	my $sid = sprintf("S-1-5-21-1482476501-1659004503-725345%03d-%04d", int(rand(999)), int(rand(9999)));
	my $sid_u = encode("UTF-16LE", $sid."\0");
	my $iter = 4000;
	my $iv = get_iv(16);
	my $pw_u = encode("UTF-16LE", $_[0]);
	my $out = sha1($pw_u);
	my $out2 = Digest::SHA::hmac_sha1($sid_u, $out);
	# NOTE, efs has a busted pbkdf2 function.  The last param (1) tells pbkdf2 to use the busted extra step.
	my $p = pp_pbkdf2($out2,$iv,$iter,"sha1",32, 64, 0, 1);
	#create the ct here. We just build a 104 byte random string, then perform the computations that
	#sets bytes [16..36] to the proper computed hmac value of the password hash and the other parts of ct.
	$out2 .= "\0\0\0\0\0\0\0\0\0\0\0\0";
	my $ct = randstr(104);
	my $ourKey = substr($ct, length($ct)-64);
	my $hmacSalt = substr($ct, 0, 16);
	my $encKey = Digest::SHA::hmac_sha1($hmacSalt, $out2);
	my $hmacComputed = Digest::SHA::hmac_sha1($ourKey, $encKey);
	substr($ct, 16, 20) = $hmacComputed;
	# now crypt the ct.  This crypted value is stored in the hash line.
	require Crypt::DES_EDE3; require Crypt::CBC;
	my $cbc = Crypt::CBC->new(-key => substr($p,0,24), -cipher => "DES_EDE3", -iv => substr($p,24,8), -literal_key => 1, -header => "none");
	my $enc = $cbc->encrypt($ct);
	$enc = substr($enc, 0, length($enc)-8);
	return "\$efs\$0\$$sid\$".unpack("H*",$iv)."\$$iter\$".unpack("H*",$enc);
}
sub keyring {
	my $s = get_salt(8);
	my $iter = int(2000 + rand(2000));
	my $data = randstr(16);
	$data = md5($data) . $data;
	my $h = sha256($_[0].$s);
	for (my $i = 1; $i < $iter; ++$i) {
		$h = sha256($h);
	}
	my $key = substr($h, 0, 16);
	my $iv = substr($h, 16, 16);
	require Crypt::Cipher::AES;
	require Crypt::CBC;
	my $crypt = Crypt::CBC->new(-literal_key => 1, -key => $key, -keysize => 16, -iv => $iv, -cipher => "Crypt::Cipher::AES", -header => 'none', -padding => 'none');
	$h = $crypt->encrypt($data);
	$h = unpack("H*", $h);
	$s = unpack("H*", $s);
	my $l = length($data);
	return "\$keyring\$$s*$iter*$l*0*$h";
}
sub snefru_128 {
	require Crypt::Rhash;
	my $r = Crypt::Rhash->new(Crypt::Rhash::RHASH_SNEFRU128());
	return "\$snefru\$" . $r->update($_[0])->hash();
}
sub snefru_256 {
	require Crypt::Rhash;
	my $r = Crypt::Rhash->new(Crypt::Rhash::RHASH_SNEFRU256());
	return "\$snefru\$" . $r->update($_[0])->hash();
}
sub palshop {
	my $m1 = md5($_[0]);
	my $s1 = sha1($_[0]);
	my $s = unpack("H*", $m1.$s1);
	$s = substr($s, 11, 50) . substr($s, 0, 1);
	#print ("$s\n");
	my $m2 = md5($s);
	my $s2 = sha1($s);
	return "\$palshop\$". substr(unpack("H*",$m2),11) . substr(unpack("H*",$s2), 0, 29) . substr(unpack("H*",$m2),0,1);
}
sub iwork {
	my $s = get_salt(16);
	my $iv = get_iv(16);
	my $iter = 100000;
	my $blob_dat = randstr(32);
	#$blob_dat = pack("H*", "c6ef9b77af9e4d356e3dc977910b8cb3c3c1f2db89430ec36232078c2cefdec7");
	$blob_dat .= sha256($blob_dat);
	$h = pp_pbkdf2($_[0], $s, $iter, "sha1", 16, 64);
	require Crypt::Cipher::AES;
	require Crypt::CBC;
	my $crypt = Crypt::CBC->new(-literal_key => 1, -key => $h, -keysize => 16, -iv => $iv, -cipher => "Crypt::Cipher::AES", -header => 'none', -padding => 'none');
	my $output = $crypt->encrypt($blob_dat);
	return "\$iwork\$1\$2\$1\$$iter\$".unpack("H*",$s)."\$".unpack("H*",$iv)."\$".unpack("H*",$output);
}
sub fgt {
	my $s = get_salt(12);
	my $magic = "\xa3\x88\xba\x2e\x42\x4c\xb0\x4a\x53\x79\x30\xc1\x31\x07\xcc\x3f\xa1\x32\x90\x29\xa9\x81\x5b\x70";
	$h = sha1($s.$_[0].$magic);
	return "AK1".base64($s.$h);
}
sub has160 {
	require Crypt::Rhash;
	my $r = Crypt::Rhash->new(Crypt::Rhash::RHASH_HAS160());
	return $r->update($_[0])->hash();
}
sub mongodb_scram {
	my $u = get_username(-16);
	my $s = get_salt(16);
	my $iter = 10000;
	my $h = md5_hex($u . ':mongo:' . $_[0]);
	$h = pp_pbkdf2($h, $s, $iter, "sha1", 20, 64);
	$h = Digest::SHA::hmac_sha1("Client Key", $h);
	$h = sha1($h);
	return "\$scram\$$u\$$iter\$" . base64($s) . '$' . base64($h);
}
sub zipmonster {
	my $s = uc md5_hex($_[0]);
	for (my $i = 0; $i < 49999; ++$i) {
		$s = uc md5_hex($s);
	}
	return "\$zipmonster\$".lc $s;
}
sub cloudkeychain {
	$salt = get_salt(16);
	my $iv = get_iv(16);
	my $iter = get_loops(227272);
	my $master_key = "  ";
	my $hmacdata = get_content(96, -1024);
	my $p = pp_pbkdf2($_[1],$salt,$iter,"sha512",64, 128);
	my $expectedhmac = _hmac_shas(\&sha256, 64, substr($p,32), $hmacdata);
	my $mklen = length($master_key);
	my $hmdl = length($hmacdata);
	my $ct = pack("H*", "000");
	my $ctlen = length($ct);
	$salt = unpack("H*",$salt); $iv = unpack("H*",$iv); $ct = unpack("H*",$ct); $master_key = unpack("H*",$master_key);
	$expectedhmac = unpack("H*",$expectedhmac); $hmacdata = unpack("H*",$hmacdata);
	return "\$cloudkeychain\$16\$$salt\$$iter\$$mklen\$$master_key\$256\$16\$$iv\$$ctlen\$$ct\$32\$$expectedhmac\$$hmdl\$$hmacdata";
}
sub agilekeychain {
	my $nkeys=1;
	my $iterations=get_loops(1000);
	my $salt=get_salt(8);
	my $iv=get_iv(16);
	my $dat=randstr(1040-32); # not sure what would be here, but JtR does not do anything with it.
	$dat .= $iv;
	my $key = pp_pbkdf2($_[1], $salt, $iterations,"sha1",16, 64);
	require Crypt::Cipher::AES;
	require Crypt::CBC;
	my $crypt = Crypt::CBC->new(-literal_key => 1, -key => $key, -keysize => 16, -iv => $iv, -cipher => 'Crypt::Cipher::AES', -header => 'none');
	my $h = $crypt->encrypt("\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10");
	$dat .= substr($h,0,16);

	return "\$agilekeychain\$$nkeys*$iterations*8*".unpack("H*", $salt)."*1040*".unpack("H*", $dat)."*".unpack("H*", $key);
}
sub bitcoin {
	my $master; my $rounds; # my $ckey; my $public_key;
	$master = pack("H*", "0e34a996b1ce8a1735bba1acf6d696a43bc6730b5c41224206c93006f14f951410101010101010101010101010101010");
	$salt = get_salt(8);
	$rounds = get_loops(20000);  # 20k is a 'small' default number, but runs pretty fast.
	$h = sha512($_[1] . $salt);
	for (my $i = 1; $i < $rounds; $i++) {
		$h = sha512($h);
	}
	require Crypt::Cipher::AES;
	require Crypt::CBC;
	my $crypt = Crypt::CBC->new(-literal_key => 1, -key => substr($h,0,32), -keysize => 32, -iv => substr($h,32,16), -cipher => 'Crypt::Cipher::AES', -header => 'none');
	return '$bitcoin$96$'.substr(unpack("H*", $crypt->encrypt($master)),0,96).'$16$'.unpack("H*", $salt).'$'.$rounds.'$2$00$2$00';
}
sub azuread {
	$salt = get_salt(10);
	#$salt = pack("H*", "317ee9d1dec6508fa510");
	my $rounds = get_loops(100); # NOTE, right now, Azure-AD 'is' hard coded at 100, ITRW
	$h = encode("UTF-16LE", uc unpack("H*",md4(encode("UTF-16LE", $_[0]))));
	my $key = unpack("H*",pp_pbkdf2($h, $salt, $rounds, "sha256", 32, 64));
	return "v1;PPH1_MD4,".unpack("H*",$salt).",$rounds,$key;";
}
sub vdi_256 {
	my $salt1   = randstr(32, \@chrRawData);
	my $salt2   = randstr(32, \@chrRawData);
	my $dec_dat = randstr(64, , \@chrRawData);
	my $evp_pass = pp_pbkdf2($_[0], $salt1, 2000, \&sha256, 64, 64);
	my $tweak = "\x00"x16;
	my $enc_pass = _aes_xts($evp_pass,$dec_dat,$tweak, 256);
	my $final  = unpack("H*",pp_pbkdf2($dec_dat, $salt2, 2000, \&sha256, 32, 64));
	$salt1   = unpack("H*",$salt1); $salt2   = unpack("H*",$salt2); $enc_pass = unpack("H*",$enc_pass);
	return "\$vdi\$aes-xts256\$sha256\$2000\$2000\$64\$32\$$salt1\$$salt2\$$enc_pass\$$final";
}
sub vdi_128 {
	my $salt1   = randstr(32, \@chrRawData);
	my $salt2   = randstr(32, \@chrRawData);
	my $dec_dat = randstr(32, , \@chrRawData);
	my $evp_pass = pp_pbkdf2($_[0], $salt1, 2000, \&sha256, 32, 64);
	my $tweak = "\x00"x16;
	my $enc_pass = _aes_xts($evp_pass,$dec_dat,$tweak, 128);
	my $final  = unpack("H*",pp_pbkdf2($dec_dat, $salt2, 2000, \&sha256, 32, 64));
	$salt1   = unpack("H*",$salt1); $salt2   = unpack("H*",$salt2); $enc_pass = unpack("H*",$enc_pass);
	return "\$vdi\$aes-xts128\$sha256\$2000\$2000\$32\$32\$$salt1\$$salt2\$$enc_pass\$$final";
}
sub qnx_md5 {
	$salt = get_salt(16, \@chrHexLo);
	my $rounds = get_loops(1000);
	my $h = md5($salt . $_[0]x($rounds+1));
	my $ret = "\@m";
	if ($rounds != 1000) { $ret .= ",$rounds"; }
	$ret .= "\@".unpack("H*",$h)."\@$salt";
	return $ret;
}
sub qnx_sha512 {
#	use SHA512_qnx;
#	$salt = get_salt(16, \@chrHexLo);
#	my $rounds = get_loops(1000);
#	my $h = SHA512_qnx::sha512($salt . $_[0]x($rounds+1));
#	my $ret = "\@S";
#	if ($rounds != 1000) { $ret .= ",$rounds"; }
#	$ret .= "\@".unpack("H*",$h)."\@$salt";
#	return $ret;
	if ($qnx_sha512_warning == 0) {
		print STDERR "\nqnx_sha512 requires SHA512_qnx.pm to be in current directory, and the qnx_sha512 function edited.\n\n";}
	$qnx_sha512_warning += 1;
	return qnx_sha256(@_);
}
sub qnx_sha256 {
	$salt = get_salt(16, \@chrHexLo);
	my $rounds = get_loops(1000);
	my $h = sha256($salt . $_[0]x($rounds+1));
	my $ret = "\@s";
	if ($rounds != 1000) { $ret .= ",$rounds"; }
	$ret .= "\@".unpack("H*",$h)."\@$salt";
	return $ret;
}
sub blockchain {
	my $unenc = "{\n{\t\"guid\" : \"246093c1-de47-4227-89be-".randstr(12,\@chrHexLo)."\",\n\t\"sharedKey\" : \"fccdf579-707c-46bc-9ed1-".randstr(12,\@chrHexLo)."\",\n\t";
	$unenc .= "\"options\" : {\"pbkdf2_iterations\":10,\"fee_policy\":0,\"html5_notifications\":false,\"logout_time\":600000,\"tx_display\":0,\"always_keep_local_backup\":false},\n\t";
	$unenc .= "\"keys\" : [\n\t{\"addr\" : \"156yFScjeoMCvPnNji2UiztuVuYL2MY16Z\",\n\t \"priv\" : \"DNDjMS2CsrKE8kXhwkZawbou56fJECiGCqNEzZbwgxSJ\"}\n\t]\n}";
	my $len = length($unenc);
	$len = floor(($len+15)/16);
	$len *= 16;
	my $data;
	my $iv = get_salt(16);
	my $key = pp_pbkdf2($_[1], $iv, 10,"sha1",32, 64);
	require Crypt::Cipher::AES;
	require Crypt::CBC;
	my $crypt = Crypt::CBC->new(-literal_key => 1, -key => $key, -keysize => 32, -iv => $iv, -cipher => 'Crypt::Cipher::AES', -header => 'none');
	my $h = $crypt->encrypt($unenc);
	$data = $iv.substr($h,0,$len);
	return '$blockchain$'.length($data).'$'.unpack("H*", $data);
}
sub keystore {
	$out_username = get_username($arg_maxuserlen);
	# we want to assure that we will NEVER set the 0x80 bit in the first block.
	# so, salt and contant have to be > 64 bytes (at min).
	$salt = pack("H*", "feedfeed0000000200000001000000010000") . get_salt(36) . get_salt(-128);
	my $p = unpack("H*", $_[0]);
	my $p2 = "";
	for (my $i = 0; $i < length($p); $i += 2) {
		$p2 .= "00" . substr($p, $i, 2);
	}
	$p = pack("H*", $p2);
	my $hash = sha1_hex($p . "Mighty Aphrodite" . $salt);
	return "\$keystore\$0\$".length($salt).'$'.unpack("H*",$salt)."\$$hash\$1\$1\$00";
}
sub vnc {
	require Crypt::ECB;
	Crypt::ECB->import();
	my $chal = get_salt(16);
	my $key = str_force_length_pad($_[0], 8, "\0");
	$key = str_odd_parity($key);
	$key = str_reverse_bits_in_bytes($key);
	my $cr = Crypt::ECB->new;
	$cr->padding(ecb_padding_none);
	$cr->cipher("DES");
	$cr->key($key);
	my $hash = $cr->encrypt($chal);
	return "\$vnc\$*".uc(unpack("H*",$chal))."*".uc(unpack('H*', $hash));
}
sub sxc {
	$salt = get_salt(16);
	my$iv = get_iv(8);
	my $r = get_loops(1024);
	my $content = get_content(-1024, -4095);
	my $len = length($content);
	my $len2 = floor(length($content)/20) * 20;
	$h = sha1($_[0]);
	my $key = pp_pbkdf2($h, $salt, $r, "sha1", 16 , 64);
	require Crypt::Cipher::Blowfish;
	require Crypt::Mode::CFB;
	my $crypt = Crypt::Mode::CFB->new('Blowfish');
	my $output = $crypt->decrypt($content, $key, $iv);
	my $res = sha1_hex(substr($output, 0, $len2));
	return "\$sxc\$*0*0*$r*16*$res*8*".unpack("H*",$iv)."*16*".unpack("H*",$salt)."*$len2*$len*".unpack("H*",$content);
}
sub vtp {
	my $secret = $_[0];
	if (length($secret)) {
		while (length($secret) < 1563*64) { $secret .= $_[0]; }
		if (length($secret) > 1563*64) { $secret = substr($secret, 0, 1563*64); }
		$secret = md5($secret);
	} else {
		$secret = "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
	}
	my $c = randstr(1,\@chrRawData);
	my $vtp;
	my $trailer_data;
	my $vlans_data;
	my $v = 2;
	my $salt = get_salt(10);
	if (ord($c) < 20) {
		# create v1 record.
		$v = 1;
		$vtp = pack("H*","0101000c646f6d61696e31323334353600000000000000000000000000000000000000000000001".
						 "00000000000000000000000000000000000000000000000000000000000000000");
		$trailer_data = pack("H*","0101000200");
		$vlans_data = pack("H*","14000107000105dc000186a164656661756c740014000105000505dc000186a568656c6c6".
								"f0000002000020c03ea05dc00018a8a666464692d64656661756c74010100000401000028".
								"00031203eb05dc00018a8b746f6b656e2d72696e672d64656661756c74000001010000040".
								"100002400040f03ec05dc00018a8c666464696e65742d64656661756c7400020100000301".
								"00012400050d03ed05dc00018a8d74726e65742d64656661756c740000000201000003010002");
	} else {
		# create v2 record.
		$vtp = pack("H*","0201000c646f6d61696e313233343536000000000000000000000000000000000000000000000015".
						 "0000000000000000000000000000000000000000000000000000000000000000");
		$trailer_data = pack("H*","0000000106010002");
		$vlans_data = pack("H*","14000107000105dc000186a164656661756c740014000105000505dc000186a56368656e61".
								"00000010000103000605dc000186a6666666001800020c03ea05dc00018a8a666464692d64".
								"656661756c743000030d03eb117800018a8b74726372662d64656661756c7400000001010c".
								"cc040103ed0701000208010007090100072000040f03ec05dc00018a8c666464696e65742d".
								"64656661756c7400030100012400050d03ed117800018a8d74726272662d64656661756c740000000201000f03010002");
	}
	substr($vtp, 4, 10) = "\0\0\0\0\0\0\0\0\0\0";
	substr($vtp, 4, length($salt)) = $salt;
	my $h =	$secret.$vtp;
	if ($v != 1) { $h .= $trailer_data; }
	my $vdl = length($vlans_data);
	my $sl = length($vtp)+length($trailer_data);
	$h = unpack("H*",md5($h.$vlans_data.$secret));
	$vtp = unpack("H*",$vtp);
	$vlans_data = unpack("H*",$vlans_data);
	$trailer_data = unpack("H*",$trailer_data);
	return "\$vtp\$$v\$$vdl\$$vlans_data\$$sl\$$vtp$trailer_data\$$h";
}
sub racf {
	require Convert::EBCDIC;
	import Convert::EBCDIC qw (ascii2ebcdic);
	require Crypt::DES;
	my $user = uc get_username(12);
	my $pw = uc $_[0];
	my $pad_user = substr ($user . " " x 8, 0, 8);
	my $pad_pass = substr ($pw . " " x 8, 0, 8);
	my $usr_ebc = ascii2ebcdic ($pad_user);
	my $pass_ebc = ascii2ebcdic ($pad_pass);
	my @pw = split ("", $pass_ebc);
	for (my $i = 0; $i < 8; $i++) {
		$pw[$i] = unpack ("C", $pw[$i]);
		$pw[$i] ^= 0x55;
		$pw[$i] <<= 1;
		$pw[$i] = pack ("C", $pw[$i] & 0xff);
	}
	my $key = join ("", @pw);
	my $des = new Crypt::DES $key;
	my $h = $des->encrypt ($usr_ebc);
	$h = uc unpack ("H16", $h);
	return "\$racf\$*$user*$h";
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
	return "\$mozilla\$*3*20*1*".unpack("H*",$salt)."*11*2a864886f70d010c050103*16*".unpack("H*",$enc)."*20*".unpack("H*",$gsalt);
}
sub keychain {
	$out_username = get_username($arg_maxuserlen);
	require Crypt::DES_EDE3;
	require Crypt::CBC;
	my $iv; my $data; my $key; my $h;
	$salt = get_salt(20);
	$iv = get_iv(8);

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
	return "\$keychain\$*".unpack("H*",$salt)."*".unpack("H*",$iv)."*".substr(unpack("H*",$h),0,48*2);
}
sub wpapsk {
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
	$prf = _hmacsha1($wpaH, $data);

	if ($keyver == 1) {
		$prf = substr($prf, 0, 16);
		$keymic = _hmacmd5($prf, $eapol);
	} else {
		$prf = substr($prf, 0, 16);
		$keymic = _hmacsha1($prf, $eapol);
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
	return "\$WPAPSK\$$ssid#".base64_wpa($inpdat);
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
	$out_username = get_salt(22,-27,\@userNames);
	$salt = encode("UTF-16LE", lc($out_username));
	my $key = md4(md4(encode("UTF-16LE",$_[0])).$salt);
	return '$DCC2$'."$iter#$out_username#".pp_pbkdf2_hex($key,$salt,$iter,"sha1",16,64);
}
sub lm {
	$out_username = get_username($arg_maxuserlen);
	my $p = $_[0];
	if (length($p)>14) { $p = substr($p,0,14);}
	$out_uc_pass = 1; $out_extras = 1;
	return "0:".unpack("H*",LANMan($p));
}
sub nt {
	$out_username = get_username($arg_maxuserlen);
	return "\$NT\$".unpack("H*",md4(encode("UTF-16LE", $_[0])));
}
sub pwdump {
	$out_username = get_username($arg_maxuserlen);
	my $lm = unpack("H*",LANMan(length($_[0]) <= 14 ? $_[0] : ""));
	my $nt = unpack("H*",md4(encode("UTF-16LE", $_[0])));
	$out_extras = 0;
	return "0:$lm:$nt";
}
sub raw_md4 {
	$out_username = get_username($arg_maxuserlen);
	return md4_hex($_[1]);
}
sub mediawiki {
	$out_username = get_username($arg_maxuserlen);
	$salt = get_salt(8);
	return "\$B\$$salt\$".md5_hex($salt . "-" . md5_hex($_[1]));
}
sub osc {
	$salt = get_salt(2);
	return "\$OSC\$".unpack("H*",$salt)."\$".md5_hex($salt. $_[1]);
}
sub formspring {
	$salt = get_salt(2,2,\@chrAsciiNum);
	return sha256_hex($salt. $_[1])."\$$salt";
}
sub phpass {
	$out_username = get_username($arg_maxuserlen);
	$salt = get_salt(8);
	my $h = phpass_hash($_[1], 11, $salt);
	return "\$P\$".to_phpbyte(11).$salt.substr(base64i($h),0,22);
}
sub po {
	if (defined $argsalt) {
		$salt = md5_hex($argsalt);
	} else {
		$salt=randstr(32, \@chrHexLo);
	}
	return md5_hex($salt."Y".$_[1]."\xF7".$salt)."$salt";
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
	$out_username = get_username($arg_maxuserlen);
	$salt = get_salt(8);
	$h = md5crypt_hash($_[1], $salt, "\$apr1\$");
	return $h;
}
sub md5crypt_smd5 {
	$out_username = get_username($arg_maxuserlen);
	$salt = get_salt(8);
	$h = md5crypt_hash($_[1], $salt, "");
	return "{smd5}$h";
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
	return "$salt\$$h";
}
sub wowsrp {
	require Math::BigInt;
	$salt = get_salt(16);
	my $usr = uc get_username(24);
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
	$out_uc_pass = 1;

#   this next line  left pads 0's to the hash. Optional. We handle both instances.
#	while (length($h) < 64) { $h = "0".$h; }

	return "\$WoWSRP\$$h\$".uc unpack("H*", $salt)."*$usr";
}
sub clipperz_srp {
	require Math::BigInt;
	$salt = get_salt(64);
	my $usr = get_username(24);
	my $h = "0x" . unpack("H*", sha256(sha256($salt.unpack("H*",sha256(sha256($_[1].$usr))))));

	# perform exponentation.
	my $base = Math::BigInt->new(2);
	my $exp = Math::BigInt->new($h);
	my $mod = Math::BigInt->new("125617018995153554710546479714086468244499594888726646874671447258204721048803");
	$h = $base->bmodpow($exp, $mod);

	# convert h into hex
	$h = substr($h->as_hex(), 2);

#   this next line  left pads 0's to the hash. Optional. We handle both instances.
#	while (length($h) < 65) { $h = "0".$h; }

	return "\$clipperz\$$h\$$salt*$usr";
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
sub _hmacsha1 {
	my ($key, $data) = @_;
	my $ipad; my $opad;
	if (length($key) > 64) {
		$key = sha1($key);
	}
	for ($i = 0; $i < length($key); ++$i) {
		$ipad .= chr(ord(substr($key, $i, 1)) ^ 0x36);
		$opad .= chr(ord(substr($key, $i, 1)) ^ 0x5C);
	}
	while ($i++ < 64) {
		$ipad .= chr(0x36);
		$opad .= chr(0x5C);
	}
	return sha1($opad,sha1($ipad,$data));
}
sub hmac_md5 {
	$salt = get_salt(-183);
	my $bin = _hmacmd5($_[1], $salt);
	return "$salt#".unpack("H*",$bin);
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
	return "$salt#".unpack("H*",$bin);
}
sub hmac_sha224 {
	$salt = get_salt(-183);
	my $bin = _hmac_shas(\&sha224, 64, $_[1], $salt);
	return "$salt#".unpack("H*",$bin);
}
sub hmac_sha256 {
	$salt = get_salt(-183);
	my $bin = _hmac_shas(\&sha256, 64, $_[1], $salt);
	return "$salt#".unpack("H*",$bin);
}
sub hmac_sha384 {
	$salt = get_salt(-239);
	my $bin = _hmac_shas(\&sha384, 128, $_[1], $salt);
	return "$salt#".unpack("H*",$bin);
}
sub hmac_sha512 {
	$salt = get_salt(-239);
	my $bin = _hmac_shas(\&sha512, 128, $_[1], $salt);
	return "$salt#".unpack("H*",$bin);
}
sub rakp {
	$out_username = get_username(64);
	$salt = get_salt(56) . $out_username;
	my $bin = _hmac_shas(\&sha1, 64, $_[1], $salt);
	return unpack("H*",$salt)."\$".unpack("H*",$bin);
}
sub _sha_crypts {
	my $a; my $b, my $c, my $tmp; my $i; my $ds; my $dp; my $p; my $s;
	my ($func, $bits, $key, $salt) = @_;
	my $bytes = $bits/8;
	my $loops = get_loops(5000);

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
	$out_username = get_username($arg_maxuserlen);
	$salt = get_salt(-16);
	my $bin = _sha_crypts(\&sha256, 256, $_[1], $salt);
	if ($arg_loops != -1) { return "\$5\$rounds=${arg_loops}\$$salt\$$bin"; }
	return "\$5\$$salt\$$bin";
}
sub sha512crypt {
	$out_username = get_username($arg_maxuserlen);
	$salt = get_salt(-16);
	my $bin = _sha_crypts(\&sha512, 512, $_[1], $salt);
	if ($arg_loops != -1) { return "\$6\$rounds=${arg_loops}\$$salt\$$bin" }
	return "\$6\$$salt\$$bin";
}
sub sha1crypt {
	$out_username = get_username($arg_maxuserlen);
	$salt = get_salt(8);
	my $loops = get_loops(5000);
	# actual call to pbkdf1 (that is the last 1 param, it says to use pbkdf1 logic)
	$h = pp_pbkdf2($_[1], $salt.'$sha1$'.$loops, $loops, "sha1", 20, 64, 1);
	$h = base64_aix($h.substr($h,0,1)); # the hash is padded to 21 bytes, by appending first byte.  That is how it is done, dont ask why.
	return "\$sha1\$$loops\$$salt\$$h";
}
sub xsha512 {
	# simple 4 byte salted crypt.  No separator char, just raw hash and 'may' have $LION$
	my $ret = "";
	$salt = get_salt(4);
	if ($u&1) { $ret = "\$LION\$"; }
	$ret .= unpack("H*", $salt).sha512_hex($salt . $_[1]);
}
sub krb5pa_sha1 {
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
	return "\$mskrb5\$\$\$".unpack("H*",$K2)."\$".unpack("H*",$encrypted);
}
sub ipb2 {
	$salt = get_salt(5);
	return "\$IPB2\$".unpack("H*",$salt)."\$".md5_hex(md5_hex($salt).md5_hex($_[1]));
}
sub phps {
	$salt = get_salt(3);
	return "\$PHPS\$".unpack("H*",$salt)."\$".md5_hex(md5_hex($_[1]),$salt);
}
sub md4p {
	$salt = get_salt(8);
	return "\$MD4p\$$salt\$".md4_hex($salt, $_[1]);
}
sub md4s {
	$salt = get_salt(8);
	return "\$MD4s\$$salt\$".md4_hex($_[1], $salt);
}
sub sha1p {
	$salt = get_salt(8);
	return "\$SHA1p\$$salt\$".sha1_hex($salt, $_[1]);
}
sub sha1s {
	$salt = get_salt(8);
	return "\$SHA1s\$$salt\$".sha1_hex($_[1], $salt);
}
sub mysql_sha1 {
	return "*".sha1_hex(sha1($_[1]));
}
sub mysql {
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
	return unpack("H*",Uint32BERaw($nr&0x7fffffff)).unpack("H*",Uint32BERaw($nr2&0x7fffffff));
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
	return $h;
}
# salted pix
sub asamd5 {
	my $pass = $_[1];
	$salt = get_salt(-4);
	if (length($pass)>12) { $pass = substr($pass,0,12); }
	my $pass_padd = $pass.$salt;
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
	return "\$dynamic_20\$$h\$$salt";
}
sub mssql12 {
	$out_username = get_username($arg_maxuserlen);
	$salt = get_salt(4);
	return "0x0200".uc unpack("H*",$salt).uc sha512_hex(encode("UTF-16LE", $_[0]).$salt);
}
sub mssql05 {
	$out_username = get_username($arg_maxuserlen);
	$salt = get_salt(4);
	return "0x0100".uc unpack("H*",$salt).uc sha1_hex(encode("UTF-16LE", $_[0]).$salt);
}
sub mssql {
	$salt = get_salt(4);
	my $t = uc $_[1];
	if (length($_[1]) == length($t)) {
		$out_uc_pass = 1;
		return "0x0100".uc unpack("H*",$salt).uc sha1_hex(encode("UTF-16LE", $_[0]).$salt).uc sha1_hex(encode("UTF-16LE", $t).$salt);
	}
}
sub mssql_no_upcase_change {
	$salt = get_salt(4);
	# converts $c into utf8, from $enc code page, and 'sets' the 'flag' in perl that $c IS a utf8 char.
	# since we are NOT doing case changes in this function, it is ASSSUMED that we have been given a properly upcased dictionary
	if (!defined $arg_hidden_cp) { print STDERR "ERROR, for this format, you MUST use -hiddencp=CP to set the proper code page conversion\n"; exit(1); }
	my $PASS = Encode::decode($arg_hidden_cp, $_[0]);
	return "0x0100".uc unpack("H*",$salt).uc sha1_hex(encode("UTF-16LE", $PASS).$salt).uc sha1_hex(encode("UTF-16LE", $PASS).$salt);
}

sub nsldap {
	$out_username = get_username($arg_maxuserlen);
	$h = sha1($_[0]);
	return "{SHA}".base64($h);
}
sub nsldaps {
	$out_username = get_username($arg_maxuserlen);
	$salt = get_salt(8);
	$h = sha1($_[1],$salt);
	$h .= $salt;
	return "{SSHA}".base64($h);
}
sub openssha {
	$out_username = get_username($arg_maxuserlen);
	$salt = get_salt(4);
	$h = sha1($_[1],$salt);
	$h .= $salt;
	return "{SSHA}".base64($h);
}
sub salted_sha1 {
	$out_username = get_username($arg_maxuserlen);
	$salt = get_salt(-16, -128);
	$h = sha1($_[1],$salt);
	$h .= $salt;
	return "{SSHA}".base64($h);
}
sub ns {
	$salt = get_salt(7, -7, \@chrHexLo);
	$h = md5($salt, ":Administration Tools:", $_[1]);
	my $hh = ns_base64_2(8);
	substr($hh, 0, 0) = 'n';
	substr($hh, 6, 0) = 'r';
	substr($hh, 12, 0) = 'c';
	substr($hh, 17, 0) = 's';
	substr($hh, 23, 0) = 't';
	substr($hh, 29, 0) = 'n';
	return "$salt\$".$hh;
}
sub xsha {
	$salt = get_salt(4);
	return uc unpack("H*",$salt).uc sha1_hex($salt, $_[1]);
}
sub oracle {
	require Crypt::CBC;
	# snagged perl source from http://users.aber.ac.uk/auj/freestuff/orapass.pl.txt
	$out_username = get_salt(30, -30, \@userNames);
	my $pass = $_[1];
	my $userpass = pack('n*', unpack('C*', uc($out_username.$pass)));
	$userpass .= pack('C', 0) while (length($userpass) % 8);
	my $key = pack('H*', "0123456789ABCDEF");
	my $iv = pack('H*', "0000000000000000");
	my $cr1 = new Crypt::CBC(-literal_key => 1, -cipher => "DES", -key => $key, -iv => $iv, -header => "none" );
	my $key2 = substr($cr1->encrypt($userpass), length($userpass)-8, 8);
	my $cr2 = new Crypt::CBC( -literal_key => 1, -cipher => "DES", -key => $key2, -iv => $iv, -header => "none" );
	my $hash = substr($cr2->encrypt($userpass), length($userpass)-8, 8);
	return uc(unpack('H*', $hash));
}
sub oracle_no_upcase_change {
	require Crypt::CBC;
	# snagged perl source from http://users.aber.ac.uk/auj/freestuff/orapass.pl.txt
	my $out_username = get_salt(30, -30, \@userNames);
	# converts $c into utf8, from $enc code page, and 'sets' the 'flag' in perl that $c IS a utf8 char.
	# since we are NOT doing case changes in this function, it is ASSSUMED that we have been given a properly upcased dictionary
	if (!defined $arg_hidden_cp) { print STDERR "ERROR, for this format, you MUST use -hiddencp=CP to set the proper code page conversion\n"; exit(1); }

	my $pass = $out_username . Encode::decode($arg_hidden_cp, $_[0]);

	my $userpass = encode("UTF-16BE", $pass);
	$userpass .= pack('C', 0) while (length($userpass) % 8);
	my $key = pack('H*', "0123456789ABCDEF");
	my $iv = pack('H*', "0000000000000000");
	my $cr1 = new Crypt::CBC(-literal_key => 1, -cipher => "DES", -key => $key, -iv => $iv, -header => "none" );
	my $key2 = substr($cr1->encrypt($userpass), length($userpass)-8, 8);
	my $cr2 = new Crypt::CBC( -literal_key => 1, -cipher => "DES", -key => $key2, -iv => $iv, -header => "none" );
	my $hash = substr($cr2->encrypt($userpass), length($userpass)-8, 8);
	return uc(unpack('H*', $hash));
}
sub oracle11 {
	$out_username = get_username($arg_maxuserlen);
	$salt=get_salt(10);
	return uc sha1_hex($_[1], $salt).uc unpack("H*",$salt);
}
sub hdaa {
	#  	{"$response$679066476e67b5c7c4e88f04be567f8b$user$myrealm$GET$/$8c12bd8f728afe56d45a0ce846b70e5a$00000001$4b61913cec32e2c9$auth", "nocode"},
	my $user = randusername(20);
	my $realm = randusername(10);
	my $url = randstr(rand(64)+1);
	my $nonce = randstr(rand(32)+1, \@chrHexLo);
	my $clientNonce = randstr(rand(32)+1, \@chrHexLo);
	my $h1 = md5_hex($user, ":".$realm.":", $_[1]);
	my $h2 = md5_hex("GET:/$url");
	my $resp = md5_hex($h1, ":", $nonce, ":00000001:", $clientNonce, ":auth:", $h2);
	return "\$response\$$resp\$$user\$$realm\$GET\$/$url\$$nonce\$00000001\$$clientNonce\$auth";
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
	import Crypt::ECB qw(encrypt);
	my $password = $_[1];
	my $domain = get_salt(15, -15);
	my $nthash = md4(encode("UTF-16LE", $password));
	$nthash .= "\x00"x5;
	my $s_challenge = get_iv(8);
	my $c_challenge = get_content(8);
	my $challenge = substr(md5($s_challenge.$c_challenge), 0, 8);
	my $ntresp = Crypt::ECB::encrypt(setup_des_key(substr($nthash, 0, 7)), 'DES', $challenge, ecb_padding_none);
	$ntresp .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 7, 7)), 'DES', $challenge, ecb_padding_none);
	$ntresp .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 14, 7)), 'DES', $challenge, ecb_padding_none);
	my $type = "ntlm ESS";
	my $lmresp = $c_challenge . "\0"x16;
	#printf("%s\\%s:::%s:%s:%s::%s:%s\n", $domain, "u$u-netntlm", unpack("H*",$lmresp), unpack("H*",$ntresp), unpack("H*",$s_challenge), $_[0], $type);
	$l0pht_fmt = 1;
	return "u$u".":::".unpack("H*",$lmresp).":".unpack("H*",$ntresp).":".unpack("H*",$s_challenge);
}
# Alias for l0phtcrack
sub netntlm {
	return l0phtcrack(@_);
}
# This produces NETHALFLM, NETLM and non-ESS NETNTLM hashes in L0pthcrack format
sub l0phtcrack {
	require Crypt::ECB;
	import Crypt::ECB qw(encrypt);
	my $password = $_[1];
	my $domain = get_salt(15);
	my $nthash = md4(encode("UTF-16LE", $password));
	$nthash .= "\x00"x5;
	my $lmhash; my $lmresp;
	my $challenge = get_iv(8);
	my $ntresp = Crypt::ECB::encrypt(setup_des_key(substr($nthash, 0, 7)), 'DES', $challenge, ecb_padding_none);
	$ntresp .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 7, 7)), 'DES', $challenge, ecb_padding_none);
	$ntresp .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 14, 7)), 'DES', $challenge, ecb_padding_none);
	my $type;
	if (length($password) > 14) {
		$type = "ntlm only";
		$lmresp = $ntresp;
	} else {
		$type = "lm and ntlm";
		$lmhash = LANMan($password);
		$lmhash .= "\x00"x5;
		$lmresp = Crypt::ECB::encrypt(setup_des_key(substr($lmhash, 0, 7)), 'DES', $challenge, ecb_padding_none);
		$lmresp .= Crypt::ECB::encrypt(setup_des_key(substr($lmhash, 7, 7)), 'DES', $challenge, ecb_padding_none);
		$lmresp .= Crypt::ECB::encrypt(setup_des_key(substr($lmhash, 14, 7)), 'DES', $challenge, ecb_padding_none);
	}
	#printf("%s\\%s:::%s:%s:%s::%s:%s\n", $domain, "u$u-netntlm", unpack("H*",$lmresp), unpack("H*",$ntresp), unpack("H*",$challenge), $_[0], $type);
	$l0pht_fmt = 1;
	return "u$u".":::".unpack("H*",$lmresp).":".unpack("H*",$ntresp).":".unpack("H*",$challenge);
}
sub hsrp {
	if (length($_[1]) > 55) { return; }
	$h = pad_md64($_[1]);
	$salt = get_salt(16,-64);
	$h = md5($h.$salt.$_[1]);
	return '$hsrp$'.unpack("H*",$salt).'$'.unpack('H*', $h);
}
sub netlmv2 {
	my $pwd = $_[1];
	my $nthash = md4(encode("UTF-16LE", $pwd));
	my $domain = get_salt(15);
	my $user = get_username($arg_maxuserlen);
	my $identity = Encode::encode("UTF-16LE", uc($user).$domain);
	my $s_challenge = get_iv(8);
	my $c_challenge = get_content(8);
	my $lmresponse = _hmacmd5(_hmacmd5($nthash, $identity), $s_challenge.$c_challenge);
	#printf("%s\\%s:::%s:%s:%s::%s:netlmv2\n", $domain, $user, unpack("H*",$s_challenge), unpack("H*",$lmresponse), unpack("H*",$c_challenge), $_[0]);
	$l0pht_fmt = 1;
	return "$domain\\$user".":::".unpack("H*",$s_challenge).":".unpack("H*",$lmresponse).":".unpack("H*",$c_challenge);
}
sub netntlmv2 {
	my $pwd = $_[1];
	my $nthash = md4(encode("UTF-16LE", $pwd));
	my $user = get_username($arg_maxuserlen);
	my $domain = get_salt(15);
	my $identity = Encode::encode("UTF-16LE", uc($user).$domain);
	my $s_challenge = get_iv(8);
	my $c_challenge = get_content(8);
	my $temp = '\x01\x01' . "\x00"x6 . "abdegagt" . $c_challenge . "\x00"x4 . "flasjhstgluahr" . '\x00';
	my $ntproofstr = _hmacmd5(_hmacmd5($nthash, $identity), $s_challenge.$temp);
	# $ntresponse = $ntproofstr.$temp but we separate them with a :
	#printf("%s\\%s:::%s:%s:%s::%s:netntlmv2\n", $domain, $user, unpack("H*",$s_challenge), unpack("H*",$ntproofstr), unpack("H*",$temp), $_[0]);
	$l0pht_fmt = 1;
	return "$domain\\$user".":::".unpack("H*",$s_challenge).":".unpack("H*",$ntproofstr).":".unpack("H*",$temp);
}
sub mschapv2 {
	require Crypt::ECB;
	import Crypt::ECB qw(encrypt);
	my $pwd = $_[1];
	my $nthash = md4(encode("UTF-16LE", $pwd));
	my $user = get_username($arg_maxuserlen);
	my $p_challenge = get_iv(16);
	my $a_challenge = get_content(16);
	my $ctx = Digest::SHA->new('sha1');
	$ctx->add($p_challenge);
	$ctx->add($a_challenge);
	$ctx->add($user);
	my $challenge = substr($ctx->digest, 0, 8);
	my $response = Crypt::ECB::encrypt(setup_des_key(substr($nthash, 0, 7)), 'DES', $challenge, ecb_padding_none);
	$response .= Crypt::ECB::encrypt(setup_des_key(substr($nthash, 7, 7)), 'DES', $challenge, ecb_padding_none);
	$response .= Crypt::ECB::encrypt(setup_des_key(substr($nthash . "\x00" x 5, 14, 7)), 'DES', $challenge, ecb_padding_none);
	#printf("%s:::%s:%s:%s::%s:mschapv2\n", $user, unpack("H*",$a_challenge), unpack("H*",$response), unpack("H*",$p_challenge), $_[0]);
	$l0pht_fmt = 1;
	return "$user".":::".unpack("H*",$a_challenge).":".unpack("H*",$response).":".unpack("H*",$p_challenge);
}
sub crc_32 {
	my $pwd = $_[1];
	if (rand(256) > 245) {
		my $init = rand(2000000000);
		return "\$crc32\$".unpack("H*",Uint32BERaw($init)).".".unpack("H*",Uint32BERaw(crc32($pwd,$init)));
	} else {
		return "\$crc32\$00000000.".unpack("H*",Uint32BERaw(crc32($pwd)));
	}
}
sub dummy {
	return '$dummy$'.unpack('H*', $_[1]);
}
sub raw_gost {
	require Digest::GOST;
	import Digest::GOST qw(gost gost_hex gost_base64);
	return "\$gost\$".gost_hex($_[1]);
}
sub raw_gost_cp {
	# HMMM.  Not sure how to do this at this time in perl.
	#print STDERR "raw_gost_cp : THIS ONE STILL LEFT TO DO\n";
}
sub pwsafe {
	$salt=get_salt(32);
	my $digest = sha256($_[1],$salt);
	my $loops = get_loops(2048);
	my $i;
	for ($i = 0; $i <= $loops; ++$i) {
		$digest = sha256($digest);
	}
	return "\$pwsafe\$\*3\*".unpack('H*', $salt)."\*$loops\*".unpack('H*', $digest);
}
sub django {
	$salt=get_salt(12,-32);
	my $loops = get_loops(10000);
	return "\$django\$\*1\*pbkdf2_sha256\$$loops\$$salt\$".base64(pp_pbkdf2($_[1], $salt, $loops, "sha256", 32, 64));
}
sub django_scrypt {
	$out_username = get_username($arg_maxuserlen);
	require Crypt::ScryptKDF;
	import Crypt::ScryptKDF qw(scrypt_b64);
	$salt=get_salt(12,12,\@i64);
	my $N = get_loops(14);
	my $r=8; my $p=1; my $bytes=64;
	my $h = scrypt_b64($_[1],$salt,1<<$N,$r,$p,$bytes);
	return "scrypt\$$salt\$$N\$$r\$$p\$$bytes\$$h";
}
sub scrypt {
	$out_username = get_username($arg_maxuserlen);
	require Crypt::ScryptKDF;
	import Crypt::ScryptKDF qw(scrypt_raw);
	$salt=get_salt(12,-64,\@i64);
	my $N=14; my $r=8; my $p=1; my $bytes=32;
	my $h = base64i(scrypt_raw($_[1],$salt,1<<$N,$r,$p,$bytes));
	# C is 14, 6.... is 8 and /.... is 1  ($N, $r, $p)
	if (length($h) > 43) { $h = substr($h,0,43); }
	return "\$7\$C6..../....$salt\$".$h;
}
sub aix_ssha1 {
	$salt=get_salt(16);
	return "{ssha1}06\$$salt\$".base64_aix(pp_pbkdf2($_[1],$salt,(1<<6),"sha1",20, 64));
}
sub aix_ssha256 {
	$salt=get_salt(16);
	return "{ssha256}06\$$salt\$".base64_aix(pp_pbkdf2($_[1],$salt,(1<<6),"sha256",32, 64));
}
sub aix_ssha512 {
	$salt=get_salt(16);
	return "{ssha512}06\$$salt\$".base64_aix(pp_pbkdf2($_[1],$salt,(1<<6),"sha512",64, 128));
}
# there are many 'formats' handled, but we just do the cannonical $pbkdf2-hmac-sha512$ one.
# there could also be $ml$ and grub.pbkdf2.sha512. as the signatures. but within prepare() of pbkdf2-hmac-sha512_fmt,
# they all get converted to this one, so that is all I plan on using.
sub pbkdf2_hmac_sha512 {
	$salt=get_salt(16,-107);
	my $itr = get_loops(10000);
	return "\$pbkdf2-hmac-sha512\$${itr}.".unpack("H*", $salt).".".pp_pbkdf2_hex($_[1],$salt,$itr,"sha512",64, 128);
}
sub pbkdf2_hmac_sha256 {
	$out_username = get_username($arg_maxuserlen);
	$salt=get_salt(16, -179);
	my $itr = get_loops(12000);
	my $s64 = base64pl($salt);
	my $h64 = substr(base64pl(pack("H*",pp_pbkdf2_hex($_[1],$salt,$itr,"sha256",32, 64))),0,43);
	while (substr($s64, length($s64)-1) eq "=") { $s64 = substr($s64, 0, length($s64)-1); }
	return "\$pbkdf2-sha256\$${itr}\$${s64}\$${h64}";
}
sub pbkdf2_hmac_sha1 {
	$salt=get_salt(16, -179);
	my $itr = get_loops(1000);
	return "\$pbkdf2-hmac-sha1\$${itr}.".unpack("H*", $salt).".".pp_pbkdf2_hex($_[1],$salt,$itr,"sha1",20, 64);
}
sub pbkdf2_hmac_md4 {
	$salt=get_salt(16, -179);
	my $itr = get_loops(1000);
	return "\$pbkdf2-hmac-md4\$${itr}\$".unpack("H*", $salt).'$'.pp_pbkdf2_hex($_[1],$salt,$itr,"md4",16, 64);
}
sub pbkdf2_hmac_md5 {
	$salt=get_salt(16, -179);
	my $itr = get_loops(1000);
	return "\$pbkdf2-hmac-md5\$${itr}\$".unpack("H*", $salt).'$'.pp_pbkdf2_hex($_[1],$salt,$itr,"md5",16, 64);
}
sub pbkdf2_hmac_sha1_pkcs5s2 {
	$salt=get_salt(16);
	my $itr = get_loops(10000);
	my $h = base64pl($salt.pp_pbkdf2($_[1],$salt,$itr,"sha1",20, 64));
	return "{PKCS5S2}$h";
}
sub pbkdf2_hmac_sha1_p5k2 {
	$salt=get_salt(16);
	my $itr = get_loops(1000);
	my $itrs = sprintf("%x", $itr);
	return "\$p5k2\$$itrs\$".base64($salt).'$'.base64(pack("H*",pp_pbkdf2_hex($_[1],$salt,$itr,"sha1",20, 64)));
}
sub drupal7 {
	$salt=get_salt(8,-8);
	# We only handle the 'C' count (16384)
	my $h = sha512($salt.$_[1]);
	my $i = 16384;
	do { $h = sha512($h.$_[1]); } while (--$i > 0);
	return "\$S\$C".$salt.substr(base64i($h),0,43);
}
sub epi {
	$salt=get_salt(30);
	return "0x".uc(unpack("H*", $salt))." 0x".uc(sha1_hex(substr($salt,0,29),$_[1], "\0"));
}
sub episerver_sha1 {
	$salt=get_salt(16);
	return "\$episerver\$\*0\*".base64($salt)."\*".sha1_base64($salt, Encode::encode("UTF-16LE", $_[1]));
}
sub episerver_sha256 {
	$salt=get_salt(16);
	return "\$episerver\$\*1\*".base64($salt)."\*".sha256_base64($salt, Encode::encode("UTF-16LE", $_[1]));
}
sub hmailserver {
	$salt=get_salt(6,6,\@chrHexLo);
	return "$salt".sha256_hex($salt,$_[1]);
}
sub nukedclan {
	$salt=get_salt(20, 20, \@chrAsciiTextNum);
	my $decal=get_iv(1, \@chrHexLo);
	my $pass_hash = sha1_hex($_[1]);
	my $i = 0; my $k;
	$k = hex($decal);

	my $out = "";
	for (; $i < 40; $i += 1, $k += 1) {
		$out .= substr($pass_hash, $i, 1);
		if ($k > 19) { $k = 0; }
		$out .= substr($salt, $k, 1);
	}
	return "\$nk\$\*".unpack("H*", $salt)."\*#$decal".md5_hex($out);
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
	my $cnt=get_iv(3, \@chrAsciiNum);
	if (defined $argmode) {$cnt=$argmode;}
	my $h = md5($salt.$_[1]);
	$h = skey_fold($h, 4);
	my $i = $cnt;
	while ($i-- > 0) {
		$h = md5($h);
		$h = skey_fold($h, 4)
	}
	return "md5 $cnt $salt ".unpack("H*", $h);
}
sub skey_md4 {
	$salt=get_salt(8, 8, \@chrAsciiTextNumLo);
	$salt = lc $salt;
	my $cnt=get_iv(3, \@chrAsciiNum);
	if (defined $argmode) {$cnt=$argmode;}
	my $h = md4($salt.$_[1]);
	$h = skey_fold($h, 4);
	my $i = $cnt;
	while ($i-- > 0) {
		$h = md4($h);
		$h = skey_fold($h, 4)
	}
	return "md4 $cnt $salt ".unpack("H*", $h);
}
sub skey_sha1 {
	$salt=get_salt(8, 8, \@chrAsciiTextNumLo);
	$salt = lc $salt;
	my $cnt=get_iv(3, \@chrAsciiNum);
	if (defined $argmode) {$cnt=$argmode;}
	my $h = sha1($salt.$_[1]);
	$h = skey_fold($h, 5);
	my $i = $cnt;
	while ($i-- > 0) {
		$h = sha1($h);
		$h = skey_fold($h, 5)
	}
	return "sha1 $cnt $salt ".unpack("H*", $h);
}
sub skey_rmd160 {
	$salt=get_salt(8, 8, \@chrAsciiTextNumLo);
	$salt = lc $salt;
	my $cnt=get_iv(3, \@chrAsciiNum);
	if (defined $argmode) {$cnt=$argmode;}
	my $h = ripemd160($salt.$_[1]);
	$h = skey_fold($h, 5);
	my $i = $cnt;
	while ($i-- > 0) {
		$h = ripemd160($h);
		$h = skey_fold($h, 5)
	}
	return "rmd160 $cnt $salt ".unpack("H*", $h);
}
sub radmin {
	my $pass = $_[1];
	while (length($pass) < 100) { $pass .= "\0"; }
	return "\$radmin2\$".md5_hex($pass);
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
	return unpack("H*",$h);
}
sub sybasease {
	$salt=get_salt(8, 8, \@chrAsciiTextNum);
	my $h = Encode::encode("UTF-16BE", $_[0]);
	while (length($h) < 510) { $h .= "\0\0"; }
	return "0xc007".unpack("H*",$salt).sha256_hex($h.$salt);
}
sub wbb3 {
	# Simply 'dynamic' format:  sha1($s.sha1($s.sha1($p)))
	$salt=get_salt(40, 40, \@chrHexLo);
	return "\$wbb3\$\*1\*$salt\*".sha1_hex($salt,sha1_hex($salt,sha1_hex($_[1])));
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
sub pad100 { # used by pad100($p)  This will null pad a string to 100 bytes long for dyna1010
	my $p = $_[0];
	while (length($p) < 100) {
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

sub dynamic_17 { #dynamic_17 --> phpass ($P$ or $H$)	phpass
	$salt=get_salt(8);
	my $h = phpass_hash($_[1], 11, $salt);
	return "\$dynamic_17\$".substr(base64i($h),0,22)."\$".to_phpbyte(11).$salt;
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
	return "\$dynamic_19\$$h";
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
	return "\$dynamic_20\$$h\$$salt";
}
sub dynamic_27 { #dynamic_27 --> OpenBSD MD5
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(8); }
	$h = md5crypt_hash($_[1], $salt, "\$1\$");
	return "\$dynamic_27\$".substr($h,15)."\$$salt";
}
sub dynamic_28 { # Apache MD5
	if (defined $argsalt) { $salt = $argsalt; } else { $salt=randstr(8); }
	$h = md5crypt_hash($_[1], $salt, "\$apr1\$");
	return "\$dynamic_28\$".substr($h,15)."\$$salt";
}
sub dynamic_1590 {
	# as400-ssha1
	$out_username = get_username(10);
	my $uname = uc $out_username;
	while (length($uname) < 10) { $uname .= ' '; }
	return '$dynamic_1590$'.uc unpack("H*",sha1(encode("UTF-16BE", $uname.$_[1]))) . '$HEX$' . uc unpack("H*",encode("UTF-16BE", $uname));
}
sub dynamic_compile {
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
		# NOTE, there is also debug=1 will dump the symtab, and optimize=1 optimizes the parse.
		print STDERR "\n";
		print STDERR "The FMT_EXPR is somewhat 'normal' php type format, with some extensions.\n";
		print STDERR "    A format such as md5(\$p.\$s.md5(\$p)) is 'normal'.  Dots must be used\n";
		print STDERR "    where needed. Also, only a SINGLE expression is valid.  Using an\n";
		print STDERR "    expression such as md5(\$p).md5(\$s) is not valid.\n";
		print STDERR "    The extensions are:\n";
		print STDERR "        Added \$s2 (if 2nd salt is defined),\n";
		print STDERR "        Added \$c1 to \$c9 for constants (must be defined in const#= values)\n";
		print STDERR "        Added \$u if user name (normal, upper/lower case or unicode convert)\n";
		print STDERR "        Handle utf16() and utf16be() for items. So md5(utf16(\$p)) gives md5 of unicode password\n";
		print STDERR "        Handle md5, sha1, md4 sha2 (sha224,sha256,sha384,sha512) gost whirlpool tiger and haval crypts.\n";
		print STDERR "        Handle MD5, SHA1, MD4 SHA2 (all uc(sha2) types) GOST WHILRPOOL TIGER HAVAL which output hex in uppercase.\n";
		print STDERR "        Handle md5_64, sha1_64, md4_64, sha2*_64 gost_64 whirlpool_64 tiger_64 haval_64 which output in\n";
		print STDERR "          'mime-standard' base-64 which is \"A-Za-z0-9+/\"\n";
		print STDERR "        Handle md5_64c, sha1_64c, md4_64c, sha2*_64c gost_64c, whirlpool_64c which output in\n";
		print STDERR "          'crypt character set' base-64 which is \"./0-9A-Za-z\" \n";
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

		if ($dynamic_args >= 50 && $dynamic_args <= 1000) {
			my $dyna_func_which = $dynamic_args%10;
			my $dyna_func_range = $dynamic_args-$dyna_func_which;
			my %dyna_hashes = (
				50=>'sha224',		60=>'sha256',		70=>'sha384',	80=>'sha512',	90=>'gost',
				100=>'whirlpool',	110=>'tiger',		120=>'ripemd128',	130=>'ripemd160',	140=>'ripemd256',
				150=>'ripemd320',	370=>'sha3_224',	380=>'sha3_256',	390=>'sha3_384',	400=>'sha3_512',
				410=>'keccak_256',	420=>'keccak_512',	310=>'md2' );

# NOTE, these are still part of dynamic in JtR, but may not be handled here.
# Some may NOT be able to be done within perl.  Haval does have some Perl
# support, but not nearly as much as john has.  Skein is the wrong version
# perl is v1.2 and john is v1.3. John implements skein-512-224 skein-512-256
# skein-512-384 and skein-512-512
#dynamic_160 -->haval128_3($p)
#dynamic_170 -->haval128_4($p)
#dynamic_180 -->haval128_5($p)
#dynamic_190 -->haval160_3($p)
#dynamic_200 -->haval160_4($p)
#dynamic_210 -->haval160_5($p)
#dynamic_220 -->haval192_3($p)
#dynamic_230 -->haval192_4($p)
#dynamic_240 -->haval192_5($p)
#dynamic_250 -->haval224_3($p)
#dynamic_260 -->haval224_4($p)
#dynamic_270 -->haval224_5($p)
#dynamic_280 -->haval256_3($p)
#dynamic_290 -->haval256_4($p)
#dynamic_300 -->haval256_5($p)
#dynamic_320 -->panama($p)
#dynamic_330 -->skein224($p)
#dynamic_340 -->skein256($p)
#dynamic_350 -->skein384($p)
#dynamic_360 -->skein512($p)
			my $ht = $dyna_hashes{$dynamic_args-$dyna_func_which};
			if (!defined($ht)) { return $func; }
			SWITCH: {
				$dyna_func_which==0 && do {$fmt="$ht(\$p)";							last SWITCH; };
				$dyna_func_which==1 && do {$fmt="$ht(\$s.\$p),saltlen=6";			last SWITCH; };
				$dyna_func_which==2 && do {$fmt="$ht(\$p.\$s)";						last SWITCH; };
				$dyna_func_which==3 && do {$fmt="$ht($ht(\$p))";					last SWITCH; };
				$dyna_func_which==4 && do {$fmt="$ht($ht"."_raw(\$p))";				last SWITCH; };
				$dyna_func_which==5 && do {$fmt="$ht($ht(\$p).\$s),saltlen=6";		last SWITCH; };
				$dyna_func_which==6 && do {$fmt="$ht(\$s.$ht(\$p)),saltlen=6";		last SWITCH; };
				$dyna_func_which==7 && do {$fmt="$ht($ht(\$s).$ht(\$p)),saltlen=6";	last SWITCH; };
				$dyna_func_which==8 && do {$fmt="$ht($ht(\$p).$ht(\$p))";			last SWITCH; };
				return $func;
			}
		} else {
		SWITCH: {
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
			$dynamic_args==29 && do {$fmt='md5(utf16($p))';				last SWITCH; };
			$dynamic_args==30 && do {$fmt='md4($p)';					last SWITCH; };
			$dynamic_args==31 && do {$fmt='md4($s.$p)';					last SWITCH; };
			$dynamic_args==32 && do {$fmt='md4($p.$s)';					last SWITCH; };
			$dynamic_args==33 && do {$fmt='md4(utf16($p))';				last SWITCH; };
			$dynamic_args==34 && do {$fmt='md5(md4($p))';				last SWITCH; };
			$dynamic_args==35 && do {$fmt='sha1($u.$c1.$p),usrname=uc,const1=:';	last SWITCH; };
			$dynamic_args==36 && do {$fmt='sha1($u.$c1.$p),usrname=true,const1=:';	last SWITCH; };
			$dynamic_args==37 && do {$fmt='sha1($u.$p),usrname=lc';					last SWITCH; };
			$dynamic_args==38 && do {$fmt='sha1($s.sha1($s.sha1($p))),saltlen=20';	last SWITCH; };
			$dynamic_args==39 && do {$fmt='md5($s.pad16($p)),saltlen=60';			last SWITCH; };
			$dynamic_args==40 && do {$fmt='sha1($s.pad20($p)),saltlen=60';			last SWITCH; };

			# 7, 17, 19, 20, 21, 27, 28 are still handled by 'special' functions.

			# since these are in dynamic.conf, and treatly 'like' builtins, we might as well put them here.
			$dynamic_args==1001 && do {$fmt='md5(md5(md5(md5($p))))';						last SWITCH; };
			$dynamic_args==1002 && do {$fmt='md5(md5(md5(md5(md5($p)))))';					last SWITCH; };
			$dynamic_args==1003 && do {$fmt='md5(md5($p).md5($p))';							last SWITCH; };
			$dynamic_args==1004 && do {$fmt='md5(md5(md5(md5(md5(md5($p))))))';				last SWITCH; };
			$dynamic_args==1005 && do {$fmt='md5(md5(md5(md5(md5(md5(md5($p)))))))';		last SWITCH; };
			$dynamic_args==1006 && do {$fmt='md5(md5(md5(md5(md5(md5(md5(md5($p))))))))';	last SWITCH; };
			$dynamic_args==1007 && do {$fmt='md5(md5($p).$s),saltlen=3';					last SWITCH; };
			$dynamic_args==1008 && do {$fmt='md5($p.$s),saltlen=16';						last SWITCH; };
			$dynamic_args==1009 && do {$fmt='md5($s.$p),saltlen=16';						last SWITCH; };
			$dynamic_args==1010 && do {$fmt='md5(pad100($p))';								last SWITCH; };
			$dynamic_args==1011 && do {$fmt='md5($p.md5($s)),saltlen=6';					last SWITCH; };
			$dynamic_args==1012 && do {$fmt='md5($p.md5($s)),saltlen=6';					last SWITCH; };
			$dynamic_args==1013 && do {$fmt='md5($p.$s),usrname=md5_hex_salt';				last SWITCH; };
			$dynamic_args==1014 && do {$fmt='md5($p.$s),saltlen=56';						last SWITCH; };
			$dynamic_args==1015 && do {$fmt='md5(md5($p.$u).$s),saltlen=6,username';		last SWITCH; };
			$dynamic_args==1016 && do {$fmt='md5($p.$s),saltlen=-64';						last SWITCH; };
			$dynamic_args==1017 && do {$fmt='md5($s.$p),saltlen=-64';						last SWITCH; };
			$dynamic_args==1018 && do {$fmt='md5(sha1(sha1($p)))';							last SWITCH; };
			$dynamic_args==1019 && do {$fmt='md5(sha1(sha1(md5($p))))';						last SWITCH; };
			$dynamic_args==1020 && do {$fmt='md5(sha1(md5($p)))';							last SWITCH; };
			$dynamic_args==1021 && do {$fmt='md5(sha1(md5(sha1($p))))';						last SWITCH; };
			$dynamic_args==1022 && do {$fmt='md5(sha1(md5(sha1(md5($p)))))';				last SWITCH; };
			$dynamic_args==1023 && do {$fmt='trunc32(sha1($p))';							last SWITCH; };
			$dynamic_args==1024 && do {$fmt='trunc32(sha1(md5($p)))';						last SWITCH; };
			$dynamic_args==1025 && do {$fmt='trunc32(sha1(md5(md5($p))))';					last SWITCH; };
			$dynamic_args==1026 && do {$fmt='trunc32(sha1(sha1($p)))';						last SWITCH; };
			$dynamic_args==1027 && do {$fmt='trunc32(sha1(sha1(sha1($p))))';				last SWITCH; };
			$dynamic_args==1028 && do {$fmt='trunc32(sha1(sha1_raw($p)))';					last SWITCH; };
			$dynamic_args==1029 && do {$fmt='trunc32(sha256($p))';							last SWITCH; };
			$dynamic_args==1030 && do {$fmt='trunc32(whirlpool($p))';						last SWITCH; };
			$dynamic_args==1031 && do {$fmt='trunc32(gost($p))';							last SWITCH; };
			$dynamic_args==1032 && do {$fmt='sha1_64(utf16($p))';							last SWITCH; };
			$dynamic_args==1033 && do {$fmt='sha1_64(utf16($p).$s)';						last SWITCH; };
			$dynamic_args==1300 && do {$fmt='md5(md5_raw($p))';								last SWITCH; };
			$dynamic_args==1350 && do {$fmt='md5(md5($s.$p).$c1.$s),saltlen=2,const1=:';	last SWITCH; };
			$dynamic_args==1400 && do {$fmt='sha1(utf16($p))';								last SWITCH; };
			$dynamic_args==1401 && do {$fmt='md5_40($u.$c1.$p),const1='."\n".'skyper'."\n,usrname=true";	last SWITCH; };
			$dynamic_args==1501 && do {$fmt='sha1($s.sha1($p)),saltlen=32';					last SWITCH; };
			$dynamic_args==1502 && do {$fmt='sha1(sha1($p).$s),saltlen=-32';				last SWITCH; };
			$dynamic_args==1503 && do {$fmt='sha256(sha256($p).$s),saltlen=64';				last SWITCH; };
			$dynamic_args==1504 && do {$fmt='sha1($s.$p.$s)';								last SWITCH; };
			$dynamic_args==1505 && do {$fmt='md5($p.$s.md5($p.$s)),saltlen=-64';			last SWITCH; };
			$dynamic_args==1506 && do {$fmt='md5($u.$c1.$p),const1=:XDB:,usrname=true';		last SWITCH; };
			$dynamic_args==1507 && do {$fmt='sha1($c1.utf16($p)),const1='."\x01\x00\x0f\x00\x0d\x00\x33\x00";		last SWITCH; };
			$dynamic_args==1588 && do {$fmt='SHA256($s.SHA1($p)),saltlen=64,salt=asHEX64';	last SWITCH; };
			$dynamic_args==2000 && do {$fmt='md5($p)';										last SWITCH; };
			$dynamic_args==2001 && do {$fmt='md5($p.$s),saltlen=32';						last SWITCH; };
			$dynamic_args==2002 && do {$fmt='md5(md5($p))';									last SWITCH; };
			$dynamic_args==2003 && do {$fmt='md5(md5(md5($p)))';							last SWITCH; };
			$dynamic_args==2004 && do {$fmt='md5($s.$p),saltlen=2';							last SWITCH; };
			$dynamic_args==2005 && do {$fmt='md5($s.$p.$s)';								last SWITCH; };
			$dynamic_args==2006 && do {$fmt='md5(md5($p).$s)';								last SWITCH; };
			$dynamic_args==2008 && do {$fmt='md5(md5($s).$p)';								last SWITCH; };
			$dynamic_args==2009 && do {$fmt='md5($s.md5($p))';								last SWITCH; };
			$dynamic_args==2010 && do {$fmt='md5($s.md5($s.$p))';							last SWITCH; };
			$dynamic_args==2011 && do {$fmt='md5($s.md5($p.$s))';							last SWITCH; };
			$dynamic_args==2014 && do {$fmt='md5($s.md5($p).$s)';							last SWITCH; };

			return $func;
		}
		}
		# allow the generic compiler to handle these types.
		$dynamic_args = $prefmt.$fmt;
	}

	# now compile.
	dynamic_compile_to_pcode($dynamic_args);

	#return the name of the function to run the compiled pcode.
	return "dynamic_run_compiled_pcode";
}
sub dyna_addtok {
	push(@gen_toks, $_[0]);
	return $_[1];
}
sub do_dynamic_GetToken {
	# parses next token.
	# the token is placed on the gen_toks array as the 'new' token.
	#  the return is the rest of the string (not tokenized yet)
	# if there is an error, then "tok_bad" (X) is pushed on to the top of the gen_toks array.
	$gen_lastTokIsFunc = 0;
	my $exprStr = $_[0];
	if (!defined($exprStr) || length($exprStr) == 0) { return dyna_addtok("X", $exprStr); }
	my $stmp = substr($exprStr, 0, 1);
	if ($stmp eq "." || $stmp eq "(" || $stmp eq ")") {
		return dyna_addtok(substr($exprStr, 0, 1), substr($exprStr, 1));
	}
	if ($stmp eq '$') {
		$stmp = substr($exprStr, 0, 2);
		if ($stmp eq '$p' || $stmp eq '$u') { return dyna_addtok(substr($exprStr,1,1), substr($exprStr, 2)); }
		if ($stmp eq '$s') {
			if (substr($exprStr, 0, 3) eq '$s2') { return dyna_addtok("S", substr($exprStr, 3)); }
			return dyna_addtok("s", substr($exprStr, 2));
		}
		if ($stmp ne '$c') { return dyna_addtok("X", $exprStr); }
		$stmp = substr($exprStr, 2, 1);
		if ($stmp < 1 || $stmp > 9) {  return dyna_addtok("X", $exprStr); }
		my $sRet = dyna_addtok($stmp, substr($exprStr, 3));
		if (!defined($gen_c[$stmp-1])) {print STDERR "\$c$stmp found, but no const$stmp loaded\n"; die; }
		return $sRet;
	}

	$gen_lastTokIsFunc=2; # a func, but can NOT be the 'outside' function.
	if (substr($exprStr, 0, 7) eq "md5_raw")    { return dyna_addtok("f5r", substr($exprStr, 7)); }
	if (substr($exprStr, 0, 8) eq "sha1_raw")   { return dyna_addtok("f1r", substr($exprStr, 8)); }
	if (substr($exprStr, 0, 7) eq "md4_raw")    { return dyna_addtok("f4r", substr($exprStr, 7)); }
	if (substr($exprStr, 0,10) eq "sha224_raw") { return dyna_addtok("f224r", substr($exprStr,10)); }
	if (substr($exprStr, 0,10) eq "sha256_raw") { return dyna_addtok("f256r", substr($exprStr,10)); }
	if (substr($exprStr, 0,10) eq "sha384_raw") { return dyna_addtok("f384r", substr($exprStr,10)); }
	if (substr($exprStr, 0,10) eq "sha512_raw") { return dyna_addtok("f512r", substr($exprStr,10)); }
	if (substr($exprStr, 0,12) eq "sha3_224_raw") { return dyna_addtok("fsha3_224r", substr($exprStr,12)); }
	if (substr($exprStr, 0,12) eq "sha3_256_raw") { return dyna_addtok("fsha3_256r", substr($exprStr,12)); }
	if (substr($exprStr, 0,12) eq "sha3_384_raw") { return dyna_addtok("fsha3_384r", substr($exprStr,12)); }
	if (substr($exprStr, 0,12) eq "sha3_512_raw") { return dyna_addtok("fsha3_512r", substr($exprStr,12)); }
	if (substr($exprStr, 0,14) eq "keccak_256_raw") { return dyna_addtok("fkeccak_256r", substr($exprStr,14)); }
	if (substr($exprStr, 0,14) eq "keccak_512_raw") { return dyna_addtok("fkeccak_512r", substr($exprStr,14)); }
	if (substr($exprStr, 0, 7) eq "md2_raw") { return dyna_addtok("fmd2r", substr($exprStr, 7)); }
	if (substr($exprStr, 0, 8) eq "gost_raw")   { return dyna_addtok("fgostr",substr($exprStr, 8)); }
	if (substr($exprStr, 0,13) eq "whirlpool_raw") { return dyna_addtok("fwrlpr", substr($exprStr, 13)); }
	if (substr($exprStr, 0, 9) eq "tiger_raw")     { return dyna_addtok("ftigr", substr($exprStr, 9)); }
	if (substr($exprStr, 0,13) eq "ripemd128_raw") { return dyna_addtok("frip128r", substr($exprStr,13)); }
	if (substr($exprStr, 0,13) eq "ripemd160_raw") { return dyna_addtok("frip160r", substr($exprStr,13)); }
	if (substr($exprStr, 0,13) eq "ripemd256_raw") { return dyna_addtok("frip256r", substr($exprStr,13)); }
	if (substr($exprStr, 0,13) eq "ripemd320_raw") { return dyna_addtok("frip320r", substr($exprStr,13)); }
	if (substr($exprStr, 0,12) eq "haval256_raw")  { return dyna_addtok("fhavr", substr($exprStr,12)); }
	if (substr($exprStr, 0,5)  eq "pad16")         { return dyna_addtok("fpad16", substr($exprStr,5)); }
	if (substr($exprStr, 0,5)  eq "pad20")         { return dyna_addtok("fpad20", substr($exprStr,5)); }
	if (substr($exprStr, 0,6)  eq "pad100")        { return dyna_addtok("fpad100", substr($exprStr,6)); }
	if (substr($exprStr, 0,7)  eq "padmd64")       { return dyna_addtok("fpadmd64", substr($exprStr,7)); }
	if (substr($exprStr, 0,7)  eq "utf16be")       { return dyna_addtok("futf16be", substr($exprStr,7)); }
	if (substr($exprStr, 0,5)  eq "utf16")         { return dyna_addtok("futf16", substr($exprStr,5)); }

	$gen_lastTokIsFunc=1;
	$stmp = uc substr($exprStr, 0, 3);
	if ($stmp eq "MD5") {
		if (substr($exprStr, 0, 7) eq "md5_64c") { return dyna_addtok("f5c", substr($exprStr, 7)); }
		if (substr($exprStr, 0, 6) eq "md5_64")  { return dyna_addtok("f56", substr($exprStr, 6)); }
		#md5_40 is used by dyna_1401, which is md5, but pads (with 0's) to 20 bytes, not 16
		if (substr($exprStr, 0, 6) eq "md5_40")  { return dyna_addtok("f54", substr($exprStr, 6)); }
		if (substr($exprStr, 0, 3) eq "md5")     { return dyna_addtok("f5h", substr($exprStr, 3)); }
		if (substr($exprStr, 0, 3) eq "MD5")     { return dyna_addtok("f5H", substr($exprStr, 3)); }
	} elsif ($stmp eq "SHA") {
		if (substr($exprStr, 0, 8) eq "sha1_64c")  { return dyna_addtok("f1c", substr($exprStr, 8)); }
		if (substr($exprStr, 0, 7) eq "sha1_64")   { return dyna_addtok("f16", substr($exprStr, 7)); }
		if (substr($exprStr, 0, 4) eq "SHA1")      { return dyna_addtok("f1H", substr($exprStr, 4)); }
		if (substr($exprStr, 0, 4) eq "sha1")      { return dyna_addtok("f1h", substr($exprStr, 4)); }
		if (substr($exprStr, 0,10) eq "sha224_64c"){ return dyna_addtok("f224c", substr($exprStr, 10)); }
		if (substr($exprStr, 0, 9) eq "sha224_64") { return dyna_addtok("f2246", substr($exprStr, 9)); }
		if (substr($exprStr, 0, 6) eq "SHA224")    { return dyna_addtok("f224H", substr($exprStr, 6)); }
		if (substr($exprStr, 0, 6) eq "sha224")    { return dyna_addtok("f224h", substr($exprStr, 6)); }
		if (substr($exprStr, 0,10) eq "sha256_64c"){ return dyna_addtok("f256c", substr($exprStr, 10)); }
		if (substr($exprStr, 0, 9) eq "sha256_64") { return dyna_addtok("f2566", substr($exprStr, 9)); }
		if (substr($exprStr, 0, 6) eq "SHA256")    { return dyna_addtok("f256H", substr($exprStr, 6)); }
		if (substr($exprStr, 0, 6) eq "sha256")    { return dyna_addtok("f256h", substr($exprStr, 6)); }
		if (substr($exprStr, 0,10) eq "sha384_64c"){ return dyna_addtok("f384c", substr($exprStr, 10)); }
		if (substr($exprStr, 0, 9) eq "sha384_64") { return dyna_addtok("f3846", substr($exprStr, 9)); }
		if (substr($exprStr, 0, 6) eq "SHA384")    { return dyna_addtok("f384H", substr($exprStr, 6)); }
		if (substr($exprStr, 0, 6) eq "sha384")    { return dyna_addtok("f384h", substr($exprStr, 6)); }
		if (substr($exprStr, 0,10) eq "sha512_64c"){ return dyna_addtok("f512c", substr($exprStr, 10)); }
		if (substr($exprStr, 0, 9) eq "sha512_64") { return dyna_addtok("f5126", substr($exprStr, 9)); }
		if (substr($exprStr, 0, 6) eq "SHA512")    { return dyna_addtok("f512H", substr($exprStr, 6)); }
		if (substr($exprStr, 0, 6) eq "sha512")    { return dyna_addtok("f512h", substr($exprStr, 6)); }
		if (substr($exprStr, 0,12) eq "sha3_224_64c"){ return dyna_addtok("fsha3_224c", substr($exprStr, 12)); }
		if (substr($exprStr, 0,11) eq "sha3_224_64") { return dyna_addtok("fsha3_2246", substr($exprStr, 11)); }
		if (substr($exprStr, 0, 8) eq "SHA3_224")    { return dyna_addtok("fsha3_224H", substr($exprStr, 8)); }
		if (substr($exprStr, 0, 8) eq "sha3_224")    { return dyna_addtok("fsha3_224h", substr($exprStr, 8)); }
		if (substr($exprStr, 0,12) eq "sha3_256_64c"){ return dyna_addtok("fsha3_256c", substr($exprStr, 12)); }
		if (substr($exprStr, 0,11) eq "sha3_256_64") { return dyna_addtok("fsha3_2566", substr($exprStr, 11)); }
		if (substr($exprStr, 0, 8) eq "SHA3_256")    { return dyna_addtok("fsha3_256H", substr($exprStr, 8)); }
		if (substr($exprStr, 0, 8) eq "sha3_256")    { return dyna_addtok("fsha3_256h", substr($exprStr, 8)); }
		if (substr($exprStr, 0,12) eq "sha3_384_64c"){ return dyna_addtok("fsha3_384c", substr($exprStr, 12)); }
		if (substr($exprStr, 0,11) eq "sha3_384_64") { return dyna_addtok("fsha3_3846", substr($exprStr, 11)); }
		if (substr($exprStr, 0, 8) eq "SHA3_384")    { return dyna_addtok("fsha3_384H", substr($exprStr, 8)); }
		if (substr($exprStr, 0, 8) eq "sha3_384")    { return dyna_addtok("fsha3_384h", substr($exprStr, 8)); }
		if (substr($exprStr, 0,12) eq "sha3_512_64c"){ return dyna_addtok("fsha3_512c", substr($exprStr, 12)); }
		if (substr($exprStr, 0,11) eq "sha3_512_64") { return dyna_addtok("fsha3_5126", substr($exprStr, 11)); }
		if (substr($exprStr, 0, 8) eq "SHA3_512")    { return dyna_addtok("fsha3_512H", substr($exprStr, 8)); }
		if (substr($exprStr, 0, 8) eq "sha3_512")    { return dyna_addtok("fsha3_512h", substr($exprStr, 8)); }

	} elsif ($stmp eq "MD4") {
		if (substr($exprStr, 0, 7) eq "md4_64c")   { return dyna_addtok("f4c", substr($exprStr, 7)); }
		if (substr($exprStr, 0, 6) eq "md4_64")    { return dyna_addtok("f46", substr($exprStr, 6)); }
		if (substr($exprStr, 0, 3) eq "md4")       { return dyna_addtok("f4h", substr($exprStr, 3)); }
		if (substr($exprStr, 0, 3) eq "MD4")       { return dyna_addtok("f4H", substr($exprStr, 3)); }
	} elsif ($stmp eq "GOS") {
		if (substr($exprStr, 0, 8) eq "gost_64c")  { return dyna_addtok("fgostc", substr($exprStr, 8)); }
		if (substr($exprStr, 0, 7) eq "gost_64")   { return dyna_addtok("fgost6", substr($exprStr, 7)); }
		if (substr($exprStr, 0, 4) eq "GOST")      { return dyna_addtok("fgostH", substr($exprStr, 4)); }
		if (substr($exprStr, 0, 4) eq "gost")      { return dyna_addtok("fgosth", substr($exprStr, 4)); }
	} elsif ($stmp eq "WHI") {
		if (substr($exprStr, 0,13) eq "whirlpool_64c")  { return dyna_addtok("fwrlpc", substr($exprStr, 13)); }
		if (substr($exprStr, 0,12) eq "whirlpool_64")   { return dyna_addtok("fwrlp6", substr($exprStr, 12)); }
		if (substr($exprStr, 0, 9) eq "WHIRLPOOL")      { return dyna_addtok("fwrlpH", substr($exprStr, 9)); }
		if (substr($exprStr, 0, 9) eq "whirlpool")      { return dyna_addtok("fwrlph", substr($exprStr, 9)); }
	} elsif ($stmp eq "TIG") {
		if (substr($exprStr, 0, 9) eq "tiger_64c")  { return dyna_addtok("ftigc", substr($exprStr, 9)); }
		if (substr($exprStr, 0, 8) eq "tiger_64")   { return dyna_addtok("ftig6", substr($exprStr, 8)); }
		if (substr($exprStr, 0, 5) eq "TIGER")      { return dyna_addtok("ftigH", substr($exprStr, 5)); }
		if (substr($exprStr, 0, 5) eq "tiger")      { return dyna_addtok("ftigh", substr($exprStr, 5)); }
	} elsif ($stmp eq "RIP") {
		if (substr($exprStr, 0,13) eq "ripemd128_64c")  { return dyna_addtok("frip128c", substr($exprStr,13)); }
		if (substr($exprStr, 0,12) eq "ripemd128_64")   { return dyna_addtok("frip1286", substr($exprStr,12)); }
		if (substr($exprStr, 0, 9) eq "RIPEMD129")      { return dyna_addtok("frip128H", substr($exprStr, 9)); }
		if (substr($exprStr, 0, 9) eq "ripemd128")      { return dyna_addtok("frip128h", substr($exprStr, 9)); }
		if (substr($exprStr, 0,13) eq "ripemd160_64c")  { return dyna_addtok("frip160c", substr($exprStr,13)); }
		if (substr($exprStr, 0,12) eq "ripemd160_64")   { return dyna_addtok("frip1606", substr($exprStr,12)); }
		if (substr($exprStr, 0, 9) eq "RIPEMD160")      { return dyna_addtok("frip160H", substr($exprStr, 9)); }
		if (substr($exprStr, 0, 9) eq "ripemd160")      { return dyna_addtok("frip160h", substr($exprStr, 9)); }
		if (substr($exprStr, 0,13) eq "ripemd256_64c")  { return dyna_addtok("frip256c", substr($exprStr,13)); }
		if (substr($exprStr, 0,12) eq "ripemd256_64")   { return dyna_addtok("frip2566", substr($exprStr,12)); }
		if (substr($exprStr, 0, 9) eq "RIPEMD129")      { return dyna_addtok("frip256H", substr($exprStr, 9)); }
		if (substr($exprStr, 0, 9) eq "ripemd256")      { return dyna_addtok("frip256h", substr($exprStr, 9)); }
		if (substr($exprStr, 0,13) eq "ripemd320_64c")  { return dyna_addtok("frip320c", substr($exprStr,13)); }
		if (substr($exprStr, 0,12) eq "ripemd320_64")   { return dyna_addtok("frip3206", substr($exprStr,12)); }
		if (substr($exprStr, 0, 9) eq "RIPEMD129")      { return dyna_addtok("frip320H", substr($exprStr, 9)); }
		if (substr($exprStr, 0, 9) eq "ripemd320")      { return dyna_addtok("frip320h", substr($exprStr, 9)); }
	} elsif ($stmp eq "HAV") {
		if (substr($exprStr, 0,12) eq "haval256_64c")  { return dyna_addtok("fhavc", substr($exprStr,12)); }
		if (substr($exprStr, 0,11) eq "haval256_64")   { return dyna_addtok("fhav6", substr($exprStr,11)); }
		if (substr($exprStr, 0, 8) eq "HAVEL256")      { return dyna_addtok("fhavH", substr($exprStr, 8)); }
		if (substr($exprStr, 0, 8) eq "haval256")      { return dyna_addtok("fhavh", substr($exprStr, 8)); }
	} elsif ($stmp eq "TRU") {
		if (substr($exprStr, 0,7) eq "trunc32")  { return dyna_addtok("ftr32", substr($exprStr, 7)); }
	} elsif ($stmp eq "KEC") {
		if (substr($exprStr, 0,14) eq "keccak_256_64c"){ return dyna_addtok("fkeccak_256c", substr($exprStr, 14)); }
		if (substr($exprStr, 0,13) eq "keccak_256_64") { return dyna_addtok("fkeccak_2566", substr($exprStr, 13)); }
		if (substr($exprStr, 0,10) eq "KECCAK_256")    { return dyna_addtok("fkeccak_256H", substr($exprStr, 10)); }
		if (substr($exprStr, 0,10) eq "keccak_256")    { return dyna_addtok("fkeccak_256h", substr($exprStr, 10)); }
		if (substr($exprStr, 0,14) eq "keccak_512_64c"){ return dyna_addtok("fkeccak_512c", substr($exprStr, 14)); }
		if (substr($exprStr, 0,13) eq "keccak_512_64") { return dyna_addtok("fkeccak_5126", substr($exprStr, 13)); }
		if (substr($exprStr, 0,10) eq "KECCAK_512")    { return dyna_addtok("fkeccak_512H", substr($exprStr, 10)); }
		if (substr($exprStr, 0,10) eq "keccak_512")    { return dyna_addtok("fkeccak_512h", substr($exprStr, 10)); }
	}  elsif ($stmp eq "MD2") {
		if (substr($exprStr, 0, 7) eq "md2_64c")   { return dyna_addtok("fmd2c", substr($exprStr, 7)); }
		if (substr($exprStr, 0, 6) eq "md2_64")    { return dyna_addtok("fmd26", substr($exprStr, 6)); }
		if (substr($exprStr, 0, 3) eq "md2")       { return dyna_addtok("fmd2h", substr($exprStr, 3)); }
		if (substr($exprStr, 0, 3) eq "MD2")       { return dyna_addtok("fmd2H", substr($exprStr, 3)); }
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
		print STDERR "The expression MUST start with a 'known' md5/md4/sha1 type function.\n";  die;
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
	$gen_needs = 0; $gen_needs2 = 0; $gen_needu = 0;

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
	#print "$gen_stype\n";

	# load salt #2
	$salt2len = $hash{"salt2len"};
	unless (defined($salt2len) && $salt2len =~ /^[+\-]?\d*.?\d+$/) { $salt2len = 6; }

	# load user name
	$dynamic_usernameType = $hash{"usrname"};
	if (!$dynamic_usernameType) { $dynamic_usernameType=0; } else {$gen_needu=1; }
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

	if ($gen_needu == 1) { dynamic_load_username(); $out_username=$gen_u;}
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

	# older (pre-unified hash output function) code was kept, just in case.
#	if ($gen_needu == 1) { print "$gen_u:\$dynamic_$gen_num\$$h"; }
#	else { print "u$u-dynamic_$gen_num:\$dynamic_$gen_num\$$h"; }
#	if ($gen_needs > 0) { print "\$$gen_soutput"; }
#	if ($gen_needs2 > 0) { if (!defined($gen_stype) || $gen_stype ne "toS2hex") {print "\$\$2$gen_s2";} }
#	print ":$u:0:$_[0]::\n";
#	return $h;  # might as well return the value.

	my $ret = "";
	if ($gen_needu == 1) { $ret .= "\$dynamic_$gen_num\$$h"; }
	else { $ret .= "\$dynamic_$gen_num\$$h"; }
	if ($gen_needs > 0) { $ret .= "\$$gen_soutput"; }
	if ($gen_needs2 > 0) { if (!defined($gen_stype) || $gen_stype ne "toS2hex") {$ret .= "\$\$2$gen_s2";} }
	return $ret;
}
sub dynamic_load_username {
	# load user name
	if (defined $arguser) {
		$gen_u = $arguser;
	} else {
		$gen_u = randusername(12);
	}
	if (defined($dynamic_usernameType)) {
		if ($dynamic_usernameType eq "lc") { $gen_u = lc $gen_u; }
		elsif ($dynamic_usernameType eq "uc") { $gen_u = uc $gen_u; }
		elsif ($dynamic_usernameType eq "uni") { $gen_u = encode("UTF-16LE",$gen_u); }
		elsif ($dynamic_usernameType eq "md5_hex_salt") { $argsalt = md5_hex($gen_u); }
	}
}
sub dynamic_load_salt {
	if (defined $argsalt) {
		if ($gen_stype eq "ashex") { $gen_s=md5_hex($argsalt); }
		else { $gen_s=$argsalt; }
		if (!defined $gen_s) {$gen_s = get_salt(4);}
		$gen_soutput = $gen_s;
		$saltlen = length($gen_s);
		if ($gen_stype eq "tohex") { $gen_s=md5_hex($gen_s); }
	} else {
		if ($gen_stype eq "ashex") { $gen_s=randstr(32, \@chrHexLo); }
		elsif ($gen_stype eq "asHEX") { $gen_s=uc randstr(32, \@chrHexLo); }
		elsif ($gen_stype eq "asHEX64") { $gen_s=uc randstr(64, \@chrHexLo); }
		else {
			my $slen = $saltlen;
			if ($slen < 0) {
				$slen = int(rand($slen*-1));
			}
			#print "$gen_stype\n";
			if ($gen_stype eq "onlyhex") {
				$gen_s=randstr($slen, \@chrHexLo);
			} else {
				$gen_s=randstr($slen);
			}
		}
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
sub dynamic_f54    { $h = pop @gen_Stack; $h = md5_hex($h)."00000000";	 $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f16    { $h = pop @gen_Stack; $h = sha1_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f46    { $h = pop @gen_Stack; $h = md4_base64($h);  $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f5c    { $h = pop @gen_Stack; $h = base64_wpa(md5($h));  $gen_Stack[@gen_Stack-1] .= $h; return $h; }
# we can use base64i to get cryptBS layout
sub dynamic_f1c    { $h = pop @gen_Stack; $h = base64_wpa(sha1($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f4c    { $h = pop @gen_Stack; $h = base64_wpa(md4($h));  $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f5r    { $h = pop @gen_Stack; $h = md5($h);  $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f1r    { $h = pop @gen_Stack; $h = sha1($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f4r    { $h = pop @gen_Stack; $h = md4($h);  $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f224h  { $h = pop @gen_Stack; $h = sha224_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f224H  { $h = pop @gen_Stack; $h = uc sha224_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f2246  { $h = pop @gen_Stack; $h = sha224_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f224c  { $h = pop @gen_Stack; $h = base64_wpa(sha224($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f224r  { $h = pop @gen_Stack; $h = sha224($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f256h  { $h = pop @gen_Stack; $h = sha256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f256H  { $h = pop @gen_Stack; $h = uc sha256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f2566  { $h = pop @gen_Stack; $h = sha256_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f256c  { $h = pop @gen_Stack; $h = base64_wpa(sha256($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f256r  { $h = pop @gen_Stack; $h = sha256($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f384h  { $h = pop @gen_Stack; $h = sha384_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f384H  { $h = pop @gen_Stack; $h = uc sha384_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f3846  { $h = pop @gen_Stack; $h = sha384_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f384c  { $h = pop @gen_Stack; $h = base64_wpa(sha384($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f384r  { $h = pop @gen_Stack; $h = sha384($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f512h  { $h = pop @gen_Stack; $h = sha512_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f512H  { $h = pop @gen_Stack; $h = uc sha512_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f5126  { $h = pop @gen_Stack; $h = sha512_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f512c  { $h = pop @gen_Stack; $h = base64_wpa(sha512($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_f512r  { $h = pop @gen_Stack; $h = sha512($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgosth { require Digest::GOST; import Digest::GOST qw(gost gost_hex gost_base64); $h = pop @gen_Stack; $h = gost_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgostH { require Digest::GOST; import Digest::GOST qw(gost gost_hex gost_base64); $h = pop @gen_Stack; $h = uc gost_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgost6 { require Digest::GOST; import Digest::GOST qw(gost gost_hex gost_base64); $h = pop @gen_Stack; $h = gost_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgostc { require Digest::GOST; import Digest::GOST qw(gost gost_hex gost_base64); $h = pop @gen_Stack; $h = base64_wpa(gost($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fgostr { require Digest::GOST; import Digest::GOST qw(gost gost_hex gost_base64); $h = pop @gen_Stack; $h = gost($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlph { $h = pop @gen_Stack; $h = whirlpool_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlpH { $h = pop @gen_Stack; $h = uc whirlpool_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlp6 { $h = pop @gen_Stack; $h = whirlpool_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlpc { $h = pop @gen_Stack; $h = base64_wpa(whirlpool($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fwrlpr { $h = pop @gen_Stack; $h = whirlpool($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_ftigh  { $h = pop @gen_Stack; $h = tiger_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_ftigH  { $h = pop @gen_Stack; $h = uc tiger_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_ftig6  { $h = pop @gen_Stack; $h = tiger_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_ftigc  { $h = pop @gen_Stack; $h = base64_wpa(tiger($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_ftigr  { $h = pop @gen_Stack; $h = tiger($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip128h  { $h = pop @gen_Stack; $h = ripemd128_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip128H  { $h = pop @gen_Stack; $h = uc ripemd128_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip1286  { $h = pop @gen_Stack; $h = ripemd128_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip128c  { $h = pop @gen_Stack; $h = base64_wpa(ripemd128($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip128r  { $h = pop @gen_Stack; $h = ripemd128($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip160h  { $h = pop @gen_Stack; $h = ripemd160_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip160H  { $h = pop @gen_Stack; $h = uc ripemd160_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip1606  { $h = pop @gen_Stack; $h = ripemd160_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip160c  { $h = pop @gen_Stack; $h = base64_wpa(ripemd160($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip160r  { $h = pop @gen_Stack; $h = ripemd160($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip256h  { $h = pop @gen_Stack; $h = ripemd256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip256H  { $h = pop @gen_Stack; $h = uc ripemd256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip2566  { $h = pop @gen_Stack; $h = ripemd256_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip256c  { $h = pop @gen_Stack; $h = base64_wpa(ripemd256($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip256r  { $h = pop @gen_Stack; $h = ripemd256($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip320h  { $h = pop @gen_Stack; $h = ripemd320_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip320H  { $h = pop @gen_Stack; $h = uc ripemd320_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip3206  { $h = pop @gen_Stack; $h = ripemd320_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip320c  { $h = pop @gen_Stack; $h = base64_wpa(ripemd320($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_frip320r  { $h = pop @gen_Stack; $h = ripemd320($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fhavh  { require Digest::Haval256; $h = pop @gen_Stack; $h = haval256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fhavH  { require Digest::Haval256; $h = pop @gen_Stack; $h = uc haval256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fhav6  { require Digest::Haval256; $h = pop @gen_Stack; $h = haval256_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fhavc  { require Digest::Haval256; $h = pop @gen_Stack; $h = base64_wpa(haval256($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fhavr  { require Digest::Haval256; $h = pop @gen_Stack; $h = haval256($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fpad16 { $h = pop @gen_Stack; $h = pad16($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fpad20 { $h = pop @gen_Stack; $h = pad20($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fpad100{ $h = pop @gen_Stack; $h = pad100($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fpadmd64 { $h = pop @gen_Stack; $h = pad_md64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_futf16  { $h = pop @gen_Stack; $h = encode("UTF-16LE",$h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_futf16be{ $h = pop @gen_Stack; $h = encode("UTF-16BE",$h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }

sub dynamic_fsha3_224h  { require Digest::SHA3; import Digest::SHA3 qw(sha3_224_hex);     $h = pop @gen_Stack; $h = sha3_224_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_224H  { require Digest::SHA3; import Digest::SHA3 qw(sha3_224_hex);     $h = pop @gen_Stack; $h = uc sha3_224_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_2246  { require Digest::SHA3; import Digest::SHA3 qw(sha3_224_base64);  $h = pop @gen_Stack; $h = sha3_224_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_224c  { require Digest::SHA3; import Digest::SHA3 qw(sha3_224);         $h = pop @gen_Stack; $h = base64_wpa(sha3_224($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_224r  { require Digest::SHA3; import Digest::SHA3 qw(sha3_224);         $h = pop @gen_Stack; $h = sha3_224($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_256h  { require Digest::SHA3; import Digest::SHA3 qw(sha3_256_hex);     $h = pop @gen_Stack; $h = sha3_256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_256H  { require Digest::SHA3; import Digest::SHA3 qw(sha3_256_hex);     $h = pop @gen_Stack; $h = uc sha3_256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_2566  { require Digest::SHA3; import Digest::SHA3 qw(sha3_256_base64);  $h = pop @gen_Stack; $h = sha3_256_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_256c  { require Digest::SHA3; import Digest::SHA3 qw(sha3_256);         $h = pop @gen_Stack; $h = base64_wpa(sha3_256($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_256r  { require Digest::SHA3; import Digest::SHA3 qw(sha3_256);         $h = pop @gen_Stack; $h = sha3_256($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_384h  { require Digest::SHA3; import Digest::SHA3 qw(sha3_384_hex);     $h = pop @gen_Stack; $h = sha3_384_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_384H  { require Digest::SHA3; import Digest::SHA3 qw(sha3_384_hex);     $h = pop @gen_Stack; $h = uc sha3_384_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_3846  { require Digest::SHA3; import Digest::SHA3 qw(sha3_384_base64);  $h = pop @gen_Stack; $h = sha3_384_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_384c  { require Digest::SHA3; import Digest::SHA3 qw(sha3_384);         $h = pop @gen_Stack; $h = base64_wpa(sha3_384($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_384r  { require Digest::SHA3; import Digest::SHA3 qw(sha3_384);         $h = pop @gen_Stack; $h = sha3_384($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_512h  { require Digest::SHA3; import Digest::SHA3 qw(sha3_512_hex);     $h = pop @gen_Stack; $h = sha3_512_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_512H  { require Digest::SHA3; import Digest::SHA3 qw(sha3_512_hex);     $h = pop @gen_Stack; $h = uc sha3_512_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_5126  { require Digest::SHA3; import Digest::SHA3 qw(sha3_512_base64);  $h = pop @gen_Stack; $h = sha3_512_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_512c  { require Digest::SHA3; import Digest::SHA3 qw(sha3_512);         $h = pop @gen_Stack; $h = base64_wpa(sha3_512($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fsha3_512r  { require Digest::SHA3; import Digest::SHA3 qw(sha3_512);         $h = pop @gen_Stack; $h = sha3_512($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fkeccak_256h  { require Digest::Keccak; import Digest::Keccak qw(keccak_256_hex);     $h = pop @gen_Stack; $h = keccak_256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fkeccak_256H  { require Digest::Keccak; import Digest::Keccak qw(keccak_256_hex);     $h = pop @gen_Stack; $h = uc keccak_256_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fkeccak_2566  { require Digest::Keccak; import Digest::Keccak qw(keccak_256_base64);  $h = pop @gen_Stack; $h = keccak_256_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fkeccak_256c  { require Digest::Keccak; import Digest::Keccak qw(keccak_256);         $h = pop @gen_Stack; $h = base64_wpa(keccak_256($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fkeccak_256r  { require Digest::Keccak; import Digest::Keccak qw(keccak_256);         $h = pop @gen_Stack; $h = keccak_256($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fkeccak_512h  { require Digest::Keccak; import Digest::Keccak qw(keccak_512_hex);     $h = pop @gen_Stack; $h = keccak_512_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fkeccak_512H  { require Digest::Keccak; import Digest::Keccak qw(keccak_512_hex);     $h = pop @gen_Stack; $h = uc keccak_512_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fkeccak_5126  { require Digest::Keccak; import Digest::Keccak qw(keccak_512_base64);  $h = pop @gen_Stack; $h = keccak_512_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fkeccak_512c  { require Digest::Keccak; import Digest::Keccak qw(keccak_512);         $h = pop @gen_Stack; $h = base64_wpa(keccak_512($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fkeccak_512r  { require Digest::Keccak; import Digest::Keccak qw(keccak_512);         $h = pop @gen_Stack; $h = keccak_512($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fmd2h  { require Digest::MD2; import Digest::MD2 qw(md2_hex);     $h = pop @gen_Stack; $h = md2_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fmd2H  { require Digest::MD2; import Digest::MD2 qw(md2_hex);     $h = pop @gen_Stack; $h = uc md2_hex($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fmd26  { require Digest::MD2; import Digest::MD2 qw(md2_base64);  $h = pop @gen_Stack; $h = md2_base64($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fmd2c  { require Digest::MD2; import Digest::MD2 qw(md2);         $h = pop @gen_Stack; $h = base64_wpa(md2($h)); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
sub dynamic_fmd2r  { require Digest::MD2; import Digest::MD2 qw(md2);         $h = pop @gen_Stack; $h = md2($h); $gen_Stack[@gen_Stack-1] .= $h; return $h; }
