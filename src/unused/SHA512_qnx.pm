package SHA512_qnx;

# this code was taken and stripped down from Digest::SHA::PurePerl
# in this code, ONLY SHA512_qnx() is defined. That function is the
# 'same' as Digest::SHA::PurePerl::SHA512() except the code here
# has the same 'bug' as we have found in QNX's passwd SHA512 function.

use strict;
use warnings;
use vars qw($VERSION @ISA @EXPORT @EXPORT_OK);
use integer;
use Carp qw(croak);

$VERSION = '5.95';

require Exporter;
@ISA = qw(Exporter);
@EXPORT_OK = ();

my $MAX32 = 0xffffffff;

no warnings qw(portable);

my @K512 = (
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817);

my @H0512 = (
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179);

use warnings;

sub _c_SL64    { my($x, $n) = @_; "($x << $n)" }
sub _c_SR64    { my($x, $n) = @_; my $mask = (1 << (64 - $n)) - 1; "(($x >> $n) & $mask)"; }
sub _c_ROTRQ   { my($x, $n) = @_; "(" . _c_SR64($x, $n) . "|" . _c_SL64($x, 64 - $n) . ")"; }
sub _c_SIGMAQ0 { my($x) = @_;     "(" . _c_ROTRQ($x,28) . "^" . _c_ROTRQ($x, 34) . "^" . _c_ROTRQ($x, 39) . ")"; }
sub _c_SIGMAQ1 { my($x) = @_;     "(" . _c_ROTRQ($x,14) . "^" . _c_ROTRQ($x, 18) . "^" . _c_ROTRQ($x, 41) . ")"; }
sub _c_sigmaQ0 { my($x) = @_;     "(" . _c_ROTRQ($x, 1) . "^" . _c_ROTRQ($x, 8)  . "^" . _c_SR64($x, 7) . ")";   }
sub _c_sigmaQ1 { my($x) = @_;     "(" . _c_ROTRQ($x,19) . "^" . _c_ROTRQ($x, 61) . "^" . _c_SR64($x, 6) . ")";   }

my $sha512_code = q/
sub _sha512 {
	my($self, $block) = @_;
	my(@N, @W, $a, $b, $c, $d, $e, $f, $g, $h, $T1, $T2);

	@N = unpack("N32", $block);
	($a, $b, $c, $d, $e, $f, $g, $h) = @{$self->{H}};
	for ( 0 .. 15) { $W[$_] = (($N[2*$_] << 16) << 16) | $N[2*$_+1] }
	for (16 .. 79) { $W[$_] = / .
		_c_sigmaQ1(q/$W[$_- 2]/) . q/ + $W[$_- 7] + / .
		_c_sigmaQ0(q/$W[$_-15]/) . q/ + $W[$_-16] }
	for ( 0 .. 79) {
		$T1 = $h + / . _c_SIGMAQ1(q/$e/) .
			q/ + (($g) ^ (($e) & (($f) ^ ($g)))) +
				$K512[$_] + $W[$_];
		$T2 = / . _c_SIGMAQ0(q/$a/) .
			q/ + ((($a) & ($b)) | (($c) & (($a) | ($b))));
		$h = $g; $g = $f; $f = $e; $e = $d + $T1;
		$d = $c; $c = $b; $b = $a; $a = $T1 + $T2;
	}
	$self->{H}->[0] += $a; $self->{H}->[1] += $b; $self->{H}->[2] += $c; $self->{H}->[3] += $d;
	$self->{H}->[4] += $e; $self->{H}->[5] += $f; $self->{H}->[6] += $g; $self->{H}->[7] += $h;
}
/;

eval($sha512_code);
my $sha512 = \&_sha512;

sub _SETBIT {
	my($self, $pos) = @_;
	my @c = unpack("C*", $self->{block});
	$c[$pos >> 3] = 0x00 unless defined $c[$pos >> 3];
	$c[$pos >> 3] |= (0x01 << (7 - $pos % 8));
	$self->{block} = pack("C*", @c);
}

sub _CLRBIT {
	my($self, $pos) = @_;
	my @c = unpack("C*", $self->{block});
	$c[$pos >> 3] = 0x00 unless defined $c[$pos >> 3];
	$c[$pos >> 3] &= ~(0x01 << (7 - $pos % 8));
	$self->{block} = pack("C*", @c);
}

sub _BYTECNT {
	my($bitcnt) = @_;
	$bitcnt > 0 ? 1 + (($bitcnt - 1) >> 3) : 0;
}

sub _digcpy {
	my($self) = @_;
	my @dig;
	for (@{$self->{H}}) {
		push(@dig, (($_>>16)>>16) & $MAX32) if $self->{alg} >= 384;
		push(@dig, $_ & $MAX32);
	}
	$self->{digest} = pack("N" . ($self->{digestlen}>>2), @dig);
}

sub _sharewind {
	my($self) = @_;
	my $alg = $self->{alg};
	$self->{block} = "";
	$self->{blockcnt} = 0;
	$self->{blocksize} = 1024;
	for (qw(lenll lenlh lenhl lenhh)) { $self->{$_} = 0 }
	$self->{digestlen} = 64;
	$self->{sha} = \&_sha512;
	$self->{H} = [@H0512];
	push(@{$self->{H}}, 0) while scalar(@{$self->{H}}) < 8;
	$self;
}

sub _shaopen {
	my($alg) = @_;
	my($self);
	$self->{alg} = $alg;
	_sharewind($self);
}

sub _shadirect {
	my($bitstr, $bitcnt, $self) = @_;
	my $savecnt = $bitcnt;
	my $offset = 0;
	my $blockbytes = $self->{blocksize} >> 3;
	while ($bitcnt >= $self->{blocksize}) {
		&{$self->{sha}}($self, substr($bitstr, $offset, $blockbytes));
		$self->{priorblock} = substr($bitstr, $offset, $blockbytes);
		$offset += $blockbytes;
		$bitcnt -= $self->{blocksize};
	}
	if ($bitcnt > 0) {
		$self->{block} = substr($bitstr, $offset, _BYTECNT($bitcnt));
		$self->{blockcnt} = $bitcnt;
	}
	$savecnt;
}
sub _shawrite {
	my($bitstr, $bitcnt, $self) = @_;
	return(0) unless $bitcnt > 0;
	no integer;
	my $TWO32 = 4294967296;
	if (($self->{lenll} += $bitcnt) >= $TWO32) {
		$self->{lenll} -= $TWO32;
		if (++$self->{lenlh} >= $TWO32) {
			$self->{lenlh} -= $TWO32;
			if (++$self->{lenhl} >= $TWO32) {
				$self->{lenhl} -= $TWO32;
				if (++$self->{lenhh} >= $TWO32) {
					$self->{lenhh} -= $TWO32;
				}
			}
		}
	}
	use integer;
	my $blockcnt = $self->{blockcnt};
	return _shadirect($bitstr, $bitcnt, $self);
}

sub _shaWrite {
	my($bytestr_r, $bytecnt, $self) = @_;
	my $MWS = 33554432;
	return(0) unless $bytecnt > 0;
	croak 'Wide character in subroutine entry' unless utf8::downgrade($$bytestr_r, 1);
	return(_shawrite($$bytestr_r, $bytecnt<<3, $self)) if $bytecnt <= $MWS;
	my $offset = 0;
	while ($bytecnt > $MWS) {
		_shawrite(substr($$bytestr_r, $offset, $MWS), $MWS<<3, $self);
		$offset  += $MWS;
		$bytecnt -= $MWS;
	}
	_shawrite(substr($$bytestr_r, $offset, $bytecnt), $bytecnt<<3, $self);
}

sub _shafinish {
	my($self) = @_;
	my $LENPOS = $self->{alg} <= 256 ? 448 : 896;
	_SETBIT($self, $self->{blockcnt}++);
	while ($self->{blockcnt} > $LENPOS) {
		if ($self->{blockcnt} < $self->{blocksize}) {
			_CLRBIT($self, $self->{blockcnt}++);
		}
		else {
			&{$self->{sha}}($self, $self->{block});
			$self->{priorblock} = $self->{block};
			$self->{block} = "";
			$self->{blockcnt} = 0;
		}
	}
	while ($self->{blockcnt} < $LENPOS) {
		_CLRBIT($self, $self->{blockcnt}++);
	}
	if ($self->{blocksize} > 512) {
		$self->{block} .= pack("N", $self->{lenhh} & $MAX32);
		$self->{block} .= pack("N", $self->{lenhl} & $MAX32);
	}
	$self->{block} .= pack("N", $self->{lenlh} & $MAX32);
	$self->{block} .= pack("N", $self->{lenll} & $MAX32);
	# here is the 'magic' code from the BROKEN QNX implementation
	# NOTE, only sha512 should be used from this module. the other
	# magic is every time we 'reset' $self->{block} we first copy
	# that over to $self->{priorblock} so that we have those 4 bytes
	# which do not properly get cleaned out.
	my $len = $self->{lenll}/8;
	if ($len >= 116) { # NOTE, only work up to 4gbit string (good enough for JtR)
		substr($self->{block}, 116, 4) = substr($self->{priorblock}, 116, 4);
	}
	&{$self->{sha}}($self, $self->{block});
}

sub _shadigest { my($self) = @_; _digcpy($self); $self->{digest} }

sub sha512 {
	my $state = _shaopen(512) or return;
	for (@_) { _shaWrite(\$_, length($_), $state) }
	_shafinish($state);
	_shadigest($state);
}
push(@EXPORT_OK, 'sha512');

1;
