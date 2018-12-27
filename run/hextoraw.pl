#!/usr/bin/env perl
#
# used this to help load specific salt values in pbkdf2-hmac-sha512 format, within pass_gen.pl. Used like this:
# ./pass_gen.pl pbkdf2_hmac_sha512 -loops=23923 -salt=`./hextoraw c3fa2e153466f7619286024fe7d812d0a8ae836295f84b9133ccc65456519fc3`
# that command line would generate same salt and loop count as first $ml$ hash in the self tests of that format.

use warnings;

print pack("H*", $ARGV[0])."\n";
