#!/usr/bin/perl -w
use strict;
my $VERSION = "1.00";
####################################################################
# This script will modifies .S file built with icc-32 bit, so that
# it can be compiled properly with cygwin. We have to comment out
# several lines, and we also have to add a block of #defines, for
# the modification of the 'NEEDSUNDERSCORE' building.
####################################################################

unless ( -e "sse-intrinsics-win32.S" ) {

	open INPUT,  "<", "sse-intrinsics-32.S"    or die $!;
    open OUTPUT, ">", "sse-intrinsics-win32.S" or die $!;
	my $line = <INPUT>;
	print OUTPUT $line;
	print OUTPUT "\n#ifdef UNDERSCORES\n";
	print OUTPUT "#define memcpy	    _memcpy\n";
	print OUTPUT "#define memset	    _memset\n";
	print OUTPUT "#define strlen	    _strlen\n";
	print OUTPUT "#define MD5_Init    _MD5_Init\n";
	print OUTPUT "#define MD5_Update  _MD5_Update\n";
	print OUTPUT "#define MD5_Final   _MD5_Final\n";
	print OUTPUT "#define SSEmd5body   _SSEmd5body\n";
	print OUTPUT "#define SSESHA1body  _SSESHA1body\n";
	print OUTPUT "#define SSEmd4body   _SSEmd4body\n";
	print OUTPUT "#define md5cryptsse  _md5cryptsse\n";
	print OUTPUT "#endif\n\n";
	while (<INPUT>) {
		next if (/^\t\.type\t/);
		next if (/^\t\.size\t/);
		next if (/^\t\.section \.rodata\./);
		next if (/^\t\.section \.note\./);
		print OUTPUT;
	}
	close INPUT;
	close OUTPUT;
}
