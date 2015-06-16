#!/usr/bin/perl -w
#/
#  This software is Copyright (c) 2013 Konrads Smelkovs <konrads.smelkovs@kpmg.co.uk>,
#  and it is hereby released to the general public under the following terms:
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted.
#
# This script converts AIX /etc/security/passw
# cat /etc/security/passwd
# root:
#         password = mrXXXXXXXXXX
#         lastupdate = 1343960660
#         flags =
#
# admin:
#         password = oiXXXXXXXXXX
#         lastupdate = 1339748349
#         flags =
# ...
# Usage: aixpasswd2john.pl <inputfile>
# If no input files are given, aixpasswd2john.pl will read from stdin

$currentuser="";
while(<>){
	chomp;
	if (m!^(\w+):$!){
		$currentuser=$1;
		next;
	}
	if (m!^\s*password\s+=\s+(\S+)$! and $1 ne "*"){
		print "$currentuser:$1\n";
		$currentuser="";
		next
	}
}
