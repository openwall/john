#!/usr/bin/env perl

# aixpasswd2john.pl
#
# This script parses AIX password data and transforms it into a format
# suitable for use with the John the Ripper password cracking tool.
# It expects input in the form of AIX /etc/security/passwd file data.
#
# The script reads input either from a file passed as a command-line
# argument or from stdin if no file is provided.
# Each line of the input is expected to follow one of these formats:
# 
#   username:
#   password = password_hash
#
# The script produces output in the format:
#   username:password_hash
# If a user does not have a password or the password is "*", the output will be:
#   username:NoPassword
#
# It's important to note that password hashes are sensitive data. Ensure this 
# script is run in a secure environment and that the output is stored securely.
#
# Usage:
#   aixpasswd2john.pl <inputfile>
# If no input files are given, it will read from stdin.
#
# Example:
#   cat /etc/security/passwd | aixpasswd2john.pl
#
# This will output the usernames and password hashes in a format suitable for 
# John the Ripper, one per line.

use strict;
use warnings;
use feature 'say';
use English '-no_match_vars';

my ($current_user, $current_password);

while (<>) {
	chomp;
	if (/^\s*([^:]+):\s*$/) {
		output_user($current_user, $current_password) if defined $current_user;
		($current_user, $current_password) = ($1, undef);
	} elsif (/^\s*password\s+=\s*(\S+)\s*$/) {
		$current_password = $1;
	}
}

output_user($current_user, $current_password) if defined $current_user;

sub output_user {
	my ($user, $password) = @_;
	$password = 'NoPassword' if !defined $password || $password eq '*';
	say "$user:$password";
}
