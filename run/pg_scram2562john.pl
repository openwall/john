#!/usr/bin/env perl
#
# pg_scram2562john.pl - prepare PostgreSQL SCRAM-SHA-256 hashes for John the Ripper
#
# Written by Pranjal Prasad <prasadpranjal213@gmail.com> on 26 April 2025
#
# This software is in the public domain - it is uncopyrighted
#
# Converts PostgreSQL SCRAM-SHA-256 password hashes into a format suitable for John the Ripper.
#
# Usage:
#   ./pg_scram2562john.pl [inputfile(s)]
#
# Each line containing a SCRAM-SHA-256 verifier will be converted for cracking.
# This script handles lines in the format:
#   SCRAM-SHA-256$<iterations>:<salt>$<storedKey>:<serverKey>

use strict;
use warnings;

# Display the usage message
sub usage {
    print "Usage: $0 [inputfile(s)]\n";
    print "Each line containing a SCRAM-SHA-256 verifier will be converted for cracking.\n";
    print "Expected format: SCRAM-SHA-256$<iterations>:<salt>$<storedKey>:<serverKey>\n";
    exit 1;
}

# If no arguments are provided, show usage
usage() if (@ARGV == 0);

# Process each line from the input files or stdin
while (my $line = <>) {
    chomp $line;

    # Skip empty lines
    next if ($line =~ /^\s*$/);

    # Expect format: SCRAM-SHA-256$<iterations>:<salt>$<storedKey>:<serverKey>
    unless ($line =~ /^SCRAM-SHA-256\$(\d+):([^$]+)\$([^:]+):(.+)$/) {
        warn "Skipping invalid line: $line\n";
        next;
    }

    my ($iter, $salt, $stored_key, $server_key) = ($1, $2, $3, $4);

    # Produce John the Ripper compatible format
    # For example: $scram256$4096$<salt>$<stored_key>$<server_key>
    my $output = "\$scram256\$${iter}\$${salt}\$${stored_key}\$${server_key}";

    print "$output\n";
}
