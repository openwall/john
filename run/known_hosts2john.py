#!/usr/bin/env python

# known_hosts2john processes input "known_hosts" files into a format suitable
# for use with JtR.
#
# This software is Copyright (c) 2014, Dhiru Kholia <dhiru [at] openwall.com>
#
# This code may be freely used and modified for any purpose.

import sys


def process_file(filename):

    for line in open(filename, "rb"):

        fields = line.strip().split(" ")

        if not line.startswith("|1|"):  # is this always the case?
            sys.stderr.write("%s\n" % fields[0]) # Assume non-hashed entries; print as seed
            continue

        sys.stdout.write("$known_hosts$%s\n" % fields[0])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: known_hosts2john [known_hosts files]\n")
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
