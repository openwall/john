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
        if not line.startswith("|1|"):  # is this always the case?
            continue

        fields = line.strip().split("= ")
        h = fields[0] + "="
        hash_start = h.rfind("|") + 1

        sys.stdout.write("%s:$known_hosts$%s\n" % (h[hash_start:], h))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: known_hosts2john [known_hosts files]\n")
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
