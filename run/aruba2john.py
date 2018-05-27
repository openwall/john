#!/usr/bin/env python

# This software is Copyright (c) 2017, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

"""
ArubaOS password hashing algorithm details were found by Sven Blumenstein.

http://seclists.org/fulldisclosure/2016/May/19
"""

import sys


def process_file(filename):
    with open(filename, "r") as f:
        for line in f.readlines():
            username = None
            data = line.rstrip().split(":")
            if len(data) > 1:  # are usernames present?
                username = data[0]
                rest = data[1]
            else:
                rest = data[0]

            if len(rest) != 50:
                sys.stderr.write("Skipping hash of unsupported length -> %s\n" % rest)
                continue

            # first 5 bytes are the salt
            salt = rest[0:10]
            h = rest[10:]
            output = "$dynamic_25$%s$HEX$%s" % (h, salt)

            if username:
                sys.stdout.write("%s:%s\n" % (username, output))
            else:
                sys.stdout.write("%s\n" % output)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <ArubaOS hashes file>\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
