#!/usr/bin/env python

"""enpass2john.py extracts hashes from Enpass Password Manager databases"""

# This software is Copyright (c) 2017, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import os
import sys
import binascii


def process_file(filename):
    try:
        f = open(filename, "rb")
    except (IOError):
        e = sys.exc_info()[1]
        sys.stderr.write("%s : %s\n" % (filename, str(e)))
        return 2

    data = f.read(1024)
    version = 0
    iterations = 24000

    sys.stderr.write("Warning: Assuming older (Enpass 5.x) version of database\n");
    sys.stdout.write("%s:$enpass$%s$%s$%s\n" % (os.path.basename(filename),
        version, iterations, binascii.hexlify(data).decode("ascii")))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <Enpass .walletx files>\n" % sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
