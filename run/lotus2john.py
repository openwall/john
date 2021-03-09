#!/usr/bin/python3
# -*- coding: utf-8 -*-

# This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com>, and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Based on "LotusIdHashExtractor" program written by Sébastien Kaczmarek.
#
# See http://blog.quarkslab.com/have-you-ever-played-with-domino.html for more
# details.

import sys
import os
import struct
from binascii import hexlify


def process_file(filename):
    dataSize = os.path.getsize(filename)
    if dataSize < 0xD8:
        assert 0

    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    # seek to offset 0xD6
    f.seek(0xD6, 0)

    # read the size of user id ciphered blob */
    wUserBlobSize = struct.unpack("< H", f.read(2))[0]

    # Blob size is variable but there are some limits
    if wUserBlobSize < 0x10 or wUserBlobSize > 0x64:
        assert 0

    if wUserBlobSize + 0xD8 > dataSize:
        assert 0

    # read blob of size wUserBlobSize
    sys.stdout.write("%s:%s\n" % (os.path.basename(filename),
        hexlify(f.read(wUserBlobSize)).decode("ascii").upper()))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [Lotus Notes ID file(s)]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
