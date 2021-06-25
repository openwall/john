#!/usr/bin/env python

# pwsafe2john processes input Password Safe files into a format suitable
# for use with JtR.
#
# This software is Copyright (c) 2012, Dhiru Kholia <dhiru at openwall.com>,
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Ported to Python 3 by Jannik Vieten <me at exploide.net>
#
# Password Safe file format is documented at
# https://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt
#
# Output Format: filename:$pwsafe$*version*salt*iterations*hash

magic = b"PWS3"

import sys
import struct
from binascii import hexlify
import os


def process_file(filename):

    f = open(filename, "rb")

    data = f.read(4)
    if data != magic:
        sys.stderr.write("%s : PWS3 magic string missing, is this a Password Safe file?\n" % filename)
        return

    buf = f.read(32)
    if len(buf) != 32:
        sys.std.write("Error: salt read failed.\n")
        return

    iterations = struct.unpack("<I", f.read(4))[0]

    sys.stdout.write("%s:$pwsafe$*3*" %
                     os.path.basename(filename).rstrip(".psafe3"))
    sys.stdout.write(hexlify(buf).decode('ascii'))
    sys.stdout.write("*%s*" % iterations)
    hsh = f.read(32)
    if len(hsh) != 32:
        sys.stderr.write("Error: hash read failed.\n")
        return
    sys.stdout.write(hexlify(hsh).decode('ascii'))
    sys.stdout.write("\n")

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: %s [.psafe3 files]\n" % sys.argv[0])
        sys.exit(1)

    for f in sys.argv[1:]:
        process_file(f)
