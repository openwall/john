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
# Password Safe file format is documented at,
#
# + http://keybox.rubyforge.org/password-safe-db-format.html
#
# + https://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt
#
# Output Format: filename:$passwordsaf$*version*salt*iterations*hash */

magic = "PWS3"

import sys
import struct
from binascii import hexlify
import os


def process_file(filename):

    f = open(filename, "rb")

    data = f.read(4)
    if data != magic:
        sys.stderr.write("%s : PWS3 magic string missing, is this a Password Safe file?\n", filename)
        return

    buf = f.read(32)
    if len(buf) != 32:
        sys.std.write("Error: salt read failed.\n")
        return

    iterations = struct.unpack(">I", f.read(4))[0]

    sys.stdout.write("%s:$pwsafe$*3*" %
                     os.path.basename(filename).rstrip(".psafe3"))
    sys.stdout.write(hexlify(buf))
    sys.stdout.write("*%s*" % iterations)
    hsh = f.read(32)
    if len(hsh) != 32:
        sys.stderr.write("Error: hash read failed.\n")
        return
    sys.stdout.write(hexlify(hsh))
    sys.stdout.write("\n")

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: pwsafe2john [.psafe3 files]\n")
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
