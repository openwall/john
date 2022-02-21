#!/usr/bin/env python

# This software is Copyright (c) 2018, Dhiru Kholia <kholia at kth.se> and it
# is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Tested with andOTP 0.6.0-beta1 running on Android 6.0.


import os
import sys
from binascii import hexlify

PY3 = sys.version_info[0] == 3

if not PY3:
    reload(sys)
    sys.setdefaultencoding('utf8')


def process_file(filename):
    """
    Parser for andOTP backup files
    """
    data = open(filename, "rb").read()

    # weak sanity check
    if len(data) < 12 + 2 + 16:  # IV + minimum-data-size + TAG
        return

    iv = data[0:12]
    tag = data[-16:]
    ciphertext = data[12:-16]

    iv = hexlify(iv)
    tag = hexlify(tag)
    ciphertext = hexlify(ciphertext)
    version = 0

    if PY3:
        iv = iv.decode("ascii")
        tag = tag.decode("ascii")
        ciphertext = ciphertext.decode("ascii")
    sys.stdout.write("%s:$andotp$%s*%s*%s*%s\n" %
                     (os.path.basename(filename), version, iv, ciphertext, tag))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [andOTP backup .json.aes file(s)]\n" % sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
