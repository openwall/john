#!/usr/bin/env python

# This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>
# and it is hereby released to the general public under the Apache License
# Version 2.0.
#
# Written in July of 2017 based on from "Jackcess Encrypt" and Jackcess
# projects.
#
# All credit goes to Vladimir Berezniker for documenting the MS Money encryption
# scheme.

import os
import sys
from binascii import hexlify, unhexlify

PY3 = sys.version_info[0] == 3

# MSISAMCryptCodecHandler.java
SALT_OFFSET = 0x72
CRYPT_CHECK_START = 0x2e9
ENCRYPTION_FLAGS_OFFSET = 0x298
# SALT_LENGTH = 0x4
USE_SHA1 = 0x20
# Modern encryption using hashing
NEW_ENCRYPTION = 0x6
TRAILING_PWD_LEN = 20

# from Jackcess sources
HEADER_MASK = "b56f03626108c255eba96772433f009c7a9f90ff809a31c579baed30bcdfcc9d63d9e4c37b42fb8abc4e86fbec375d449cfac65e28e613b68a6054947b36f572dfb177f41343cfafb1333461795b92b57c2a05f17c99011b98fd124f4a946c3e60265f95f8d089248567c61f2744d2eecf65edff07c746a178160cede92d62d4"
OFFSET_MASKED_HEADER = 24


def applyHeaderMask(buf):
    headerMask = bytearray(unhexlify(HEADER_MASK))

    for idx in range(0, len(headerMask)):
        pos = idx + OFFSET_MASKED_HEADER
        buf[pos] = buf[pos] ^ headerMask[idx]

    return buf


def process_file(filename):
    bname = os.path.basename(filename)
    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    data = f.read(4096)
    buf = applyHeaderMask(bytearray(data))
    encrypted = buf[ENCRYPTION_FLAGS_OFFSET] & NEW_ENCRYPTION
    if not encrypted:
        return

    salt = hexlify(buf[SALT_OFFSET:SALT_OFFSET+8])
    if PY3:
        salt = salt.decode("ascii")

    cryptCheckOffset = buf[SALT_OFFSET]
    start = CRYPT_CHECK_START + cryptCheckOffset
    encrypted4BytesCheck = buf[start:start+4]
    encrypted4BytesCheck = hexlify(encrypted4BytesCheck)
    if PY3:
        encrypted4BytesCheck = encrypted4BytesCheck.decode("ascii")
    typ = buf[ENCRYPTION_FLAGS_OFFSET] & USE_SHA1
    if typ != 0:
        typ = 1

    if typ == 0:
        sys.stdout.write("%s: md5 crypto / old money file format found!\n" % (bname))

    sys.stdout.write("%s:$money$%s*%s*%s\n" % (bname, typ, salt, encrypted4BytesCheck))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [MS Money 2002-2007 / Money Plus file(s)]\n" % sys.argv[0])

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
