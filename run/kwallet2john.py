#!/usr/bin/env python

# This software is Copyright (c) 2014, Sanju Kholia <sanju.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted.

import sys
import os
import struct
from binascii import hexlify

KWMAGIC = "KWALLET\n\r\0\r\n"
KWMAGIC_LEN = 12
KWALLET_VERSION_MAJOR = 0
KWALLET_VERSION_MINOR = 0
KWALLET_CIPHER_BLOWFISH_CBC = 0
KWALLET_CIPHER_3DES_CBC = 1
KWALLET_HASH_SHA1 = 0
KWALLET_HASH_MD5 = 1
N = 128


def process_file(filename):
    offset = 0

    try:
        fd = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    # TOCTOU but who cares, right? ;)
    size = os.stat(filename).st_size
    buf = fd.read(KWMAGIC_LEN)

    if buf != KWMAGIC:
        sys.stderr.write("%s : Not a KDE KWallet file!\n" % filename)
        return
    offset += KWMAGIC_LEN
    buf = bytearray(fd.read(4))
    offset += 4

    # First byte is major version, second byte is minor version
    if buf[0] != KWALLET_VERSION_MAJOR:
        sys.stderr.write("%s : Unknown version!\n" % filename)
        return
    if buf[1] != KWALLET_VERSION_MINOR:
        sys.stderr.write("%s : Unknown version!\n" % filename)
        return
    if buf[2] != KWALLET_CIPHER_BLOWFISH_CBC:
        sys.stderr.write("%s : Unsupported cipher\n" % filename)
        return
    if buf[3] != KWALLET_HASH_SHA1:
        sys.stderr.write("%s : Unsupported hash\n" % filename)
        return

    # Read in the hashes
    buf = fd.read(4)
    n = struct.unpack("> I", buf)[0]
    if n > 0xffff:
        sys.stderr.write("%s : sanity check failed!\n" % filename)
        sys.exit(6)
    offset += 4
    for i in range(0, n):
        buf = fd.read(16)
        offset += 16
        buf = fd.read(4)  # read 4 bytes more
        fsz = struct.unpack("> I", buf)[0]
        offset += 4
        for j in range(0, fsz):
            fd.read(16)
            offset += 16

    # Read in the rest of the file
    encrypted_size = size - offset
    encrypted = fd.read(encrypted_size)
    encrypted_size = len(encrypted)

    if encrypted_size % 8 != 0:
        sys.stderr.write("%s : invalid file structure!\n", filename)
        sys.exit(7)

    sys.stdout.write("%s:$kwallet$%ld$%s" % (os.path.basename(filename), encrypted_size, hexlify(encrypted)))

    sys.stdout.write(":::::%s\n" % filename)

    fd.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <.kwl file(s)>\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
