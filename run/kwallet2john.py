#!/usr/bin/env python

# This software is Copyright (c) 2014, Sanju Kholia <sanju.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# "kde-runtime/kwalletd/backend/kwalletbackend.cc" file is authoritative.
#
# Use gdb -p `pidof kwalletd5` and "break gcry_kdf_derive" to debug this code.

import sys
import os
import struct
from binascii import hexlify

KWMAGIC = "KWALLET\n\r\0\r\n"
KWMAGIC_LEN = 12
KWALLET_VERSION_MAJOR = 0
KWALLET_VERSION_MINOR = 0
KWALLET_CIPHER_BLOWFISH_ECB = 0  # this was the old KWALLET_CIPHER_BLOWFISH_CBC
KWALLET_CIPHER_3DES_CBC = 1
KWALLET_CIPHER_GPG = 2
KWALLET_CIPHER_BLOWFISH_CBC = 3
KWALLET_HASH_SHA1 = 0
KWALLET_HASH_MD5 = 1  # unsupported (even upstream)
KWALLET_HASH_PBKDF2_SHA512 = 2  # used when using kwallet with pam or since 4.13 version
N = 128

PBKDF2_SHA512_KEYSIZE = 56
PBKDF2_SHA512_SALTSIZE = 56
PBKDF2_SHA512_ITERATIONS = 50000


def process_file(filename):
    offset = 0
    new_version = False  # PBKDF2-HMAC-SHA512 if True
    kwallet_minor_version = -1

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
        sys.stderr.write("%s : Unknown major version!\n" % filename)
        return
    # 0 has been the MINOR version until 4.13, from that point we use it to
    # upgrade the hash
    #
    # See runtime/kwalletd/backend/backendpersisthandler.cpp for details
    if buf[1] != 0:  # Old KWALLET_VERSION_MINOR
        if buf[1] != 1:  # New KWALLET_VERSION_MINOR
            sys.stderr.write("%s : Unknown minor version!\n" % filename)
            return
        new_version = True
        kwallet_minor_version = buf[1]
    if buf[2] != KWALLET_CIPHER_BLOWFISH_ECB and buf[2] != KWALLET_CIPHER_BLOWFISH_CBC:
        sys.stderr.write("%s : Unsupported cipher <%d>\n" % (filename, buf[2]))
        return
    if buf[3] != KWALLET_HASH_SHA1 and buf[3] != KWALLET_HASH_PBKDF2_SHA512:
        sys.stderr.write("%s : Unsupported hash <%d>\n" % (filename, buf[3]))
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

    if new_version:
        # read salt
        salt_filename = os.path.splitext(filename)[0] + ".salt"
        try:
            salt = open(salt_filename).read()
        except:
            sys.stderr.write("%s : unable to read salt from %s\n" % (filename, salt_filename))
            sys.exit(8)
        salt_len = len(salt)
        iterations = PBKDF2_SHA512_ITERATIONS  # is this fixed?
        sys.stdout.write("%s:$kwallet$%ld$%s$%d$%d$%s$%s" %
                         (os.path.basename(filename), encrypted_size,
                          hexlify(encrypted), kwallet_minor_version, salt_len,
                          salt.encode("hex"), iterations))
        sys.stdout.write(":::::%s\n" % filename)
    else:
        sys.stdout.write("%s:$kwallet$%ld$%s" % (os.path.basename(filename), encrypted_size, hexlify(encrypted)))
        sys.stdout.write(":::::%s\n" % filename)

    fd.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <.kwl file(s)>\n" % sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
