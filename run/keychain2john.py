#!/usr/bin/python3

# keychain2john processes input Mac OS X keychain files into a format suitable
# for use with JtR.
#
# This software is Copyright (c) 2014, Dhiru Kholia <dhiru [at] openwall.com>
# and (c) 2004 Matt Johnston <matt @ ucc asn au>,
#
# This code may be freely used and modified for any purpose.
#
# How it works:
#
# The parts of the keychain we're interested in are "blobs" (see ssblob.h in
# Apple's code). There are two types - DbBlobs and KeyBlobs.
#
# Each blob starts with the magic hex string FA DE 07 11 - so we search for
# that. There's only one DbBlob (at the end of the file), and that contains the
# file encryption key (amongst other things), encrypted with the master key.
# The master key is derived purely from the user's password, and a salt, also
# found in the DbBlob. PKCS #5 2 pbkdf2 is used for deriving the master key.
#
# DbBlob format:
#
# The offsets from the start of the blob are as follows:
#
#  0 0xfade0711 - magic number
#  4 version
#  8 crypto-offset - offset of the encryption and signing key
# 12 total len
# 16 signature (16 bytes)
# 32 sequence
# 36 idletimeout
# 40 lockonsleep flag
# 44 salt (20 bytes)
# 64 iv (8 bytes)
# 72 blob signature (20)
#
# Output Format: filename:$keychain$*salt*iv*ciphertext

import sys
import struct
import os
from binascii import hexlify

SALTLEN = 20
IVLEN = 8
CTLEN = 48

magic = b"\xfa\xde\x07\x11"


def process_file(filename):

    f = open(filename, "rb")

    f.seek(-4, 2)

    while True:
        f.seek(-8, 1)
        data = f.read(4)
        if len(data) < 4:
            msg = "%s : Couldn't find db key. Is it a keychain file?\n"
            sys.stderr.write(msg % filename)
            sys.exit(1)

        if data == magic:
            break

    pos = f.tell() - 4

    # ciphertext offset
    f.seek(pos + 8, 0)
    cipheroff = struct.unpack(">I", f.read(4))[0]

    # salt
    f.seek(pos + 44, 0)
    salt = f.read(SALTLEN)
    if len(salt) != SALTLEN:
        sys.stderr.write("Something went wrong - fread(salt) error\n")
        sys.exit(1)

    # IV
    f.seek(pos + 64, 0)
    iv = f.read(IVLEN)
    if len(iv) != IVLEN:
        sys.stderr.write("Something went wrong - fread(iv) error\n")
        sys.exit(1)

    # ciphertext
    f.seek(pos + cipheroff, 0)
    ct = f.read(CTLEN)
    if len(ct) != CTLEN:
        sys.stderr.write("Something went wrong - fread(ct) error\n")
        sys.exit(1)

    # output
    sys.stdout.write("%s:$keychain$*" % os.path.basename(filename))
    sys.stdout.write(hexlify(salt).decode("ascii"))
    sys.stdout.write("*")
    sys.stdout.write(hexlify(iv).decode("ascii"))
    sys.stdout.write("*")
    sys.stdout.write(hexlify(ct).decode("ascii"))
    sys.stdout.write("\n")

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: keychain2john [keychain files]\n")
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
