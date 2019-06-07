#!/usr/bin/env python

# This software is Copyright (c) 2016, Sanju Kholia <sanju.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# luks2john.py is a rewrite of luks2john.c which was written by Milen Rangelov

import sys
import struct
from binascii import hexlify
import base64

PY3 = sys.version_info[0] == 3

"""
LUKS header, derived from LUKS on disk format specification

https://gitlab.com/cryptsetup/cryptsetup/wikis/Specification

static struct luks_phdr {
    char magic[LUKS_MAGIC_L];
    uint16_t version;
    char cipherName[LUKS_CIPHERNAME_L];
    char cipherMode[LUKS_CIPHERMODE_L];
    char hashSpec[LUKS_HASHSPEC_L];
    uint32_t payloadOffset;
    uint32_t keyBytes;
    char mkDigest[LUKS_DIGESTSIZE];
    char mkDigestSalt[LUKS_SALTSIZE];
    uint32_t mkDigestIterations;
    char uuid[UUID_STRING_L];
    struct {
        uint32_t active;
        uint32_t passwordIterations;
        char passwordSalt[LUKS_SALTSIZE];
        uint32_t keyMaterialOffset;
        uint32_t stripes;
    } keyblock[LUKS_NUMKEYS];
} myphdr;
"""

luks_header_fmt = '> 6s h 32s 32s 32s I I 20s 32s I 40s 384s'
luks_header_size = struct.calcsize(luks_header_fmt)
slot_fmt = "> I I 32s I I"
slot_size = 48


def af_sectors(blocksize, blocknumbers):
    af_size = blocksize * blocknumbers
    af_size = (af_size + 511) // 512
    af_size *= 512

    return af_size


def process_file(filename):
    bestiter = 0xFFFFFFFF
    bestslot = 2000
    LUKS_NUMKEYS = 8

    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    myphdr = data = f.read(luks_header_size)
    if len(data) != luks_header_size:
        sys.stderr.write("%s : parsing failed\n" % filename)
        return -1

    data = struct.unpack(luks_header_fmt, data)
    (magic, version, cipherName, cipherMode, hashSpec, payloadOffset, keyBytes,
        mkDigest, mkDigestSalt, mkDigestIterations, uuid, slots) = data

    if magic != b"LUKS\xba\xbe":
        sys.stderr.write("%s : not a LUKS file / disk\n" % filename)
        return -2

    if version != 1:
        sys.stderr.write("%s : Only LUKS1 is supported. Used version: %d\n" %
                         (filename, version))
        return -2

    if not cipherName.startswith(b"aes\x00"):
        sys.stderr.write("%s : Only AES cipher supported. Used cipher: %s\n" %
                         (filename, cipherName))
        return -3

    if not cipherMode.startswith(b"cbc-essiv:sha256\x00"):
        sys.stderr.write("%s : Only cbc-essiv:sha256 mode is supported. Used mode: %s\n" %
                         (filename, cipherMode))
        return -4

    if not hashSpec.startswith(b"sha1\x00"):
        sys.stderr.write("%s : Only sha1 hash is supported. Used hash: %s\n" %
                         (filename, hashSpec))
        return -5

    # find the best slot
    for cnt in range(0, LUKS_NUMKEYS):
        data = slots[slot_size * cnt:slot_size * (cnt + 1)]
        data = struct.unpack(slot_fmt, data)
        (active, passwordIterations,
         passwordSalt, keyMaterialOffset, stripes) = data

        if passwordIterations < bestiter and passwordIterations > 1 \
                and active == 0x00ac71f3:
            bestslot = cnt
            bestiter = passwordIterations
            bestdata = data

    if bestslot == 2000:
        return -6

    afsize = af_sectors(keyBytes, stripes)
    (active, passwordIterations,
     passwordSalt, keyMaterialOffset, stripes) = bestdata

    sys.stderr.write("Best keyslot [%d]: %d keyslot iterations, %d stripes, %d mkiterations\n" %
                     (bestslot, passwordIterations, stripes,
                      mkDigestIterations))

    sys.stderr.write("Cipherbuf size: %d\n" % afsize)
    f.seek(keyMaterialOffset * 512, 0)
    cipherbuf = f.read(afsize)

    myphdr = hexlify(myphdr)
    cipherbuf = base64.b64encode(cipherbuf)
    mkDigest = hexlify(mkDigest)
    if PY3:
        myphdr = str(myphdr, 'ascii')
        cipherbuf = str(cipherbuf, 'ascii')
        mkDigest = str(mkDigest, 'ascii')
    sys.stdout.write("$luks$1$%d$%s" % (luks_header_size, myphdr))
    sys.stdout.write("$%d$%s$%s\n" % (afsize, cipherbuf, mkDigest))

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [LUKS file(s) / disk(s)]\n" % sys.argv[0])

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
