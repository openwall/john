#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# References,
#
# https://github.com/freebsd/freebsd/tree/master/sys/geom/eli
# https://github.com/freebsd/freebsd/blob/master/sys/geom/eli/g_eli.h
# https://github.com/freebsd/freebsd/blob/master/sys/opencrypto/cryptodev.h

import sys
import struct
import os.path
from binascii import hexlify

G_ELI_MAGIC = b"GEOM::ELI"
CRYPTO_AES_XTS = 22

# struct g_eli_metadata
g_eli_metadata_fmt = '< 16s I I H H H Q I B i 64s 384s 16s'
g_eli_metadata_size = struct.calcsize(g_eli_metadata_fmt)


def process_file(filename):
    sfilename = os.path.basename(filename)
    f = open(filename, "rb")

    # improve this logic!
    try:
        f.seek(-1024, 2)
    except:
        sys.stderr.write(sfilename + " : file is too short, not processing further!\n")
        return

    data = f.read()
    start = data.find(G_ELI_MAGIC)
    if start != -1:
        data = data[start:]
    else:
        sys.stderr.write(sfilename + " : could not find magic value!\n")
        return

    header = struct.unpack(g_eli_metadata_fmt, data[:g_eli_metadata_size])
    (md_magic, md_version, md_flags, md_ealgo, md_keylen, md_aalgo, md_provsize,
     md_sectorsize, md_keys, md_iterations, md_salt, md_mkeys, md_hash) = header

    if md_version != 7:  # we should be able to support v1 to v7 easily, check this
        sys.stderr.write(sfilename + " : md_version '%s' not supported yet!\n" % md_version)
        return

    if md_ealgo != CRYPTO_AES_XTS:
        sys.stderr.write(sfilename + " : md_ealgo '%s' not supported yet!\n" % md_ealgo)
        return

    salt = hexlify(md_salt).decode("ascii")
    mkeys = hexlify(md_mkeys).decode("ascii")
    sys.stdout.write("%s:$geli$0$%s$%s$%s$%s$%s$%s$%s$%s\n" % (sfilename,
                                                               md_version,
                                                               md_ealgo,
                                                               md_keylen,
                                                               md_aalgo,
                                                               md_keys,
                                                               md_iterations,
                                                               salt, mkeys))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: %s [disk image]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
