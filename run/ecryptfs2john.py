#!/usr/bin/env python

# Helper script for cracking eCryptfs.
#
# Refer to "ecryptfs-utils_104.orig.tar.gz" in case of doubt.
#
# This software is Copyright (c) 2014 Dhiru Kholia <dhiru.kholia at gmail.com> and
# Copyright (c) 2015, NagraVision <sylvain.pelissier at nagra.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import sys
import binascii


def process(filename, ecryptfsrc):
    salt = None
    if ecryptfsrc:  # extract variable salt from this file
        with open(ecryptfsrc, "r") as f:
            for line in f:
                if line.startswith("salt="):
                    _, salt = line.strip().split("=")
                    salt = salt[0:16]  # fixed size salt

    with open(filename, "rb") as f:
        version = f.read(2)  # Read file version
        if version == b':\x02':  # Test if version 2 of the file format is used.
            salt = binascii.hexlify(f.read(8)).decode("ascii")
            h = f.read(16).decode("ascii")
        else:  # Version 1 is used.
            h = (version + f.read(14)).decode("ascii")

        if len(h) != 16:
            return

    # we don't use basename() because we need to distinguish clearly
    # between different files, which are all named "wrapped-passphrase"
    if not salt:
        sys.stdout.write("%s:$ecryptfs$0$%s\n" % (filename, h))
    else:
        sys.stdout.write("%s:$ecryptfs$0$1$%s$%s\n" % (filename, salt, h))  # $1$ indicates variable salt


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <wrapped-passphrase> [.ecryptfsrc]\n" % sys.argv[0])
        sys.stderr.write("\nExample: %s ~/.ecryptfs/wrapped-passphrase" % sys.argv[0])
        sys.stderr.write("\nExample: %s ~/.ecryptfs/wrapped-passphrase ~/.ecryptfsrc\n" % sys.argv[0])
        sys.exit(1)

    try:
        ecryptfsrc = sys.argv[2]
    except IndexError:
        ecryptfsrc = None

    process(sys.argv[1], ecryptfsrc)
