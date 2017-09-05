#!/usr/bin/env python

# This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>
# and it is hereby released under GPL v2 license.
#
# Major parts are borrowed from the "btcrecover" program which is,
# Copyright (C) 2014-2016 Christopher Gurnee and under GPL v2.
#
# See https://github.com/gurnec/btcrecover for details.
#
# References,
#
# https://github.com/gurnec/btcrecover/blob/master/btcrecover/btcrpass.py

import os
import sys
import base64
import binascii


def process_file(filename):
    bname = os.path.basename(filename)
    try:
        f = open(filename, "rb")
        data = f.read()
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    version = 1  # MultiBit Classic
    pdata = b"".join(data.split())
    if len(pdata) < 64:
        sys.stderr.write("%s: Short length for a MultiBit wallet file!\n" % bname)
        return

    try:
        pdata = base64.b64decode(pdata[:64])
        if not pdata.startswith("Salted__"):
            version = 2
        if len(pdata) < 48:
            # sys.stderr.write("%s: Short length for a MultiBit wallet file!\n" % bname)
            # return
            version = 2  # MultiBit HD possibly?
    except:
        version = 2  # MultiBit HD possibly?

    if version == 1:
        encrypted_data = pdata[16:48]  # two AES blocks
        salt = pdata[8:16]
        encrypted_data = binascii.hexlify(encrypted_data).decode("ascii")
        salt = binascii.hexlify(salt).decode("ascii")
        sys.stdout.write("%s:$multibit$%d*%s*%s\n" % (bname, version, salt, encrypted_data))
        return
    else:
        version = 2
        # sanity check but not a very good one
        if "wallet" not in bname and "aes" not in bname:
            sys.stderr.write("%s: Make sure that this is a MultiBit HD wallet!\n" % bname)
        # two possibilities
        iv = data[:16]  # v0.5.0+
        block_iv = data[16:32]  # v0.5.0+
        block_noiv = data[:16]  # encrypted using hardcoded iv, < v0.5.0
        iv = binascii.hexlify(iv).decode("ascii")
        block_iv = binascii.hexlify(block_iv).decode("ascii")
        block_noiv = binascii.hexlify(block_noiv).decode("ascii")
        sys.stdout.write("%s:$multibit$%d*%s*%s*%s\n" % (bname, version, iv, block_iv, block_noiv))
        return

    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [MultiBit Classic or HD wallets files (.key, mbhd.wallet.aes)]\n" % sys.argv[0])
        sys.stderr.write("\nMultiBit Classic -> for a wallet named 'xyz', we need the xyz-data/key-backup/xyz*.key file\n")
        sys.exit(-1)

    for j in range(1, len(sys.argv)):
        process_file(sys.argv[j])
