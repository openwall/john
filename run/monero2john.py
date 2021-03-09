#!/usr/bin/python3

# Script to extract "hashes" from Monero databases.
#
# + Tested with monero-gui-v0.11.1.0 on Fedora 27.
# + Tested with monero.linux.x64.v0-9-0-0.tar.bz2 (from Jan, 2016) on Fedora 27.
#
# This software is Copyright (c) 2017, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import os
import sys
import time
import binascii

PY3 = sys.version_info[0] == 3

if not PY3:
    reload(sys)
    sys.setdefaultencoding('utf8')


def process_file(filename):
    if not filename.endswith(".keys"):
        sys.stderr.write("WARNING: This program only works for Monero .keys file(s). Only modern Monero JSON wallets are supported!\n")
        time.sleep(4)

    name = os.path.basename(filename)
    data = binascii.hexlify(open(filename, "rb").read())
    if data:
        data = data.decode("ascii")
    sys.stdout.write("%s:$monero$0*%s\n" % (name, data))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [Monero .keys file(s)]\n\n" % sys.argv[0])
        sys.stderr.write("WARNING: Only modern (> January, 2016) Monero JSON wallets are supported!\n")
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
