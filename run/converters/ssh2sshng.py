#!/usr/bin/env python

"""Utility to convert old style ssh format hashes into new sshng format hashes."""

import sys
from sshng2john import RSADSSKey
import StringIO
import binascii


def process_file(filename):
    with open(filename, "r") as f:
        for line in f.readlines():
            data = line.split(":")
            assert(len(data) < 3)
            if len(data) < 2:
                name = "Unknown"
            else:
                name = data[0]
                data = data[1]

            if data.startswith("$ssh2$"):
                data = data.split("*")
                assert(len(data) == 2)
                data = binascii.unhexlify(data[0][6:])
                f = StringIO.StringIO(data)
                f.name = name
                RSADSSKey.from_private_key(f, '')
            else:
                continue


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print >>sys.stderr, "Usage: %s <ssh2john output file(s)>" % sys.argv[0]
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
