#!/usr/bin/env python

"""Program to calculate CRC32 checksum of files."""

import sys
from zlib import crc32

def process_file(filename):
    """Calculate CRC32 checksum of filename."""
    data = open(filename, "r").read()
    crc = "%X" % (crc32(data) & 0xFFFFFFFF)
    return crc

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print >> sys.stderr, "Usage: %s <files>" % sys.argv[0]
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        print sys.argv[i], ":", process_file(sys.argv[i])
