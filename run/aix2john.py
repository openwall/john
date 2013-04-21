#!/usr/bin/env python

import binascii
import sys

try:
    # FIXME: don't depend on passlib
    from passlib.utils import h64
except ImportError:
    sys.stderr.write("Please install passlib python module!\n")

# NOTE: this map is taken from passlib itself!
_transpose_map = [12, 6, 0, 13, 7, 1, 14, 8, 2, 15, 9, 3, 5, 10, 4, 11]

def process_file(filename):
    try:
        fd = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    username = "?"

    for line in fd.readlines():
        output = False
        line = line.rstrip('\n')
        if line.endswith(':'):
            username = line.split(':')[0]
        if "password = " in line and "smd5" in line:
            h = line.split("=")[1].lstrip().rstrip()
            output = True
            # FIXME: add support for more LPA(s)
            if len(h) != 37:
                continue
            salt, h = h[6:].split('$')
        if output:
            try:
                h = h64.decode_transposed_bytes(h, _transpose_map)
            except:
                pass
            # FIXME: add support for standard AIX hashes too
            sys.stdout.write("%s:{smd5}%s$%s$0\n" % (username,
                    salt, binascii.hexlify(h)))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <AIX passwd file(s) "
            "(/etc/security/passwd)>\n" % sys.argv[0])
        sys.exit(-1)

    for k in range(1, len(sys.argv)):
        process_file(sys.argv[k])
