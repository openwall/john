#!/usr/bin/env python

"""strip2john.py processes STRIP files into a format suitable
for use with JtR.

Output Format:filename:$strip$*data """

import sys
import os.path
import binascii


def process_file(filename):
    try:
        f = open(filename)
    except (IOError):
        e = sys.exc_info()[1]
        sys.stderr.write("%s : %s\n" % (filename, str(e)))
        return 2

    data = f.read(1024)

    sys.stderr.write("%s:$strip$*%s\n" % (os.path.basename(filename),
                                          binascii.hexlify(data)))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <STRIP files>\n" % sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
