#!/usr/bin/env python

"""strip2john.py processes STRIP files into a format suitable
for use with JtR.

Output Format:filename:$strip$*data """

import sys
import binascii


def process_file(filename):
    try:
        f = open(filename)
    except Exception, e:
        print >> sys.stderr, "%s : %s" % (filename, str(e))
        return 2

    data = f.read(1024)

    print "%s:$strip$*%s" % (filename, binascii.hexlify(data))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print >> sys.stderr, "Usage: %s <STRIP files>" % sys.argv[0]
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
