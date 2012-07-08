#!/usr/bin/env python

"""ikescan2john.py processes ike-scan output files into a format suitable
for use with JtR."""

import sys


def usage():
    print >>sys.stderr, "Usage: %s <psk-parameters-file> [norteluser]" % sys.argv[0]
    sys.exit(-1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    with open(sys.argv[1], "r") as f:
        for line in f.readlines():
            line = line.rstrip().replace(':', '*')
            if len(sys.argv) == 2:
                print "$ike$*0*%s" % (line)
            elif len(sys.argv) == 3:
                print "$ike$*1*%s*%s" % (sys.argv[2], line)
            else:
                usage()
