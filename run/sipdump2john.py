#!/usr/bin/env python

"""sipdump2john.py processes sipdump output files (dump files)
into a format suitable for use with JtR."""

import sys

def process_file(filename):
    with open(filename, "r") as f:
        for line in f.readlines():
            line = line.rstrip().replace('"', '*').replace(':', '*')
            data = line.split('*');
            print "%s-%s:$sip$*%s" % (data[0], data[1], line)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print >>sys.stderr, "Usage: %s <sipdump dump files>" % sys.argv[0]
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])


