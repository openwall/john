#!/usr/bin/env python

"""sipdump2john.py processes sipdump output files (dump files)
into a format suitable for use with JtR."""

import sys


def process_file(filename):
    with open(filename, "r") as f:
        for line in f.readlines():
            line = line.rstrip().replace('"', '*').replace(':', '*')
            data = line.split('*')
            # Handle the case when the port number is not explicit
            # in the uri field, in that case, adds an empty field
	    if len(data) == 13:
	    	data.insert(7, '')
            print "%s-%s:$sip$*%s" % (data[0], data[1], '*'.join(data))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print >>sys.stderr, "Usage: %s <sipdump dump files>" % sys.argv[0]
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
