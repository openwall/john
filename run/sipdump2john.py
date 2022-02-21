#!/usr/bin/env python

"""sipdump2john.py processes sipdump output files (dump files)
into a format suitable for use with JtR."""

import sys
import re


def process_file(filename):
    with open(filename, "r") as f:
        for line in f.readlines():
            line = re.sub(r'sip\:\*', r'sip:0.0.0.0', line)
            line = line.rstrip().replace('"', '*').replace(':', '*')
            data = line.split('*')
            # Handle the case when the port number is not explicit
            # in the uri field, in that case, adds an empty field
            if len(data) == 13:
                data.insert(7, '')
            sys.stdout.write("%s-%s:$sip$*%s\n" % (data[0], data[1], '*'.join(data)))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <sipdump files>\n" % sys.argv[0])
        sys.exit(1)

    for i in sys.argv[1:]:
        process_file(i)
