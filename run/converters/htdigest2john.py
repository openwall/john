#!/usr/bin/env python

"""htdigest2john.py processes htdigest files into a format
suitable for use with JtR."""

import sys
import binascii


def process_file(filename):
    with open(filename, "r") as f:
        for line in f.readlines():
            line = line.rstrip()
            try:
                username, realm, htdigesthash = line.split(":")
            except (ValueError, TypeError):
                continue
            sys.stdout.write("%s:$dynamic_4$%s$HEX$%s\n" % (username,
                htdigesthash, binascii.hexlify("%s:%s:" % (username, realm))))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: %s <htdigest file(s)>\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
