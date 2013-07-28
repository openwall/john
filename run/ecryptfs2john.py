#!/usr/bin/env python

import sys

def process_file(filename):
    with open(filename, "r") as f:
        h = f.read(16)
        if len(h) != 16:
            return

        # we don't use basename() because we need to distinguish clearly
        # between different files all named wrapped-passphrase
        sys.stdout.write("%s:$ecryptfs$0$%s\n" % \
                (filename, h))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <wrapped-passphrase file(s)>\n" % \
                sys.argv[0])
        sys.stderr.write("\nExample: %s ~/.ecryptfs/wrapped-passphrase\n" % \
                sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
