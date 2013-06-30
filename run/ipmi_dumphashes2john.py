#!/usr/bin/env python

import sys

def process_file(filename):
    with open(filename, "r") as f:
        for line in f.readlines():
            data = line.strip().split(":")

            if len(data) == 3:
                inp = data[1]
                username = data[0]
                verifier = data[2]
            elif len(data) == 2:
                inp = data[0]
                username = "dummy"
                verifier = data[1]
            else:
                assert 0

            sys.stdout.write("%s:$rakp$%s$%s\n" % (username, inp, verifier))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <ipmi_dumphashes output>\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
