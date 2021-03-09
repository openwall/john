#!/usr/bin/python3

import sys

def process_file(filename):
    with open(filename, "r") as f:
        for line in f.readlines():
            data = line.split(',')

            try:
                username, apexhash, sgid = data
            except:
                continue

            username = username.rstrip().lstrip()
            apexhash = apexhash.rstrip().lstrip()
            sgid = sgid.rstrip().lstrip()

            sys.stdout.write("$dynamic_1$%s$%s\n" % (apexhash, sgid + username))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <apex-hashes.txt file(s)>\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
