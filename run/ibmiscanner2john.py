#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ibmiscanner2john.py (by Rob Schoemaker (@5up3rUs3r))
# Convert files in format userid:hash (e.g files produced by older versions of the ibmiscanner tool)
# to the as400-sha format that can be processed by JtR. Multiple files can be specified.
# Output is sent to stdout. Redirect stdout to create a file for JtR.
# See hackthelegacy.org for ibmiscanner tooling

import sys
import os

def process_file(filename):
    if not os.path.isfile(filename):
        sys.stderr.write("Error: skipping '%s': file does not exist\n" % filename)
        return

    with open(filename, "r") as f:
        for line in f.read().splitlines():
            try:
                data = line.split(':')
                out = data[0] + ":$as400ssha1$" + data[1] + "$" + data[0]
                print out.encode('utf-8')
            except:
                sys.stderr.write("Error: parsing of line '%s' failed - skipping\n" % line)
                pass

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s file [file ...]\n" % sys.argv[0])
        sys.stderr.write("       Output is written to stdout. Redirect stdout to create a file for JtR\n")
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
