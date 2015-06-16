#!/usr/bin/env python

import sys
import base64
import binascii
from optparse import OptionParser
import argparse

if __name__ == '__main__':

    parser = argparse.ArgumentParser(prog='blockchain2john.py', usage="%(prog)s [blockchain wallet files]")
    parser.add_argument('--json', action='store_true', 
								default=False,
								dest='json', 
								help='is input in base64 format?'
								)

    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(-1)

    if options.json:
        for i in range(0, len(sys.argv)):
            filename = sys.argv[i]
            with open(filename, "rb") as f:
                data = f.read()
                ddata = base64.decodestring(data)
                print "%s:$blockchain$%s$%s" % (filename,
                        len(ddata), binascii.hexlify(ddata))
    else:
        for i in range(0, len(sys.argv)):
            filename = sys.argv[i]
            with open(filename, "rb") as f:
                data = f.read()
                print "%s:$blockchain$%s$%s" % (filename,
                        len(data), binascii.hexlify(data))


