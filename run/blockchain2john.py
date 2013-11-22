#!/usr/bin/env python

import sys
import base64
import binascii
from optparse import OptionParser

if __name__ == '__main__':

    parser = OptionParser(usage="%prog [blockchain wallet files]")

    parser.add_option("--json", dest="json", action="store_true",
            default=False, help="is input in base64 format?")

    (options, args) = parser.parse_args()

    if len(args) < 1:
        parser.print_help()
        sys.exit(-1)

    if options.json:
        for i in range(0, len(args)):
            filename = args[i]
            with open(filename, "rb") as f:
                data = f.read()
                ddata = base64.decodestring(data)
                print "%s:$blockchain$%s$%s" % (filename,
                        len(ddata), binascii.hexlify(ddata))
    else:
        for i in range(0, len(args)):
            filename = args[i]
            with open(filename, "rb") as f:
                data = f.read()
                print "%s:$blockchain$%s$%s" % (filename,
                        len(data), binascii.hexlify(data))


