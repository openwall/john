#!/usr/bin/env python

import json
import hashlib
import sys
import base64

if __name__ == '__main__':

    args = sys.argv

    if len(args) < 1:
        print >> sys.stderr, "Usage: %s [blockchain wallet files]" % sys.argv[0]
        sys.exit(-1)

    for i in range(1, len(args)):
        filename = args[i]
        with open(filename, "rb") as f:
            data = f.read()
            ddata = base64.decodestring(data)
            print "%s:$blockchain$%s$%s" % (filename,
                    len(ddata), ddata.encode("hex"))


