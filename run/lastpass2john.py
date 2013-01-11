#!/usr/bin/env python

"""lastpass2john.py converts input LastPass data into a format suitable
for use with JtR.

Output Format:filename:$lp$email(salt)$hash"""

import sys
import binascii
import base64


def process_file(email, filename):
    try:
        f = open(filename)
    except Exception, e:
        print >> sys.stderr, "%s : %s" % (filename, str(e))
        return 2

    f.readline() # ignore first line
    data = f.readline()
    if not data:
        print >> sys.stderr, "%s : %s" % (filename, "Unable to parse data. Are you sure this is LastPass data?")

    print "%s:$lp$%s:%s" % (filename, email, binascii.hexlify(base64.decodestring(data)))

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print >> sys.stderr, "Usage: %s <email address> <LastPass *._lpall.slps file>" % sys.argv[0]
        sys.exit(-1)

    process_file(sys.argv[1], sys.argv[2])
