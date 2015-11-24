#!/usr/bin/env python

import binascii
import sys
import re

try:
	 import argparse
except ImportError:
    sys.stderr.write("Stop living in the past. Upgrade your python!\n")


def process_file(filename, is_standard):
    try:
        fd = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    username = "?"

    for line in fd.readlines():
        if re.match('^\s*\S+\s*:\s*$',line):
            username = line.split(':')[0]

        if "password = " in line and "smd5" in line:
            h = line.split("=")[1].strip()
            if len(h) != 37:
                continue
            if is_standard:
                sys.stdout.write("%s:$1$%s\n" % (username, h[6:]))
            else:
                sys.stdout.write("%s:%s\n" % (username,
                    h))

        elif "password = " in line and "ssha" in line:
            h = line.split("=")[1].strip()

            tc, salt, h = h.split('$')

            sys.stdout.write("%s:%s$%s$%s\n" % (username,
                    tc, salt, h))

        elif "password = " in line:  # DES
            h = line.split("=")[1].strip()
            if h != "*":
                sys.stdout.write("%s:%s\n" % (username, h))


if __name__ == "__main__":

    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [-s] -f <AIX passwd file "
            "(/etc/security/passwd)>\n" % sys.argv[0])
        sys.exit(-1)

    parser = argparse.ArgumentParser()
    parser.add_argument('-s', action="store_true",
    						default=False,
    						dest="is_standard",
    						help='Use this option if "lpa_options '
    								'= std_hash=true" is activated'
    						)
    
    parser.add_argument('-f', dest="filename",
    						default=False,
    						help='Specify the AIX shadow file filename to read (usually /etc/security/passwd)'
    						)
    
    args = parser.parse_args()
    
    if args.filename:
        process_file(args.filename, args.is_standard)
    else:   
        print "Please specify a filename (-f)"
        sys.exit(-1)

