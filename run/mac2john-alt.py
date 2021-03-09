#!/usr/bin/python3

# This software is Copyright (c) 2018, Dhiru Kholia <dhiru.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# This script is inspired by https://github.com/JMagers/MacinHash script from
# Jake Magers.
#
# From https://docs.python.org/3/library/plistlib.html,
#
# Changed in version 3.4: New API, old API deprecated. Support for binary format plists added.
#
# This program is only tested to work with Python versions >= 3.4 and <= 3.7.1.

import sys
import binascii
import plistlib


if sys.version_info[0] < 3 or sys.version_info[1] < 4:
    print("This script requires Python version >= 3.4. Try ../run/mac2john.py script instead of this for older Python versions.")
    sys.exit(1)


def process_file(filename):
    with open(filename, "rb") as fp:
        try:
            plist = plistlib.load(fp, use_builtin_types=True)
        except:
            print("%s: unable to process as a plist file!" % filename)
            return

        hints = ""
        hl = plist.get('realname', []) + plist.get('hint', [])
        hints += ",".join(hl)
        uid = plist.get('uid', ["500"])[0]
        gid = plist.get('gid', ["500"])[0]
        shell = plist.get('shell', ["bash"])[0]
        name = plist.get('name', ["user"])[0]

        try:
            data = plistlib.loads(plist['ShadowHashData'][0])
        except:
            print("%s: could not find ShadowHashData" % filename)
            return

        d = data.get('SALTED-SHA512-PBKDF2', None)
        if not d:
            sys.stderr.write("%s does not contain SALTED-SHA512-PBKDF2 hashes\n" % filename)
            return

        salt = binascii.hexlify(d.get('salt')).decode("ascii")
        entropy = binascii.hexlify(d.get('entropy')).decode("ascii")
        iterations = d.get('iterations')

        sys.stdout.write("%s:$pbkdf2-hmac-sha512$%d.%s.%s:%s:%s:%s:%s:%s\n" % \
                (name, iterations, salt, entropy[0:128], uid, gid, hints,
                 shell, filename))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("This program helps in extracting password hashes from OS X / macOS systems (>= Mountain Lion -> 10.8+).\n")
        print("Run this program against .plist file(s) obtained from /var/db/dslocal/nodes/Default/users/<username>.plist location.\n")
        print("Usage: %s <OS X / macOS .plist files>" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
