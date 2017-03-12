#!/usr/bin/env python

# This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Written in March of 2017 based on Padlock Android application.

import os
import sys

try:
    import json
    assert json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        sys.stderr.write("Please install json / simplejson module which is currently not installed.\n")
        sys.exit(-1)

from base64 import b64decode
from binascii import hexlify


def process_file(filename):
    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    data = f.read()
    try:
        data = json.loads(data)
        cipher = data["cipher"]
        tag_len = data["ts"]
        iterations = data["iter"]
        mode = data["mode"]
        add = data["adata"]
        iv = data["iv"]
        key_size = data["keySize"]
        salt = data["salt"]
        ct = data["ct"]
    except:
        sys.stdout.write("%s: json parsing failed\n" % filename)
        return -1

    if mode != "ccm":
        sys.stdout.write("%s: unexpected mode '%s' found\n" % (filename, mode))
        return -2

    if cipher != "AES":
        sys.stdout.write("%s: unexpected cipher '%s' found\n" % (filename,
                                                                 cipher))
        return -2

    if str(key_size) != "256":
        sys.stdout.write("%s: unexpected key size '%s' found\n" % (filename,
                                                                   key_size))
        return -2

    # add more error checking here

    ct = hexlify(b64decode(ct)).encode("ascii")
    ctlen = len(ct) / 2
    add = hexlify(b64decode(add)).encode("ascii")
    addlen = len(add) / 2
    salt = hexlify(b64decode(salt)).encode("ascii")
    saltlen = len(salt) / 2
    iv = hexlify(b64decode(iv)).encode("ascii")
    version = 1  # internal format version, reserved for future use

    tlb = int(tag_len) / 8
    if ctlen - tlb == 2:  # empty padlock database, plaintext is "[]"
        sys.stdout.write("%s: empty database found, expect false positives!\n" %
                         (filename))

    sys.stdout.write("%s:$padlock$%s$%s$%s$%s$%s$%s$%s$%s$%s$%s\n" %
                     (os.path.basename(filename), version, iterations, tag_len,
                      saltlen, salt, iv, addlen, add, ctlen, ct))

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [Padblock file(s)]\n" % sys.argv[0])
        sys.exit(-1)

    for j in range(1, len(sys.argv)):
        process_file(sys.argv[j])
