#! /usr/bin/python3
#
# This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Extracts hashes from Prosody IM's .dat files which can be found under the
# /var/lib/prosody/<domain>/accounts location.

import os
import sys
from binascii import hexlify


def cleanup(s):
    return s.strip().rstrip(";").replace('"', '')


def process_file(name):
    f = open(name, "rb")

    iterations = None
    stored_key = None
    salt = None

    for l in f:
        try:
            _, v = l.decode("utf-8").split("=")
        except ValueError:
            continue
        v = cleanup(v)
        if b"iteration_count" in l:
            iterations = v
        if b"stored_key" in l:
            stored_key = v
        if b"salt" in l:
            salt = hexlify(v.encode("ascii")).decode("ascii")

    if iterations and stored_key and salt:
        sys.stdout.write("%s:$xmpp-scram$0$%s$%s$%s$%s\n" %
                         (os.path.basename(name), iterations, len(salt) // 2,
                          salt, stored_key))

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [prosody .dat files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
