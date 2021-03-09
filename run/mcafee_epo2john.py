#!/usr/bin/python3

# Convert McAfee ePO passwords to John format.
#                   -- nicolas.collignon@synacktiv.com
#
# ePO configuration is stored in a DB server. Authentication may be based on
# AD or on a SHA1 hash stored in the DB.
#
# This script converts a CSV output of dbo.OrionUsers table to john format.
# The CSV output must at least match the following schema:
#   - column #1 -> Name   (not really used)
#   - column #2 -> AuthURI
#   - column separator must be ","
#
# ex:
#
# $ cat orion_users.csv      (extracted from dbo.OrionUsers)
# Name,AuthURI
# system,auth:pwd?pwd=kDv1oBRuGOU3MnpIDbyBJEmJZ%2FauS1zf  <-- SHA1 based
# adminepo,auth:ntlm?domain=XYZ&user=adminepo             <-- AD based
#
# $ ./mcafee_epo2john.py orion_users.csv > orion_hashes.txt
#
# $ john -single orion_hashes.txt
# Loaded 1 password hashes with 1 different salts (dynamic_24 [sha1($p.$s) 128/128 AVX 10x4x1])
# Press 'q' or Ctrl-C to abort, almost any other key for status
# system           (system)
#
#
# This software is Copyright (c) Nicolas Collignon <nicolas.collignon@synacktiv.com>,
# and it is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import sys
import urllib

PREFIX = 'auth:pwd?pwd='


def orion2john(f_in, f_out, sep=','):

    for line in f_in:
        words = line.strip().split(sep)
        if len(words) < 2 or not words[1].startswith(PREFIX):
            continue

        blob = urllib.unquote(words[1][len(PREFIX):]).decode('base64')
        if len(blob) == 24:
            seed, digest = blob[20:].encode('hex'), blob[:20].encode('hex')
            f_out.write('%s:$dynamic_24$%s$HEX$%s\n' % (words[0], digest,
                                                        seed))
        else:
            sys.stderr.write('invalid hash len: %i\n' % len(blob))


def usage():
    sys.stdout.write('usage: %s [dbo.OrionUsers CSV extracts]\n' % sys.argv[0])
    sys.exit(1)


if __name__ == '__main__':

    if len(sys.argv) < 2:
        usage()

    for arg in sys.argv[1:]:

        if arg == '-':
            f = sys.stdin
        else:
            f = open(arg, 'rb')

        orion2john(f, sys.stdout)

        if f != sys.stdin:
            f.close()
