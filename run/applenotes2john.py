#!/usr/bin/python3

# Script to extract "hashes" from password protected Apple Notes databases.
#
# All credit goes to hashcat folks for doing the original hard work.
#
# ~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite <- typical
# database location.
#
# This software is Copyright (c) 2017, Dhiru Kholia <kholia at kth.se> and it is
# hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import os
import sys
import sqlite3
import binascii

PY3 = sys.version_info[0] == 3

if not PY3:
    reload(sys)
    sys.setdefaultencoding('utf8')


def process_file(filename):
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    rows = cursor.execute("SELECT Z_PK, ZCRYPTOITERATIONCOUNT, ZCRYPTOSALT, ZCRYPTOWRAPPEDKEY, ZPASSWORDHINT, ZCRYPTOVERIFIER, ZISPASSWORDPROTECTED FROM ZICCLOUDSYNCINGOBJECT")
    for row in rows:
        iden, iterations, salt, fhash, hint, shash, is_protected = row
        if fhash is None:
            phash = shash
        else:
            phash = fhash
        if hint is None:
            hint = "None"
        # NOTE: is_protected can be zero even if iterations value is non-zero!
        # This was tested on macOS 10.13.2 with cloud syncing turned off.
        if iterations == 0:  # is this a safer check than checking is_protected?
            continue
        if phash is None:
            continue
        phash = binascii.hexlify(phash)
        salt = binascii.hexlify(salt)
        if PY3:
            phash = str(phash, 'ascii')
            salt = str(salt, 'ascii')
        fname = os.path.basename(filename)
        sys.stdout.write("%s:$ASN$*%d*%d*%s*%s:::::%s\n" % (fname, iden,
                                               iterations, salt, phash, hint))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [Apple Notes .sqlite files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
