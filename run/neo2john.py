#!/usr/bin/env python

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


def process_file(filename):
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    rows = cursor.execute("SELECT * FROM Key""")
    for row in rows:
        if row[0] == 'PasswordHash':
            h = binascii.hexlify(row[1])
            if PY3:
                h = str(h, 'ascii')
            print("%s:$dynamic_1608$%s" % (os.path.basename(filename), h))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.db3 files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
