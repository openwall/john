#!/usr/bin/python3

# Extracts "hashes" from Dashlane's .aes and .dash files.
#
# This software is Copyright (c) 2017, Dhiru Kholia <kholia at kth.se> and it is
# hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import sys
import os.path
from binascii import hexlify
import base64

PY3 = sys.version_info[0] == 3


def process_secure_archive(filename):
    dump_next = False
    vline = None
    with open(filename, "rb") as f:
        for line in f:
            if b"Data BEGIN" in line:
                dump_next = True
                continue
            if dump_next:
                vline = line.strip()
                dump_next = False

    if vline:
        return base64.b64decode(vline)[:256]

    return None


def process(filename, plaintext=None, cipher=0, md=0):
    with open(filename, "rb") as f:
        data = f.read()

        if b"Data BEGIN" in data:
            data = process_secure_archive(filename)
        else:
            data = data[:256]  # this is enough for cracking .aes files

        if len(data) < 32:
            sys.stderr.write("%s: too short to be valid database?\n" % filename)
            return

        salt = hexlify(data[0:32])
        if PY3:
            salt = salt.decode("ascii")
        v = 0
        if data[32:].startswith(b'KWC3'):
            v = 1
            aes_data = data[32+4:]  # skip over KWC3 which implies compression
        else:
            aes_data = data[32:]

        aes_data = hexlify(aes_data)
        if PY3:
            aes_data = aes_data.decode("ascii")

        sys.stdout.write("%s:$dashlane$%s*%s*%s*%s\n" % (os.path.basename(filename), v, salt,
                                                         len(aes_data) // 2,
                                                         aes_data))

        return

if __name__ == '__main__':

    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <.aes or .dash files from Dashlane for Windows Desktop / macOS>\n" % sys.argv[0])
        sys.stderr.write("\nNote: This only works with data from Windows and macOS Desktop version of Dashlane.\n")
        sys.stderr.write("\nThe required .aes files can be found inside %AppData%\Dashlane\profiles directory tree on Windows.\n")
        sys.stderr.write("\nThe required .aes files can be found inside ~/Library/Application\ Support/Dashlane/profiles/ directory tree on macOS.\n")
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process(sys.argv[i])
