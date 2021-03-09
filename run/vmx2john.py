#!/usr/bin/python3

# This software is Copyright (c) 2019 - Dhiru Kholia, Copyright (c) 2018 -
# axcheron, and it is hereby released under the MIT License.
#
# Key parts of this program are borrowed from the pyvmx-cracker project.
#
# See https://github.com/axcheron/pyvmx-cracker for details.

import os
import re
import sys
import base64
import argparse
from binascii import hexlify

PY3 = sys.version_info[0] == 3

if PY3:
    from urllib.parse import unquote
else:
    from urllib import unquote


def process_file(target):
    ks_re = '.+phrase/(.*?)/pass2key=(.*?):cipher=(.*?):rounds=(.*?):salt=(.*?),(.*?),(.*?)\)'

    name = "Unknown"
    keysafe = None

    with open(target, "r") as f:
        for line in f:
            if 'encryption.keySafe' in line:
                keysafe = line
            if "displayName" in line:
                name = line.split(" = ")[1].rstrip().strip('"')

    keysafe = unquote(keysafe)

    match = re.match(ks_re, keysafe)
    if not match:
        sys.stderr.write("Unsupported format of the encryption.keySafe line:\n")
        return

    iden = hexlify(base64.b64decode(match.group(1))).decode()
    password_hash = match.group(2)
    if password_hash != "PBKDF2-HMAC-SHA-1":
        sys.stderr.write("Unsupported password hashing algorithm (%s) found!\n" % password_hash)
        return
    password_cipher = match.group(3)
    if password_cipher != "AES-256":
        sys.stderr.write("Unsupported cipher (%s) found!\n" % password_cipher)
        return

    iterations = int(match.group(4))
    salt = hexlify(base64.b64decode(unquote(match.group(5))))
    config_hash = match.group(6)
    if config_hash != "HMAC-SHA-1":
        sys.stderr.write("Unsupported hashing algorithm (%s) found!\n" % config_hash)
        return

    cipherdata = hexlify(base64.b64decode(match.group(7)))

    sys.stdout.write("%s-%s:$vmx$1$0$0$%d$%s$%s\n" % (os.path.basename(target),
            name, iterations, salt, cipherdata))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.vmx files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
