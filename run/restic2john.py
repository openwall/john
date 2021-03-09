#!/usr/bin/python3
# -*- coding: utf-8 -*-

# This software is Copyright (c) 2020, Jürgen Hötzel <juergen at hoetzel.info>
# and it is hereby released to the general public under the following terms:

# Redistribution and use in source and binary forms, with or without
# modification, are permitted.


import sys
import os
import os.path
import json
from base64 import b64decode
from binascii import hexlify


def process_dir(directory):
    keys_dir = os.path.join(directory, "keys")
    if not os.path.isdir(keys_dir):
        sys.stderr.write("%s: not a valid restic repository\n" % directory)
        return -1
    for filename in os.listdir(keys_dir):
        with open(os.path.join(keys_dir, filename)) as f:
            config = json.load(f)
            kdf = config.get("kdf")
            if kdf != "scrypt":
                sys.stderr.write("%s: Only scrypt is supported. Used: kdf %s\n" % (kdf, directory))
                continue
            n = config.get("N")
            r = config.get("r")
            p = config.get("p")
            salt = b64decode(config.get("salt"))
            if len(salt) != 64:
                sys.stderr.write("%s: Invalid salt len %d\n" % (kdf, len(salt)))
            data = b64decode(config.get("data"))
            sys.stdout.write("$restic$%s*%s*%s*%s*%s*%s\n" % (kdf, n, r, p, hexlify(salt).decode(), hexlify(data).decode()))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [restic repository dirs]\n" % sys.argv[0])
        sys.exit(-1)

    for j in range(1, len(sys.argv)):
        process_dir(sys.argv[j])
