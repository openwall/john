#!/usr/bin/env python

# Helper for cracking Mozilla's password database (key3.db master password).
#
# All the real logic here is borrowed from Milen Rangelov's Hashkill project and from Deque's article.
#
# Mozilla saves the login data in signons.sqlite file using base64 encoding, 3DES in CBC mode encryption and standard
# block padding. The decryption key is saved in the key3.db file whose entries are encrypted with the master password.
# To verify the master password, decrypt the password-check entry and it should be equal to the fixed string
# "check-password\x00\x00".
#
# http://www.drh-consultancy.demon.co.uk/key3.html
#
# This software is Copyright (c) 2014, Sanju Kholia <sanju.kholia [at] gmail.com> and Dhiru Kholia, and it is hereby
# released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without modification, are permitted.

import sys
import os
from binascii import hexlify


def fail(filename):
    msg = "%s : Couldn't find the magic. Is this a key3.db file?\n"
    sys.stderr.write(msg % filename)


def process_file(filename):

    data = open(filename, "rb").read()

    idx = data.find("global-salt")
    if idx < 0:
        fail(filename)
        return
    # global_salt is at offset = idx -20
    if idx - 20 < 0:
        fail(filename)
        return
    global_salt = data[idx-20:][0:20]  # is the salt always 20 bytes?

    idx = data.find("password-check")
    if idx < 0:
        fail(filename)
        return
    # password_check is at offset = idx - 52  # does this always hold?
    if idx - 52 < 0:
        fail(filename)
        return
    password_check = data[idx-52:][0:52]
    entry_salt = password_check[3:][0:20]
    verifier = password_check[52-16:][0:16]

    version = 3  # fake (this should be improved)
    nnLen = 1  # fake
    oidLen = 11  # fake
    oidData = "\x00" * oidLen  # fake
    sys.stdout.write("%s:$mozilla$*%s*%s*%s*" % (os.path.basename(filename), version, len(entry_salt), nnLen))
    sys.stdout.write(hexlify(entry_salt).decode("ascii"))
    sys.stdout.write("*%s*%s*%s*" % (oidLen, hexlify(oidData).decode("ascii"), len(verifier)))
    sys.stdout.write(hexlify(verifier).decode("ascii"))
    sys.stdout.write("*%s*" % len(global_salt))
    sys.stdout.write(hexlify(global_salt).decode("ascii"))
    sys.stdout.write("\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: mozilla2john [key3.db file(s)]\n")
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
