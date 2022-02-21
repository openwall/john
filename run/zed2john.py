#!/usr/bin/env python3
# v0.3 now uses the login names
# v0.2 comments added, find PBA vectors for every users

# This software is Copyright (c) 2019 Gigix & magnum,
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# zed2john.py is based of pkcs12kdf which was written by Hari Selvarajan
# and zed archive description which was written by Sylvain Beucler
# (https://www.beuc.net/zed/)

import os
import sys
import struct
from binascii import hexlify
import base64
from Crypto.Cipher import AES
import hashlib
from pkcs12kdf import PKCS12KDF
import binascii


CTLFILE_DELIMITER = b'\x07\x65\x92\x1A\x2A\x07\x74\x53\x47\x52\x07\x33\x61\x71\x93\x00'
STATIC_KEY = b'\x37\xF1\x3C\xF8\x1C\x78\x0A\xF2\x6B\x6A\x52\x65\x4F\x79\x4A\xEF'
VER1 = b'\x01\x00'
VER2 = b'\x02\x00'
PBA_SALT = b'\x80\x7a\x05\x00'
PBA_ITER = b'\x80\x7b\x02\x00'
HASH_FUNC = b'\x80\x78\x02\x00'
PBA_CHK = b'\x80\x79\x05\x00'

USERNAME = b'\x80\x71\x04\x00'

PY3 = sys.version_info[0] == 3

if not PY3:
    reload(sys)
    sys.setdefaultencoding("utf8")

def parse_item(data, item, x):
    i = x
    while data[i:i+len(item)] != item:
        i += 1

    if i == len(data):
        sys.stderr.write("%s : not passphrase based or protocol error\n" % filename)
        sys.exit(1)

    return data[i + len(item) + 4 : i + len(item) + 4 + int.from_bytes(data[i + len(item) : i + len(item) + 4],byteorder='big')]

def parse_users(data):
    users = list()
    names = list()
    i = 0
    while i < len(data):
        while data[i:i+len(USERNAME)] != USERNAME and i < len(data):
            i += 1

        if i < len(data):
            names.append(data[i + len(USERNAME) + 4 : i + len(USERNAME) + 4 + int.from_bytes(data[i + len(USERNAME) : i + len(USERNAME) + 4],byteorder='big')].decode('utf-16'))
            users.append(i)

        i += len(USERNAME)

    return users, names

def parse(data, x):
    pba_chk = parse_item(data, PBA_CHK, x)
    pba_chk = binascii.hexlify(pba_chk).decode("ascii")
    hash_func = parse_item(data, HASH_FUNC, x)
    hash_func = binascii.hexlify(hash_func).decode("ascii")
    pba_iter = parse_item(data, PBA_ITER, x)
    pba_iter = binascii.hexlify(pba_iter).decode("ascii")
    pba_salt = parse_item(data, PBA_SALT, x)
    pba_salt = binascii.hexlify(pba_salt).decode("ascii")
    return hash_func, pba_chk, pba_iter, pba_salt


def pkcs7(plaintext):
    padbytes = 16 - len(plaintext) % 16
    pad = bytearray(padbytes * chr(padbytes),"ascii")
    return plaintext + pad

def parse_decode_global_properties(filename):
    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return
    data = f.read()
    f.close()

    i = 0
    while data[i:i+len(CTLFILE_DELIMITER)] != CTLFILE_DELIMITER:
        i += 1

    offset = i + len(CTLFILE_DELIMITER)
    if data[offset:offset+2] == VER1: # free version
        ver = '1'
    elif data[offset:offset+2] == VER2: # paid version - as for now the TLV values are identical from free version
        ver = '2'
    else:
        sys.stderr.write("%s : unknown version\n" % filename)
        sys.exit(1)

    global_iv = data[offset+2:offset+18]
    j = offset
    while data[j:j+len(CTLFILE_DELIMITER)] != CTLFILE_DELIMITER:
        j += 1

    ciphertext = data[offset+18:j-4]
    ciphertext = pkcs7(ciphertext)
    cipher = AES.new(STATIC_KEY, AES.MODE_CBC, global_iv)
    plaintext = cipher.decrypt(ciphertext)

    (users, names) = parse_users(plaintext)
    i = 0
    for x in users:
        hash_func = pba_chk = pba_iter = pba_salt = 0
        (hash_func, pba_chk, pba_iter, pba_salt) = parse(plaintext, x)
        #if int(hash_func,16) == 22: # sha256 256bits
        #    key_size = '256'
        #elif int(hash_func,16) == 21: # sha1 64bits
        #    key_size = '64'
        #else:
        #    sys.stderr.write("%s : unknown pkcs12_hashfunc\n" % filename)
        #    sys.exit(1)
        sys.stdout.write("%s:$zed$%s$%s$%s$%s$%s:::%s\n" % (names[i], ver, str(int(hash_func,16)), str(int(pba_iter,16)), pba_salt, pba_chk, os.path.basename(filename))) # If ID=3, then the pseudorandom bits being produced are to be used as an integrity key for MACing. (RFC 7292 Appendix B.3)
        i += 1

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [zed archives]\n" % sys.argv[0])

    for i in range(1, len(sys.argv)):
        parse_decode_global_properties(sys.argv[i])
