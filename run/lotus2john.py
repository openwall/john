#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This software is Copyright (c) 2013 Dhiru Kholia <dhiru at openwall.com>, and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Based on "LotusIdHashExtractor" program written by Sébastien Kaczmarek.
#
# See http://blog.quarkslab.com/have-you-ever-played-with-domino.html for more
# details.
#
# Strong-crypto support (RC2-128 / AES "PBES2" ID files) added in 2026 by the
# Dhiru Kholia <dhiru at openwall.com>; parameters come from the "extra 18"
# record stored right after the owner's distinguished-name string:
#
#   keyType 2   (RC2-128): [WORD 0][DWORD 2][salt16]
#   keyType 4-7 (AES)    : [WORD 0][DWORD kt][DER PBES2 AlgorithmIdentifier]
#                          (PBKDF2-HMAC-SHA1 params + AES-CBC IV, RFC 8018)
#
# Output formats:
#   legacy file : "<file>:<blob hex>"                       (lotus85 format)
#   strong file : "<file>:$lotus-strong$*kt*salt*iters*keylen*iv*blob"

import sys
import os
import struct
from binascii import hexlify


OID_PBES2 = bytes.fromhex("2a864886f70d01050d")


def der_tlv(buf, off):
    tag = buf[off]
    ln = buf[off + 1]
    nof = off + 2
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[nof:nof + n], "big")
        nof += n
    return tag, buf[nof:nof + ln], nof + ln


def parse_pbes2(der):
    t, seq, _ = der_tlv(der, 0)
    if t != 0x30:
        raise ValueError("not a SEQUENCE")
    t, oid, off = der_tlv(seq, 0)
    t, params, _ = der_tlv(seq, off)
    t, kdf, es_off = der_tlv(params, 0)
    t, oid2, off2 = der_tlv(kdf, 0)
    t, kparams, _ = der_tlv(kdf, off2)
    salt = iters = keylen = None
    k = 0
    while k < len(kparams):
        t, v, k = der_tlv(kparams, k)
        if t == 0x04:
            salt = v
        elif t == 0x02:
            n = int.from_bytes(v, "big")
            if iters is None:
                iters = n
            elif keylen is None:
                keylen = n
    t, es, m = der_tlv(params, es_off)
    t, _coid, m2 = der_tlv(es, 0)
    t, iv, _ = der_tlv(es, m2)
    if salt is None or iters is None or keylen is None or len(iv) != 16:
        raise ValueError("incomplete PBES2 parameters")
    return salt, iters, keylen, iv


def find_strong_params(data):
    """Return (key_type, salt16, iters, keylen, iv) from the extra-18 record."""
    p = data.find(OID_PBES2)
    if p > 0:
        start = data.rfind(b"\x30", max(0, p - 8), p)
        if start >= 0:
            try:
                salt, iters, keylen, iv = parse_pbes2(data[start:])
                kt = struct.unpack_from("<I", data, start - 4)[0]
                return kt, salt, iters, keylen, iv
            except Exception:
                pass
    # RC2-128: [WORD 0][DWORD 2][salt16]; skip degenerate (zero/padding) hits
    best = None
    pat = struct.pack("<HI", 0, 2)
    i = data.find(pat, 0x118)
    while i >= 0:
        cand = data[i + 6:i + 22]
        if len(cand) == 16 and len(set(cand)) >= 8:
            best = cand
        i = data.find(pat, i + 1)
    if best is not None:
        return 2, best, 0, 16, bytes(8)
    return None


def process_file(filename):
    dataSize = os.path.getsize(filename)
    if dataSize < 0xD8:
        sys.stderr.write("%s: too small\n" % filename)
        return

    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    data = f.read()
    f.close()

    # read the size of the user id ciphered blob at 0xD6
    wUserBlobSize, = struct.unpack_from("<H", data, 0xD6)

    # Blob size is variable but there are some limits
    if wUserBlobSize < 0x10 or wUserBlobSize > 0x64 or wUserBlobSize + 0xD8 > dataSize:
        sys.stderr.write("%s: bad blob size\n" % filename)
        return

    blob = data[0xD8:0xD8 + wUserBlobSize]
    name = os.path.basename(filename)

    # flag word at 0x08: bit 0x0200 marks "strong crypto" files
    wFlags, = struct.unpack_from("<H", data, 0x08)
    if wFlags & 0x0200:
        params = find_strong_params(data)
        if params is None:
            sys.stderr.write("%s: strong ID file but no extra-18/PBES2 "
                             "parameters found\n" % filename)
            return
        kt, salt, iters, keylen, iv = params
        sys.stdout.write("%s:$lotus-strong$*%d*%s*%d*%d*%s*%s\n" % (
            name, kt,
            hexlify(salt).decode("ascii").upper(),
            iters, keylen,
            hexlify(iv).decode("ascii").upper(),
            hexlify(blob).decode("ascii").upper()))
    else:
        sys.stdout.write("%s:%s\n" % (
            name, hexlify(blob).decode("ascii").upper()))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [Lotus Notes ID file(s)]\n" % sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
