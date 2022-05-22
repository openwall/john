#!/usr/bin/env python
# coding: utf-8

# This software is Copyright (c) 2015, Dhiru Kholia <dhiru.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# pylint: disable=invalid-name,line-too-long,missing-docstring,pointless-string-statement

# This script converts encrypted private key files in PKCS8 format to John input

import sys
from binascii import hexlify

try:
    from asn1crypto import pem
    from asn1crypto.keys import EncryptedPrivateKeyInfo
except ImportError:
    sys.stderr.write("asn1crypto python package is missing, please install it using 'pip install --user asn1crypto' command.\n")
    sys.exit(1)

"""

https://www.ietf.org/rfc/rfc5208.txt

http://lapo.it/asn1js/

https://github.com/bwall/pemcracker/blob/master/test.pem

$ openssl asn1parse -in test.pem
    0:d=0  hl=4 l= 710 cons: SEQUENCE
    4:d=1  hl=2 l=  64 cons: SEQUENCE
    6:d=2  hl=2 l=   9 prim: OBJECT            :PBES2
   17:d=2  hl=2 l=  51 cons: SEQUENCE
   19:d=3  hl=2 l=  27 cons: SEQUENCE
   21:d=4  hl=2 l=   9 prim: OBJECT            :PBKDF2
   32:d=4  hl=2 l=  14 cons: SEQUENCE
   34:d=5  hl=2 l=   8 prim: OCTET STRING      [HEX DUMP]:0C71E1C801194282
   44:d=5  hl=2 l=   2 prim: INTEGER           :0800
   48:d=3  hl=2 l=  20 cons: SEQUENCE
   50:d=4  hl=2 l=   8 prim: OBJECT            :des-ede3-cbc
   60:d=4  hl=2 l=   8 prim: OCTET STRING      [HEX DUMP]:87120F8C098437D0
   70:d=1  hl=4 l= 640 prim: OCTET STRING      [HEX DUMP]:C4BC6BC5447BED58...
"""

def unwrap_pkcs8(blob):
    if not pem.detect(blob):
        return False

    _, _, der_bytes = pem.unarmor(blob)
    return unwrap_pkcs8_data(der_bytes)


def unwrap_pkcs8_data(blob):
    try:
        data = EncryptedPrivateKeyInfo.load(blob).native

        if "encryption_algorithm" not in data:
            return False
        if "encrypted_data" not in data:
            return False
        if "algorithm" not in data["encryption_algorithm"]:
            return False
        if data["encryption_algorithm"]["algorithm"] != "pbes2":
            sys.stderr.write("[%s] encryption_algorithm <%s> is not supported currently!\n" %
                             (sys.argv[0], data["encryption_algorithm"]["algorithm"]))
            return True

        # encryption data
        encrypted_data = data["encrypted_data"]

        # KDF
        params = data["encryption_algorithm"]["parameters"]
        kdf = params["key_derivation_func"]
        if kdf["algorithm"] != "pbkdf2":
            sys.stderr.write("[%s] kdf algorithm <%s> is not supported currently!\n" %
                             (sys.argv[0], kdf["algorithm"]))
            return True
        kdf_params = kdf["parameters"]
        salt = kdf_params["salt"]
        iterations = kdf_params["iteration_count"]

        # Cipher
        cipher_params = params["encryption_scheme"]
        cipher = cipher_params["algorithm"]
        iv = cipher_params["parameters"]

        if cipher == "tripledes_3key":
            cid = 1
        elif cipher == "aes128_cbc":
            cid = 2
        elif cipher == "aes192_cbc":
            cid = 3
        elif cipher == "aes256_cbc":
            cid = 4
        else:
            sys.stderr.write("[%s] cipher <%s> is not supported currently!\n" % (sys.argv[0], cipher))
            return True

        salth = hexlify(salt).decode("ascii")
        encrypted_datah = hexlify(encrypted_data).decode("ascii")
        ivh = hexlify(iv).decode("ascii")

        pem_version = "$PEM$1"
        if kdf_params["prf"]["algorithm"] != "sha1":
            pem_version = f'$PEM$2${kdf["algorithm"]}${kdf_params["prf"]["algorithm"]}${cipher}'
        sys.stdout.write(pem_version+"$%d$%s$%s$%s$%d$%s\n" % (cid, salth, iterations, ivh, len(encrypted_data), encrypted_datah))
        return True
    except ValueError:
        return False


if __name__ == "__main__":

    if len(sys.argv) < 2:
        sys.stdout.write("Usage: %s <.pem files using PCKS #8 format>\n" %
                         sys.argv[0])

    for filename in sys.argv[1:]:
        blob = open(filename, "rb").read()
        if b'-----BEGIN ENCRYPTED PRIVATE KEY-----' in blob:
            ret = unwrap_pkcs8(blob)
            if not ret:
                sys.stderr.write("[%s] is this really a private key in PKCS #8 format?\n" % filename)
        elif b'-----BEGIN PRIVATE KEY-----' in blob:
            sys.stderr.write("[%s] is not encrypted!\n" % filename)
        elif b'PRIVATE KEY-----' in blob:
            sys.stderr.write("[%s] try using ssh2john.py on this file instead!\n" % filename)
        else:
            # try as DER instead of PEM
            ret = unwrap_pkcs8_data(blob)
            if not ret:
                sys.stderr.write("[%s] is this really a private key in PKCS #8 format?\n" % filename)
