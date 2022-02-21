#!/usr/bin/env python

# This utility helps in cracking files encrypted using "openssl enc" command.
# It does not help in cracking encrypted private key files. Use pem2john.py instead.
#
# This software is Copyright (c) 2013, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.


import sys
import os.path
import base64
import optparse
from binascii import hexlify

# openssl aes-256-cbc -in secret.txt -out secret.txt.enc
# openssl aes-256-cbc -a -in secret.txt -out secret.txt.enc
# openssl enc -aes-256-cbc -in secret.txt -out secret.txt.enc


def process(filename, plaintext=None, cipher=0, md=0, minascii=0):

    with open(filename, "rb") as f:
        data = f.read()

        if b"PRIVATE KEY-----" in data:
            sys.stderr.write("%s looks like a private key but this tool processes data encrypted using OpenSSL's enc command! Try pem2john.py instead!\n" % filename)
            return

        if not data.startswith(b"Salted__"):
            try:
                data = base64.b64decode(data)
            except:
                sys.stderr.write("%s doesn't seem to be encrypted using OpenSSL's enc command!\n" % filename)
                return

        if not data.startswith(b"Salted__"):
            sys.stderr.write("%s doesn't seem to be encrypted using OpenSSL's enc command!\n" % filename)
            return

        if len(data) < 32:
            sys.stderr.write("%s doesn't seem to be encrypted using OpenSSL's enc command!\n" % filename)
            return

        rlen = len(data) - 16
        salt = data[8:16]
        salt = hexlify(salt).decode("ascii")

        if rlen <= 16:
            last_chunk = data[-16:]
            if plaintext:
                s = "1$%s" % plaintext
            elif minascii:
                s = "2$%d" % minascii
            else:
                s = "0"
            last_chunk = hexlify(last_chunk).decode("ascii")
            sys.stdout.write("%s:$openssl$%s$%s$8$%s$%s$1$%s\n" %
                             (filename, cipher, md, salt, last_chunk, s))
        else:
            last_chunk = data[-32:]
            # try to decode maximum of 16
            rdata = data[16:16*17]
            if plaintext:
                s = "1$%s" % plaintext
            elif minascii:
                s = "2$%d" % minascii
            else:
                s = "0"
            last_chunk = hexlify(last_chunk).decode("ascii")
            rdata = hexlify(rdata).decode("ascii")
            sys.stdout.write("%s:$openssl$%s$%s$8$%s$%s$0$%s$%s$%s\n" %
                             (os.path.basename(filename), cipher, md, salt,
                              last_chunk,
                              len(rdata) // 2, rdata, s))


if __name__ == '__main__':

    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [-c cipher] [-m md] [-p plaintext] [-a ascii_pct] <OpenSSL encrypted files>\n" % sys.argv[0])
        sys.stderr.write("\ncipher: 0 => aes-256-cbc, 1 => aes-128-cbc\n")
        sys.stderr.write("md: 0 => md5, 1 => sha1, 2 => sha256\n")
        sys.stderr.write("ascii_pct: minimum ascii percent (1-100) on decrypted output (ignored if plaintext present)\n")
        sys.stderr.write("\nOpenSSL 1.1.0e uses aes-256-cbc with sha256\n")  # See "apps/enc.c" in OpenSSL
        sys.exit(1)

    parser = optparse.OptionParser()
    parser.add_option('-p', action="store", dest="plaintext")
    parser.add_option('-a', action="store", dest="minascii", type="int", default=0)
    parser.add_option('-c', action="store", dest="cipher", default=0)
    parser.add_option('-m', action="store", dest="md", default=0)
    options, remainder = parser.parse_args()

    for filename in remainder:
        process(filename, options.plaintext, options.cipher, options.md, options.minascii)
