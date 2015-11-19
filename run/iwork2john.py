#!/usr/bin/env python

# This software is Copyright (c) 2015, Dhiru Kholia <kholia at kth.se> and
# Maxime Hulliger <hulliger at kth.se> and it is hereby released to the general
# public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# All credit goes to Sean Patrick O'Brien for reversing the iWork '13 file
# format.
#
# https://github.com/obriensp/iWorkFileFormat/
#
# https://en.wikipedia.org/wiki/IWork#Versions

import sys
import os
import struct
from binascii import hexlify
import zipfile

# header structs are taken from the iWorkFileFormat project
# https://github.com/obriensp/iWorkFileFormat (IWPasswordVerifier.m)
#
# typedef struct {
#        uint16_t version;
#        uint16_t format;
#        uint32_t iterations;
#        uint8_t salt[16];
#        uint8_t iv[16];
#        uint8_t data[64];
# } __attribute__((packed)) IWPasswordVerifierData;

password_verifier_fmt = '< H H I 16s 16s 64s'  # data is in little-endian order
password_verifier_size = struct.calcsize(password_verifier_fmt)


def process_file(filename):

    zf = zipfile.ZipFile(filename)
    password_hint = None
    password_verifier_data = None

    # look for ".iwph" (password hint), and ".iwpv2" (password verifier) files
    for fn in zf.namelist():
        if fn.endswith(".iwph"):

            # info = zf.getinfo(fn)
            password_hint = zf.read(fn)
            sys.stderr.write("Password hint is '%s'\n" % password_hint)  # XXX GECOS!

        if fn.endswith(".iwpv2"):
            password_verifier_data = zf.read(fn)

    if password_verifier_data:
        if len(password_verifier_data) != password_verifier_size:
            assert False

        password_verifier = struct.unpack(password_verifier_fmt,
                                          password_verifier_data)
        version, fmt, iterations, salt, iv, datablob = password_verifier

        if version != 2 or fmt != 1:
            sys.stderr.write(
                "[%s] unsupported version (%d) or format (%d)\n" % (version, fmt))
            return

        sys.stdout.write(
            "%s:$iwork$1$%d$%d$%d$%s$%s$%s::::%s\n" %
            (os.path.basename(filename), version, fmt, iterations,
             hexlify(salt)[0:len(salt) * 2].decode("ascii"),
             hexlify(iv)[0:len(iv) * 2].decode("ascii"),
             hexlify(datablob)[0:len(datablob) * 2].decode("ascii"), filename))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.key files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
