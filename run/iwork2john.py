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


def process_old_file(filename):
    """
    Parser for Apple iWork '09 files

    This file format is fun to look at in a hex editor, see last 256 bytes!

    This was reverse-engineered on 20th of November, 2015.
    """
    data = open(filename).read()
    # size = len(data)

    if data[0:4] != b"\x50\x4B\x03\x04":  # ZIP signature, http://result42.com/projects/ZipFileLayout
        assert 0

    # find end of central directory
    ecdl = data.rfind("\x50\x4b\x05\x06")  # 0x6064b50 => End of central directory
    if ecdl == -1:
        assert 0

    # find central directory
    cdl_offset = ecdl + 16
    cdl = struct.unpack("< I", data[cdl_offset:][0:4])[0]
    if data[cdl:][0:4] != b"\x50\x4B\x01\x02":  # 0x2014b50 => Central Directory
        assert 0

    entry_size = struct.unpack("< I", data[cdl + 30:][0:4])
    if entry_size < 108:
        assert 0

    idx = data_offset = cdl + struct.unpack("< H", data[cdl + 28:][0:2])[0]
    s1 = data[idx+54:][0:4]  # version, and format (2 bytes each)?
    if s1 != "\x01\x00\x01\x00":
        assert 0
    version = fmt = 1
    iterations = struct.unpack("< I", data[idx+58:][0:4])[0]
    salt = "someSalt"  # isn't this awesome?
    verifier = data[data_offset+62:][0:80]  # 80 bytes
    iv = verifier[0:16]
    datablob = verifier[16:]

    # XXX also extract the passsword hint which is around this area, and is
    # prefixed by "iwph" string (for GECOS).
    sys.stdout.write(
            "%s:$iwork$2$%d$%d$%d$%s$%s$%s::::%s\n" %
            (os.path.basename(filename), version, fmt, iterations,
             hexlify(salt)[0:len(salt) * 2].decode("ascii"),
             hexlify(iv)[0:len(iv) * 2].decode("ascii"),
             hexlify(datablob)[0:len(datablob) * 2].decode("ascii"), filename))


def process_file(filename):
    """
    Parser for Apple iWork 2013 / 2014 files
    """

    zf = zipfile.ZipFile(filename)
    password_hint = None
    password_verifier_data = None

    # look for ".iwph" (password hint), and ".iwpv2" (password verifier) files
    for fn in zf.namelist():
        if fn.endswith(".iwph"):

            # info = zf.getinfo(fn)
            password_hint = zf.read(fn).decode('utf-8')
            sys.stderr.write("%s: Password hint is '%s'\n" %
                             (os.path.basename(filename), password_hint))

        if fn.endswith(".iwpv2"):
            password_verifier_data = zf.read(fn)

    # is this a iWork '09 file?
    if not password_verifier_data:
        process_old_file(filename)
        return

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

        hdatablob = hexlify(datablob)[0:len(datablob) * 2].decode("ascii")
        sys.stdout.write("%s:$iwork$1$%d$%d$%d$%s$%s$%s::::%s %s\n" %
                         (os.path.basename(filename), version, fmt, iterations,
                          hexlify(salt)[0:len(salt) * 2].decode("ascii"),
                          hexlify(iv)[0:len(iv) * 2].decode("ascii"),
                          hdatablob, password_hint or "",
                          os.path.basename(filename)))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.key files]\n" % sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
