#!/usr/bin/env python

# TrueCrypt volume importion to a format usable by John The Ripper
#
# Written by Alain Espinosa <alainesp at gmail.com> in 2012.  No copyright
# is claimed, and the software is hereby placed in the public domain.
# In case this attempt to disclaim copyright and place the software in the
# public domain is deemed null and void, then the software is
# Copyright (c) 2012 Alain Espinosa and it is hereby released to the
# general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# There's ABSOLUTELY NO WARRANTY, express or implied.
#
# (This is a heavily cut-down "BSD license".)
#
# Ported to Python by Dhiru Kholia, in June of 2015

import sys
from os.path import basename
import binascii
import optparse


def process_file(filename, keyfiles, options):
    try:
        f = open(filename, "rb")
    except Exception as e:
        sys.stderr.write("%s : No truecrypt volume found? %s\n" % str(e))
        return

    header = f.read(512)  # encrypted header of the volume
    if len(header) != 512:
        f.close()
        sys.stderr.write("%s : Truecrypt volume file to short: Need at least 512 bytes\n", filename)
        return

    if options.boot_mode:
        tags = ["truecrypt_RIPEMD_160_BOOT"]
    else:
        tags = ["truecrypt_RIPEMD_160", "truecrypt_SHA_512", "truecrypt_WHIRLPOOL"]

    for tag in tags:
        sys.stdout.write("%s:%s$" % (basename(filename), tag))
        sys.stdout.write(binascii.hexlify(header))
        if keyfiles:
            nkeyfiles = len(keyfiles)
            sys.stdout.write("$%d" % (nkeyfiles))
            for keyfile in keyfiles:
                sys.stdout.write("$%s" % keyfile)
        sys.stdout.write(":normal::::%s\n" % filename)

    # try hidden volume if any
    f.seek(65536, 0)
    if f.tell() != 65536:
        f.close()
        return
    header = f.read(512)
    if len(header) != 512:
        f.close()
        return

    for tag in ["truecrypt_RIPEMD_160", "truecrypt_SHA_512", "truecrypt_WHIRLPOOL"]:
        sys.stdout.write("%s:%s$" % (basename(filename), tag))
        sys.stdout.write(binascii.hexlify(header))
        if keyfiles:
            nkeyfiles = len(keyfiles)
            sys.stdout.write("$%d" % (nkeyfiles))
            for keyfile in keyfiles:
                sys.stdout.write("$%s" % keyfile)
        sys.stdout.write(":hidden::::%s\n" % filename)

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Utility to import TrueCrypt volume to a format crackeable by John The Ripper\n")
        sys.stderr.write("\nUsage: %s [-b] volume_filename [keyfiles(s)]> output_file\n" % sys.argv[0])
        sys.stderr.write("\nEnable -b only when attacking TrueCrypt's boot mode.\n")
        sys.stderr.write("\nError: No truecrypt volume file specified.\n")
        sys.exit(-1)

    parser = optparse.OptionParser()
    parser.add_option('-b', action="store_true", default=False, dest="boot_mode")
    options, remainder = parser.parse_args()

    keyfiles = []
    if len(remainder) > 2:
        keyfiles = remainder[1:]

    process_file(remainder[0], keyfiles, options)
