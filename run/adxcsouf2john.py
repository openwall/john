#!/usr/bin/python3

# This utility extracts ADXCRYPT password hashes from IBM/Toshiba 4690 OS
# ADXCSOUF.DAT (more well-known, hence the name of the utility) and SHA-1
# hashes from ADXEPW0F.DAT files.
#
# This software is Copyright (c) 2018, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Notes,
#
# 1. IBM/Toshiba 4690 v6.3 OS runs fine under VMware ESXi 6.7 (Select "Other
#    (64-bit)" as the Guest OS type), which itself is running under KVM using
#    nested virtualization.
#
# 2. Boot Linux on the 4690 system and use the following steps to extract the
#    ADXCSOUF.DAT and ADXEPW0F.DAT files. The ADXEPW0F.DAT file has the new
#    "Enhanced Security" SHA-1 hashes.
#
#    $ mkdir mnt/outer
#
#    $ mkdir mnt/inner
#
#    $ sudo mount /dev/sda3 mnt/outer  # change according to your setup
#
#    $ sudo mount -o loop mnt/outer/disk_c mnt/inner
#
#    # sudo cp mnt/inner/ADX_IDT1/ADXCSOUF.DAT ~
#    $ sudo cp mnt/inner/ADX_SDT1/ADXEPW0F.DAT ~

import re
import os
import sys
import math
import binascii

PY3 = sys.version_info[0] == 3

# Borrowed from https://stackoverflow.com/ (How do I compute the approximate entropy of a bit string?)
def entropy(string):
        "Calculates the Shannon entropy of a string"

        # get probability of chars in string
        prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]

        # calculate the entropy
        entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])

        return entropy


def process_other_file(filename):
    """
    Parser for ADXEPW0F.DATA files. Based on some heavy guessing.

    I am assuming that username appears on a line whose position is aligned to
    16 bytes. I am probably biased by looking at ADXEPW0F.DATA using xxd.
    """

    data = open(filename, "rb").read()

    for pos in range(0, len(data), 16):
        line = data[pos:pos+16]
        # find "lines" containing usernames
        if line.startswith(b"\x20\x20\x20\x20\x20\x20\x20") and line[-1] != 0x20 and line[-1] != 0x00:
            idx = line.rfind(b'\x20') + 1
            username = line[idx:]
            h = data[pos+16:pos+16+20]
            # check entropy of the hash
            if entropy(h) < 2.5:
                continue
            h = binascii.hexlify(h)
            if PY3:
                h = h.decode("ascii")
                username = username.decode("ascii")
            print("%s:{SHA}%s" % (username, h))


def process_file(filename):
    """
    Parser for ADXCSOUF.DAT files. Based on some trial-and-error.
    """
    data = open(filename, "rb").read()

    # lousy heuristics to detect ADXEPW0F.DAT file
    count = 0
    length = 2048 if len(data) > 2048 else len(data)
    for i in range(0, length):
        if data[i] == 0x20 or data[i] == 0x00:
            count = count + 1
    if count > 128:
        return process_other_file(filename)

    # find (username hash) pairs
    matches = re.findall(b'([a-zA-Z0-9_-]{3,9})\ (\d{8})', data)

    for items in matches:
        try:
            username = items[0]
            h = items[1]
        except:
            pass

        if PY3:
            username = username.decode("ascii")
            h = h.decode("ascii")

        sys.stdout.write("%s:$adxcrypt$%s\n" % (username, h))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <ADXCSOUF.DAT / ADXEPW0F.DAT file(s)>\n" % sys.argv[0])
        sys.exit(-1)

    # print a pro-tip
    sys.stderr.write("Tip: Maxmium password length is 8 on IBM/Toshiba 4690 systems\n\n")

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
