#!/usr/bin/env python

"""filezilla2john.py extracts password hashes from "FileZilla Server.xml" files."""

# This software is Copyright (c) 2016, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import sys
import binascii
from xml.etree.ElementTree import ElementTree


def process_file(filename):
    f = open(filename, "rb")

    tree = ElementTree()
    tree.parse(f)
    r = tree.getroot()

    for user in tree.findall(".//User"):
        username = user.attrib.get("Name")
        hsh = ""
        salt = None
        for option in user.findall("Option"):
            if option.get("Name") == "Pass":
                hsh = option.text
            if option.get("Name") == "Salt":
                salt = option.text

        if not hsh:
            continue

        if hsh:
            hsh = hsh.lower()

        if len(hsh) == 32 and not salt:  # Raw-MD5 hashes
            sys.stdout.write("%s:$dynamic_0$%s\n" % (username, hsh))
        elif len(hsh) == 128 and salt:  # sha512($p.$s)
            salt = binascii.hexlify(salt.encode("ascii")).decode("ascii")  # salt can include ":" characters
            sys.stdout.write("%s:$dynamic_82$%s$HEX$%s\n" % (username, hsh, salt))
        else:
            sys.stderr.write("Hash of length (%s) is not supported. Open a GitHub issue for reporting this!\n" % len(hsh))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <FileZilla Server.xml file(s)>\n" % sys.argv[0])
        sys.exit(1)

    for k in range(1, len(sys.argv)):
        process_file(sys.argv[k])
