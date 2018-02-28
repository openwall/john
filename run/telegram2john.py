#!/usr/bin/env python2

"""Utility to extract "hashes" from Telegram Android app's userconfing.xml file(s)"""

# Tested with Telegram for Android v4.8.4 in February, 2018.
#
# Special thanks goes to https://github.com/Banaanhangwagen for documenting
# this hashing scheme.
#
# See "UserConfig.java" from https://github.com/DrKLO/Telegram/ for details on
# the hashing scheme.
#
# Written by Dhiru Kholia <dhiru at openwall.com> in February, 2018 for JtR
# project.
#
# This software is Copyright (c) 2018, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# pylint: disable=invalid-name,line-too-long


import os
import sys
import base64
import binascii
import traceback
import xml.etree.ElementTree as ET

PY3 = sys.version_info[0] == 3

if not PY3:
    reload(sys)
    sys.setdefaultencoding('utf8')


def process_xml_file(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    h = None
    salt = None

    for item in root:
        # the "user" key doesn't seem very useful without cleaning it up
        if item.tag == 'string':
            name = item.attrib['name']
            if name == "passcodeHash1":
                h = item.text
            if name == "passcodeSalt":
                salt = item.text
    if not h or not salt:
        return

    h = h.lower()
    salt = binascii.hexlify(base64.b64decode(salt))
    if PY3:
        salt = salt.decode("ascii")

    sys.stdout.write("$dynamic_1528$%s$HEX$%s\n" % (h, salt))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <userconfing.xml file(s)>\n" %
                         sys.argv[0])
        sys.exit(-1)

    for j in range(1, len(sys.argv)):
        process_xml_file(sys.argv[j])
