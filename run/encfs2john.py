#!/usr/bin/env python

# The encfs2john.py utility processes EncFS files into a format suitable for
# use with JtR.
#
# This software is Copyright (c) 2012, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

from xml.etree.ElementTree import ElementTree
import sys
import base64
import binascii
import os


def process_folder(folder):
    filename = os.path.join(folder, ".encfs6.xml")
    if not os.path.exists(filename):
        sys.stderr.write("%s doesn't have .encfs6.xml!\n" % folder)
        return 1
    mf = open(filename, "rb")
    tree = ElementTree()
    tree.parse(mf)
    r = tree.getroot()
    elements = list(r.iter())
    cipher = None
    keySize = None
    iterations = None
    salt = None
    saltLen = None
    dataLen = None
    data = None
    for element in elements:
        if element.tag == "keySize":
            keySize = element.text
            if not keySize.isdigit():
                sys.stderr.write("%s contains bad keySize\n" % filename)
                return
        if element.tag == "kdfIterations":
            iterations = element.text
            if not iterations.isdigit():
                sys.stderr.write("%s contains bad iterations\n" % filename)
                return
        if element.tag == "name" and not cipher:
            cipher = element.text
        if element.tag == "saltData":
            salt = element.text
        if element.tag == "saltLen":
            saltLen = element.text
        if element.tag == "encodedKeySize":
            dataLen = element.text
        if element.tag == "encodedKeyData":
            data = element.text

    if not cipher or not keySize or not iterations or not salt or \
       not saltLen or not dataLen or not data:
        sys.stderr.write("%s contains bad data, please report this " \
            "if target contains valid EncFS data" % filename)
        return

    if cipher.upper().find("AES") > -1:
        cipher = 0
    else:
        sys.stderr.write("%s cipher is not supported yet!\n" % cipher)
        return
    salt = binascii.hexlify(base64.b64decode(salt))
    data = binascii.hexlify(base64.b64decode(data))
    sys.stdout.write("%s:$encfs$%s*%s*%s*%s*%s*%s*%s\n" % \
            (folder, keySize, iterations, cipher, saltLen,
            salt.decode("ascii"),
            dataLen,
            data.decode("ascii")))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <EncFS folder>\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_folder(sys.argv[i])
