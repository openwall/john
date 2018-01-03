#!/usr/bin/env python

# The libreoffice2john.py utility processes OpenOffice / LibreOffice files into
# a format suitable for use with JtR.
#
# This utility was previously named odf2john.py.

# Output Format:
#
#   filename:$odf*cipher type*checksum type*iterations*key-size*checksum*...
#     ...iv length*iv*salt length*salt*unused*content.xml data
#
# This software is Copyright (c) 2012, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

from xml.etree.ElementTree import ElementTree
import zipfile
import sys
import base64
import binascii
import os


def process_file(filename):
    try:
        zf = zipfile.ZipFile(filename)
    except zipfile.BadZipfile:
        sys.stderr.write("%s is not an OpenOffice file!\n" % filename)
        return 2
    try:
        mf = zf.open("META-INF/manifest.xml")
    except KeyError:
        sys.stderr.write("%s is not an OpenOffice file!\n" % filename)
        return 3
    tree = ElementTree()
    tree.parse(mf)
    r = tree.getroot()

    # getiterator() is deprecated but 2.6 does not have iter()
    try:
        elements = list(r.iter())
    except:
        elements = list(r.getiterator())

    is_encrypted = False
    key_size = 16
    for i in range(0, len(elements)):
        element = elements[i]
        if element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}full-path") == "content.xml":
            for j in range(i + 1, i + 1 + 3):
                element = elements[j]
                # print element.items()
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}checksum")
                if data:
                    is_encrypted = True
                    checksum = data
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}checksum-type")
                if data:
                    checksum_type = data
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}initialisation-vector")
                if data:
                    iv = data
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}salt")
                if data:
                    salt = data
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}algorithm-name")
                if data:
                    algorithm_name = data
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}iteration-count")
                if data:
                    iteration_count = data
                data = element.get("{urn:oasis:names:tc:opendocument:xmlns:manifest:1.0}key-size")
                if data:
                    key_size = data

    if not is_encrypted:
        sys.stderr.write("%s is not an encrypted OpenOffice file!\n" % filename)
        return 4

    checksum = base64.b64decode(checksum)
    checksum = binascii.hexlify(checksum).decode("ascii")
    iv = binascii.hexlify(base64.b64decode(iv)).decode("ascii")
    salt = binascii.hexlify(base64.b64decode(salt)).decode("ascii")

    try:
        content = zf.open("content.xml").read(1024)
    except KeyError:
        sys.stderr.write("%s is not an encrypted OpenOffice file, " \
                "content.xml missing!\n" % filename)
        return 5

    if algorithm_name.find("Blowfish CFB") > -1:
        algorithm_type = 0
    elif algorithm_name.find("aes256-cbc") > -1:
        algorithm_type = 1
    else:
        sys.stderr.write("%s uses un-supported encryption!\n" % filename)
        return 6

    if checksum_type.upper().find("SHA1") > -1:
        checksum_type = 0
    elif checksum_type.upper().find("SHA256") > -1:
        checksum_type = 1
    else:
        sys.stderr.write("%s uses un-supported checksum algorithm!\n" % \
                filename)
        return 7

    meta_data_available = True
    gecos = ""
    try:
        meta = zf.open("meta.xml")
        meta_tree = ElementTree()
        meta_tree.parse(meta)
        meta_r = meta_tree.getroot()
        for office_meta in meta_r:
            for child in office_meta:
                if "subject" in child.tag:
                    gecos += child.text
                elif "keyword" in child.tag:
                    gecos += child.text
                elif "title" in child.tag:
                    gecos += child.text
                elif "description" in child.tag:
                    gecos += child.text
        gecos = gecos.replace("\n","").replace("\r","").replace(":","")
    except:
        meta_data_available = False

    if meta_data_available:
        sys.stdout.write("%s:$odf$*%s*%s*%s*%s*%s*%d*%s*%d*%s*%d*%s:::%s::%s\n" % \
                (os.path.basename(filename), algorithm_type, checksum_type,
                iteration_count, key_size, checksum, len(iv) / 2, iv,
                len(salt) / 2, salt, 0, binascii.hexlify(content).decode("ascii"),
                gecos, filename))
    else:
        sys.stdout.write("%s:$odf$*%s*%s*%s*%s*%s*%d*%s*%d*%s*%d*%s:::::%s\n" % \
                (os.path.basename(filename), algorithm_type, checksum_type,
                iteration_count, key_size, checksum, len(iv) / 2, iv,
                len(salt) / 2, salt, 0, binascii.hexlify(content).decode("ascii"),
                filename))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <OpenOffice / LibreOffice files>\n" % sys.argv[0])
        sys.exit(-1)

    for k in range(1, len(sys.argv)):
        process_file(sys.argv[k])
