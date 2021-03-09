#!/usr/bin/python2

"""Utility to extract Bitwarden "hashes" from Google Chrome / Firefox / Android local data"""

# Huge thanks goes to Joshua Stein for documenting the various cryptographic
# constructions used in Bitwarden.
#
# See https://github.com/jcs/bitwarden-ruby for the details.
#
# https://help.bitwarden.com/article/where-is-data-stored-computer/
#
# On Linux with Firefox, "storage.js" can be found at the following location,
# ~/.mozilla/firefox/your_profile/browser-extension-data/\{446900e4-71c2-419f-a6a7-df9c091e268b\}/
#
# Tested with Firefox 57.x running "bitwarden - Free Password Manager 1.23.0" extension.
#
# On Android with bitwarden 1.14.1, the "hash" can be extracted from the following location,
# /data/data/com.x8bit.bitwarden/shared_prefs/com.x8bit.bitwarden_preferences.xml
#
# Use https://help.bitwarden.com/crypto.html to generate sample hashes.
#
# Written by Dhiru Kholia <dhiru at openwall.com> in January 2018 for JtR
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

try:
    import json
    assert json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        sys.stderr.write("Please install json module which is currently not installed.\n")
        sys.exit(-1)

try:
    import plyvel
except ImportError:
    sys.stderr.write("[WARNING] Please install the plyvel module for full functionality!\n")
    sys.exit(-1)


def process_xml_file(filename):
    tree = ET.parse(filename)
    root = tree.getroot()
    email = None
    enc_key = None

    for item in root:
        if item.tag == 'string':
            name = item.attrib['name']
            if name == "encKey":
                enc_key = item.text
            if name == "email":
                email = item.text
    return email, enc_key


def process_leveldb(path):
    db = plyvel.DB(path, create_if_missing=False)
    email = db.get(b'userEmail')
    email = email.decode("utf-8")
    email = email.strip('"').rstrip('"')  # always safe?
    enc_key = db.get(b'encKey')
    enc_key = enc_key.decode("ascii")

    return email, enc_key


def process_file(filename):
    if "nngceckbap" in filename or os.path.isdir(filename):
        try:
            email, enc_key = process_leveldb(filename)
            if not email or not enc_key:
                sys.stderr.write("[ERROR] %s could not be parsed properly!\n" % filename)
                return
        except:
            traceback.print_exc()
            return
    else:
        with open(filename, "rb") as f:
            data = f.read()
        if filename.endswith(".xml") or data.startswith(b"<?xml"):
            try:
                email, enc_key = process_xml_file(filename)
                if not email or not enc_key:
                    sys.stderr.write("[ERROR] %s could not be parsed properly!\n" % filename)
                    return
            except:
                traceback.print_exc()
                return
        else:
            try:
                data = json.loads(data)
                email = data["userEmail"]
                enc_key = data["encKey"]
            except (ValueError, KeyError):
                traceback.print_exc()
                return

    iterations = 5000  # seems to be fixed in the design

    email = email.lower()
    iv_mix, blob = enc_key.split("|")
    iv = iv_mix[2:]  # skip over "0."
    iv = binascii.hexlify(base64.b64decode(iv)).decode("ascii")
    blob = binascii.hexlify(base64.b64decode(blob)).decode("ascii")
    sys.stdout.write("%s:$bitwarden$0*%s*%s*%s*%s\n" %
                     (os.path.basename(filename), iterations, email, iv, blob))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <Bitwarden storage.js / com.x8bit.bitwarden_preferences.xml / Google Chrome's 'nngceckbap...' path>\n" %
                         sys.argv[0])
        sys.exit(-1)

    for j in range(1, len(sys.argv)):
        process_file(sys.argv[j])
