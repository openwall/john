#!/usr/bin/env python

# This scripts converts input LastPass data into a format suitable for use with
# JtR.
#
# Output Format:filename:$lp$email(salt)$iterations$hash
#
# The "*_key.itr" file simply contains the iteration count (e.g. 5000). This
# file is in ~/.lastpass directory for LastPass for Firefox under Linux.
#
# Read https://lastpass.com/support.php?cmd=showfaq&id=425 before using this
# script on data from a Windows version of LastPass. Be aware that on Windows,
# CryptProtectData is used to additionally encrypt the data, so this script
# won't work as it is. Additional pre-processing (decryption) of the data from
# the Windows version of LastPass is required.
#
# This only works for LastPass version 3.x for Firefox. The last supported
# version of LastPass is 3.3.4, released on March 17, 2017.
#
# Older versions of LastPass can be installed from the following URL,
# https://addons.mozilla.org/en-US/firefox/addon/lastpass-password-manager/versions/
#
# LastPass version 4.x use a very different mechanism and it not supported yet.
# It stores data in the following location,
# ~/.mozilla/firefox/<profile>/storage/permanent/index.../idb/<something>lp.sqlite
#
# https://lastpass.com/js/enc.php is interesting too.
#
# This software is Copyright (c) 2013, 2017, Dhiru Kholia <kholia at kth.se> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.


import os
import sys
import binascii
import base64


def process_lastpass_cli(folder):

    fverify = os.path.join(folder, "verify")
    fiterations = os.path.join(folder, "iterations")
    fusername = os.path.join(folder, "username")

    try:
        f = open(fusername, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s : %s\n" % (fusername, str(e)))
        return 2
    username = f.read().strip().lower()
    f.close()

    try:
        f = open(fiterations, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s : %s\n" % (fiterations, str(e)))
        return 3
    iterations = f.read().strip().lower()
    f.close()

    try:
        f = open(fverify, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s : %s\n" % (fverify, str(e)))
        return 4
    data = f.read()
    iv = data[32:][:16]
    ct = data[32+16:][:16]  # skip over checksum and iv fields

    sys.stdout.write("%s:$lpcli$%s$%s$%s$%s$%s\n" % (folder, 0, username,
                                                     iterations,
                                                     binascii.hexlify(iv),
                                                     binascii.hexlify(ct)))


def process_file(email, filename, ifilename):
    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s : %s\n" % (filename, str(e)))
        return 2

    f.readline()  # ignore first line
    data = f.readline()
    if not data:
        sys.stderr.write("%s : %s\n" % (filename,
                                        "Unable to parse data. Are you sure this is LastPass data?"))
    f.close()
    try:
        f = open(ifilename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s : %s\n" % (ifilename, str(e)))
        return 2
    iterations = f.readline().strip()

    sys.stdout.write("%s:$lp$%s$%s$%s\n" % (filename, email,
                                            iterations,
                                            binascii.hexlify(base64.decodestring(data))))


def usage():
    sys.stderr.write("Usage: %s <email address> "
                     "<LastPass *_lpall.slps file> "
                     "<LastPass *_key.itr file>\n" % sys.argv[0])
    sys.stderr.write("\nOR\n\n")
    sys.stderr.write("Usage: %s <path to .local/share/lpass directory (for lastpass-cli)>\n" % sys.argv[0])


if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()
        sys.exit(-1)

    if len(sys.argv) == 4:  # LastPass v3.x for Firefox + Linux mode
        process_file(sys.argv[1], sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 2:
        process_lastpass_cli(sys.argv[1])
    else:
        usage()
        sys.exit(-1)
