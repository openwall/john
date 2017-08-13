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


import sys
import binascii
import base64


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


if __name__ == "__main__":
    if len(sys.argv) < 4:
        sys.stderr.write("Usage: %s <email address> "
                         "<LastPass *_lpall.slps file> "
                         "<LastPass *_key.itr file>\n" % sys.argv[0])
        sys.exit(-1)

    process_file(sys.argv[1], sys.argv[2], sys.argv[3])
