#!/usr/bin/python3

# This software is Copyright (c) 2018, Dhiru Kholia <kholia at kth.se> and it
# is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Tested with ansible-vault 2.4.3.0 running on Fedora 27.


import sys
import os
from binascii import unhexlify

PY3 = sys.version_info[0] == 3

if not PY3:
    reload(sys)
    sys.setdefaultencoding('utf8')


HEADER = b'$ANSIBLE_VAULT'


def process_file(filename):
    """
    Parser for Ansible Vault .yml files
    """
    bfilename = os.path.basename(filename)

    data = open(filename, "rb").read()
    if not data.startswith(HEADER):
        sys.stderr.write("File doesn't start with %s\n" % HEADER)
        return

    tmpdata = data.splitlines()
    tmpheader = tmpdata[0].strip().split(b';')

    _ = tmpheader[1].strip()  # version
    cipher_name = tmpheader[2].strip()
    ciphertext = b''.join(tmpdata[1:])
    salt, checksum, ct = unhexlify(ciphertext).split(b"\n")
    if PY3:
        salt = salt.decode("ascii")
        checksum = checksum.decode("ascii")
        ct = ct .decode("ascii")
        cipher_name = cipher_name .decode("ascii")
    version = 0
    if cipher_name != "AES256":
        sys.stderr.write("%s: unsupported ciper '%s' found!\n" % (bfilename, cipher_name))
        return
    cipher = 0
    sys.stdout.write("%s:$ansible$%d*%d*%s*%s*%s\n" %
                     (bfilename, version, cipher, salt, ct, checksum))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [Ansible Vault .yml file(s)]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
