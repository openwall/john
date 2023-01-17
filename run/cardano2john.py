#!/usr/bin/env python3

#
# Export Cardano's legacy secret.key to John The Ripper format
#
# This software is Copyright (c) 2022, Pal Dorogi (ilap) <pal dot dorogi at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Requirements: pip3 installed
#
# Installation:
# $ pip3 install cbor2
#

import sys
import os

import binascii
from cbor2 import load


def esk_to_john(user_key):
    return "$cardano$1$" + binascii.hexlify(user_key[0]).decode("ascii")


def do_exit(return_code, message):
    sys.stderr.write(message + os.linesep)
    sys.exit(return_code)


def export_to_john(filename):

    try:
        with open(filename, "rb") as fp:
            # cbor[0]: _usVssMaybe, not interesting
            # cbor[1]: _usPrimKey,  not interesting
            # cbor[2]: _usKeys, interested only the esk part, atm, [[esk, passwordHash],...,]
            # cbor[3]: _usWalletSet, interested if there is any, but only in its [0]
            # i.e.: _wusRootKey which is an esk
            cbor = load(fp)

            # Go through all user's keys a.k.a _usKeys and the _usWalletSet.
            keys = cbor[2] + cbor[3]
            keys_len = len(keys)

            if keys_len == 0:
                sys.stderr.write(
                    "No keys found in the keystore file: %s%s" % (filename, os.linesep)
                )
            else:
                for line in map(esk_to_john, keys):
                    print(line)
    except:
        sys.stderr.write("Wrong secret key file or path: %s%s" % (filename, os.linesep))


if __name__ == "__main__":

    if len(sys.argv) < 2:
        sys.stderr.write(
            """Usage: %s secret_key_file1 [secret_key_file2 ...] > output_file
    secret_key_file: a Cardano's secret key file e.g.: "secret.key"%s"""
            % (os.path.basename(sys.argv[0]), os.linesep)
        )
        sys.exit(1)

    for filename in sys.argv[1:]:
        export_to_john(filename)
