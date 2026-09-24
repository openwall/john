#!/usr/bin/env python3

"""pysap - Python library for crafting SAP's network protocols packets"""

# Copyright (C) 2012-2018 by Martin Gallo, Core Security
# Copyright (C) 2018 by Dhiru Kholia, Openwall
#
# The library was designed and developed by Martin Gallo from Core Security's
# CoreLabs team.
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.

# Standard imports
from argparse import ArgumentParser
from binascii import hexlify
from os import path
from sys import stderr, stdout

# Custom imports
try:
    import pysap
    from pysap.SAPPSE import (SAPPSEFile, PKCS12_ALGORITHM_PBE1_SHA_3DES_CBC)
except ImportError:
    stderr.write("pysap is missing, run 'pip install --user pysap' to install it!\n")
    raise SystemExit(1)


def parse_options(argv=None):
    """Parse command line options."""
    description = ("This script can be used to parse PSE files and extract "
                   "encrypted material and data in a format that John the "
                   "Ripper or other cracking tools can use to look for the "
                   "decryption PIN.")

    parser = ArgumentParser(
        usage="%(prog)s <input_file>", description=description,
        epilog=pysap.epilog)
    parser.add_argument(
        "-o", "--output", help="Filename to write the output to [stdout]")
    parser.add_argument(
        "input_files", metavar="input_file", nargs="+",
        help="PSE file to parse")
    return parser.parse_args(argv)


def process_file(filename, output_file=stdout, error_file=stderr):
    """Process a PSE file and write John the Ripper material if supported."""
    try:
        with open(filename, "rb") as fp:
            data = fp.read()

        pse_file = SAPPSEFile(data)

        if not pse_file.is_encrypted():
            raise Exception("PSE file is already unencrypted")

        if pse_file.enc_cont.algorithm_identifier.alg_id == \
                PKCS12_ALGORITHM_PBE1_SHA_3DES_CBC:
            pbe_algo = 1
            salt = hexlify(
                pse_file.enc_cont.algorithm_identifier.parameters.salt.val
            ).decode("ascii")
            salt_size = len(
                pse_file.enc_cont.algorithm_identifier.parameters.salt.val)
            iterations = pse_file.enc_cont.algorithm_identifier.parameters.iterations.val
            iv = ""
            iv_size = len(iv)
        else:
            raise Exception("Unsupported encryption algorithm")

        encrypted_pin = hexlify(pse_file.enc_cont.encrypted_pin.val).decode("ascii")
        encrypted_pin_length = len(pse_file.enc_cont.encrypted_pin.val)
    except Exception as e:
        error_file.write("{}: {}\n".format(filename, e))
        return False

    output_file.write(
        "{}:$pse${}${}${}${}${}${}${}${}:::::\n".format(
            path.basename(filename), pbe_algo, iterations, salt_size, salt,
            iv_size, iv, encrypted_pin_length, encrypted_pin))
    return True


def main(argv=None):
    options = parse_options(argv)

    if options.output:
        output_file = open(options.output, "w")
    else:
        output_file = stdout

    try:
        for input_file in options.input_files:
            process_file(input_file, output_file)
    finally:
        if options.output:
            output_file.close()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
