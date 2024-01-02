#!/usr/bin/env python3

# Helper script for cracking ENCSecurity DataVault.
#
# This software is Copyright (c) 2021-2022, Sylvain Pelissier <sylvain.pelissier at kudelskisecurity.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import sys
import binascii
import os
from pathlib import Path


def process(vault):
    salt = None
    tag = "encdv"
    if not os.path.isdir(vault):
        sys.stderr.write(f"{vault} : should be a folder.\n")
        sys.exit(1)

    file_list = os.listdir(vault)
    if "filesystem.dat" in file_list:
        # Sandisk, Sony vault or ENCSecurity user password.
        file_path = Path(vault) / "filesystem.dat"
        version = 1
    elif "index.dat" in file_list and "keychain.dat" in file_list:
        # ENCSecurity vault prior to 7.2.1.
        file_size = os.path.getsize(Path(vault) / "keychain.dat")
        if file_size < 132:
            sys.stderr.write("keychain.dat : Problem file too small.\n")
            return
        file_path = Path(vault) / "index.dat"
        version = 3
    else:
        sys.stderr.write(f"{vault} : Valid vault not found.\n")
        return

    # Check file size
    file_size = os.path.getsize(file_path)
    if file_size < 24:
        sys.stderr.write(f"{file_path} : Problem file too small.\n")
        return

    if "enckey.dat" in file_list:
        # Sandisk PrivateAccess or ENCSecurity vault 7.2.1 and later.
        file_size = os.path.getsize(Path(vault) / "enckey.dat")
        if file_size <= 8:
            sys.stderr.write("enckey.dat : Problem file too small.\n")
            return
        tag += "-pbkdf2"

    with open(file_path, "rb") as f:
        header = f.read(4)                  # Read header
        if header == b'\xd2\xc3\xb4\xa1':   # Test if we have a valid header
            f.seek(4,1)
            crypto = int.from_bytes(f.read(4),byteorder="little")
            iv = binascii.hexlify(f.read(8))
            header_enc = binascii.hexlify(f.read(8))
        else:
            sys.stderr.write(f"{file_list[0]} : Valid header not found.\n")
            return

        if len(header_enc) != 16:
            sys.stderr.write(f"{file_list[0]} : Problem reading encrypted header.\n")
            return

    sys.stdout.write(f"{vault}:${tag}${version}${crypto}${iv.decode()}${header_enc.decode()}")

    if tag == "encdv-pbkdf2":
        with open(Path(vault) / "enckey.dat", "rb") as f:
            f.seek(4)
            length = int.from_bytes(f.read(4),byteorder="big")
            if length >= file_size - 8:
                sys.stderr.write("enckey.dat : Problem reading length.\n")
                return
            salt = binascii.hexlify(f.read(length))
            iterations = int.from_bytes(f.read(4),byteorder="big")
            sys.stdout.write(f"${length}${salt.decode()}${iterations}")

    if version == 3:
        with open(Path(vault) / "keychain.dat", "rb") as f:
            f.seek(-132, 2)
            length = int.from_bytes(f.read(4),byteorder="big")
            if length != 128:
                sys.stderr.write(f"keychain.dat : Problem reading length.\n")
                return
            keychain = binascii.hexlify(f.read(128))
        sys.stdout.write(f"${keychain.decode()}\n")
    else:
        sys.stdout.write("\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write(f"Usage: {sys.argv[0]} <vault folder>\n")
        sys.stderr.write(f"\nExample: {sys.argv[0]} vault/\n")
        sys.exit(1)

    process(sys.argv[1])
