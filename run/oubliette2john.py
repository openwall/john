#!/usr/bin/env python3

# Contributed by DavideDG github.com/davidedg
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# There's ABSOLUTELY NO WARRANTY, express or implied.

import sys
import struct
import binascii

def process_file(filename):
    try:
        with open(filename, 'rb') as f:
            # Read and validate header
            header = f.read(12)
            if len(header) != 12:
                sys.stderr.write(f"{filename}: Invalid file size\n")
                return 1

            # Unpack header fields
            magic = header[0:5].decode('ascii')
            major_ver = header[5]
            minor_ver = header[6]
            algorithm = header[7]

            if magic != "OUBPF":
                sys.stderr.write(f"{filename}: Invalid magic bytes\n")
                return 2

            if algorithm not in [0, 1]:
                sys.stderr.write(f"{filename}: Unknown algorithm {algorithm}\n")
                return 3

            if major_ver not in [1,2,3]:
                sys.stderr.write(f"{filename}: Unknown database version {major_ver}\n")
                return 6

            # Read the PasswordEncryptedHash
            password_hash = f.read(32)
            if len(password_hash) != 32:
                sys.stderr.write(f"{filename}: Failed to read PasswordEncryptedHash\n")
                return 4

            # Format output for John the Ripper with different tags for Blowfish and IDEA
            hex_hash = binascii.hexlify(password_hash).decode('ascii')
            format_tag = "oubliette-blowfish" if algorithm == 0 else "oubliette-idea"
            print(f"${format_tag}${hex_hash}")
            return 0

    except IOError as e:
        sys.stderr.write(f"{filename}: {e}\n")
        return 99

def usage():
    sys.stderr.write("Usage: oubliette2john.py <oubliette files>\n")
    sys.exit(6)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        usage()

    for filename in sys.argv[1:]:
        process_file(filename)
