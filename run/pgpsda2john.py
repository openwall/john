#!/usr/bin/env python

# This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Written in August of 2017 based on PGPDesktop10.0.1_Source.zip file.
#
# Tested with Symantec Encryption Desktop (SED) 10.4.1 MP1 running on Windows 7
# SP1. Also tested with PGP 8.0 running on Windows XP SP3.

import os
import sys
import struct
from binascii import hexlify

PY3 = sys.version_info[0] == 3

"""
Random notes on PGP SDA feature.

The following files are informative,

clients2/shared/pgpSDA.h
clients2/sc/sda/sdapass.c
clients2/shared/pgpSDAdecode.c
clients2/shared/win32/DecodeStub.c

typedef union PassphraseSalt
{
    PGPUInt8    saltBytes[ 8 ];
    PGPUInt32   saltLongs[ 8 / sizeof( PGPUInt32 ) ];
} PassphraseSalt;

typedef struct
{
    char szPGPSDA[6];
    PGPUInt32 offset;     // This will always be small (stub)
    PGPUInt64 CompLength; // This may be huge
    PGPUInt64 NumFiles;   // What the heck, why not

    PassphraseSalt Salt;
    PGPUInt16 hashReps;
    char CheckBytes[8];
}
#ifdef PGP_UNIX
__attribute__((packed))
#endif /* PGP_UNIX */
SDAHEADER;

"""

SDAHEADER_fmt = "< 6s I Q Q 8s H 8s"
SDAHEADER_size = struct.calcsize(SDAHEADER_fmt)


def process_file(filename):
    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    data = f.read()  # Can we make this smarter?

    for i in range(0, len(data) - SDAHEADER_size + 1):  # SDAHEADER structure is at the very end of the file!
        idata = data[i:SDAHEADER_size + i]

        fields = struct.unpack(SDAHEADER_fmt, idata)

        magic, offset, CompLength, NumFiles, salt, hashReps, CheckBytes = fields
        if magic == b"PGPSDA" and offset < len(data):
            # print(fields)
            salt = hexlify(salt)
            if PY3:
                salt = str(salt, 'ascii')
            CheckBytes = hexlify(CheckBytes)
            if PY3:
                CheckBytes = str(CheckBytes, 'ascii')
            print("The following hash is for an SDA archive with compressed length = %d, number of files = %d, iterations = %d. Make sure that these values sound correct!\n" %
                    (CompLength, NumFiles, hashReps))
            print("%s:$pgpsda$0*%s*%s*%s" % (os.path.basename(filename), hashReps, salt, CheckBytes))

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [PGP self-decrypting archive (SDA) file(s)]\n" % sys.argv[0])

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
