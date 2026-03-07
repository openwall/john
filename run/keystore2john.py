#!/usr/bin/env python

# This software is Copyright (c) 2014, Sanju Kholia <sanju.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Currently, only Sun "JKS" keystore files are supported.
# See https://www.bouncycastle.org/specifications.html for details.
#
# Use "Portecle" (https://sourceforge.net/projects/portecle/files/) for testing
# various keystore file formats.

"""

Output password protected Java KeyStore files in JtR compatible format.

Output Format: $keystore$target$data_length$data$hash$nkeys$keylength$keydata$keylength$keydata...

Where,

target == 0 if container password is to be cracked
target == 1 if private key password(s) are to be cracked

KEYSTORE FORMAT:

Magic number (big-endian integer),
Version of this file format (big-endian integer),

Count (big-endian integer),
followed by "count" instances of either:

    {
     tag=1 (big-endian integer),
     alias (UTF string)
     timestamp
     encrypted private-key info according to PKCS #8
         (integer length followed by encoding)
     cert chain (integer count, then certs; for each cert,
         integer length followed by encoding)
    }

or:

    {
     tag=2 (big-endian integer)
     alias (UTF string)
     timestamp
     cert (integer length followed by encoding)
    }

ended by a keyed SHA1 hash (bytes only) of
    { password + whitener + preceding body }

See http://metastatic.org/source/JKS.java (implementation of the "JKS" key
store) for more details.

"""

import sys
import os
import struct
from binascii import hexlify

MAGIC = 0xfeedfeed
VERSION_1 = 0x01
VERSION_2 = 0x02


def read_utf_string(fd):
    buf = fd.read(2)
    if len(buf) < 2:
        return b""
    length = struct.unpack(">H", buf)[0]
    return fd.read(length)


def process_file(filename):
    try:
        fd = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("! %s: %s\n" % (filename, str(e)))
        return

    # read the entire file into data variable
    data = fd.read()
    fd.seek(0, os.SEEK_SET)

    # start actual processing
    buf = fd.read(4)
    if len(buf) < 4:
        return
    xMagic = struct.unpack("> I", buf)[0]
    buf = fd.read(4)
    if len(buf) < 4:
        return
    xVersion = struct.unpack("> I", buf)[0]

    if (xMagic != MAGIC or (xVersion != VERSION_1 and xVersion != VERSION_2)):
        sys.stderr.write("%s: Invalid keystore format\n" % filename)
        return

    buf = fd.read(4)
    if len(buf) < 4:
        return
    count = struct.unpack("> I", buf)[0]

    keys = []
    for i in range(0, count):
        buf = fd.read(4)
        if len(buf) < 4:
            break
        tag = struct.unpack("> I", buf)[0]

        if (tag == 1):  # key entry
            # Read the alias
            alias = read_utf_string(fd)

            # Read the (entry creation) date
            buf = fd.read(8)
            assert(len(buf) == 8)

            # Read the key
            buf = fd.read(4)
            keysize = struct.unpack("> I", buf)[0]
            protectedPrivKey = fd.read(keysize)
            assert(len(protectedPrivKey) == keysize)

            # read certificates
            buf = fd.read(4)
            numOfCerts = struct.unpack("> I", buf)[0]
            if (numOfCerts > 0):
                for j in range(0, numOfCerts):
                    if xVersion == 2:
                        # read the certificate type
                        read_utf_string(fd)

                    # read certificate data
                    buf = fd.read(4)
                    certsize = struct.unpack("> I", buf)[0]
                    certdata = fd.read(certsize)
                    assert(len(certdata) == certsize)

            keys.append((alias, protectedPrivKey))

        elif (tag == 2):  # trusted certificate entry
            # Read the alias
            read_utf_string(fd)

            # Read the (entry creation) date
            buf = fd.read(8)

            # Read the trusted certificate
            if xVersion == 2:
                # read the certificate type
                read_utf_string(fd)

            buf = fd.read(4)
            certsize = struct.unpack("> I", buf)[0]
            certdata = fd.read(certsize)
            assert(len(certdata) == certsize)
        else:
            sys.stderr.write("%s: Unrecognized keystore entry\n" % filename)
            fd.close()
            return

    # how much data have we processed
    pos = fd.tell()

    # read hash
    md = fd.read(20)
    assert(len(md) == 20)

    # Output for container password (target 0)
    if keys:
        # Use the first key for the container password hash
        alias, protectedPrivKey = keys[0]
        keysize = len(protectedPrivKey)
        keydata = hexlify(protectedPrivKey).decode('ascii')
        nkeys = 1
    else:
        keysize = 0
        keydata = ""
        nkeys = 0

    sys.stdout.write("%s:$keystore$0$%d$%s" % (os.path.basename(filename), pos,
                                               hexlify(data[0:pos]).decode('ascii')))

    sys.stdout.write("$%s" % hexlify(md).decode('ascii'))
    sys.stdout.write("$%d$%d$%s" % (nkeys, keysize, keydata))
    sys.stdout.write(":::::%s\n" % filename)

    # Output for each key password (target 1)
    for alias, protectedPrivKey in keys:
        try:
            alias_str = alias.decode('utf-8', 'replace')
        except:
            alias_str = str(alias)

        # JtR label shouldn't contain ':'
        alias_str = alias_str.replace(':', '_')

        keysize = len(protectedPrivKey)
        keydata = hexlify(protectedPrivKey).decode('ascii')

        sys.stdout.write("%s-%s:$keystore$1$%d$%s" % (os.path.basename(filename), alias_str, pos,
                                                      hexlify(data[0:pos]).decode('ascii')))
        sys.stdout.write("$%s" % hexlify(md).decode('ascii'))
        sys.stdout.write("$1$%d$%s" % (keysize, keydata))
        sys.stdout.write(":::::%s\n" % filename)

    fd.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <.keystore / .jks file(s)>\n" % sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
