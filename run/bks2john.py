#!/usr/bin/env python

"""

Convert BKS keystore(s) into JtR compatible format

Modified for JtR by Dhiru Kholia in June, 2016

...

BKS file format decoder.

Bouncycaste "BKS" keystore parser. Supports both the old V1 and current V2
format.

The MIT License (MIT)

Copyright (c) 2013 Kurt Rose, Jeroen De Ridder

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

"""

# Useful Commands,
#
# keytool -genkey -alias secret -keystore secret.bks -storetype BKS -provider
# org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath
# "/usr/share/java/bcprov.jar
#
# keytool -list -v -keystore secret.bks -storetype BKS -provider
# org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath
# "/usr/share/java/bcprov.jar
#
# keytool -keystore cacerts.bks -storetype BKS -provider
# org.bouncycastle.jce.provider.BouncyCastleProvider -storepass changeit
# -importcert -trustcacerts -alias PortSwiggerCA -file PortSwiggerCA.crt
#
# Get "bcprov.jar" from http://www.bouncycastle.org/latest_releases.html URL.
#
# Relevant code is in org/bouncycastle/jcajce/provider/keystore/bc/BcKeyStoreSpi.java file

# Uber keystores contain the same entry data as BKS keystores, except they wrap
# it differently:
#
#    BKS  = BKS_store || HMAC-SHA1(BKS_store)
#    UBER = PBEWithSHAAndTwofish-CBC(BKS_store || SHA1(BKS_store))
#
# where BKS_store represents the entry format shared by both keystore types.
#
# The Twofish key size is 256 bits, the PBE key derivation scheme is that as
# outlined by PKCS#12 (RFC 7292), and the padding scheme for the Twofish cipher
# is PKCS#7.
#
# Use http://portecle.sourceforge.net/ (Portecle) to easily generate a variety
# of keystore files.

import struct
import binascii
import sys
import os
from optparse import OptionParser

b8 = struct.Struct('>Q')
b4 = struct.Struct('>L')  # unsigned
b2 = struct.Struct('>H')
b1 = struct.Struct('B')  # unsigned


def _read_utf(data, pos):
    size = b2.unpack_from(data, pos)[0]
    pos += 2
    return data[pos:pos+size].decode('utf-8'), pos+size


def _read_data(data, pos):
    size = b4.unpack_from(data, pos)[0]
    pos += 4
    return data[pos:pos+size], pos+size


def process_file(filename, keystore_type="bks"):
    try:
        fd = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("! %s: %s\n" % (filename, str(e)))
        return

    data = fd.read()
    pos = 0

    if keystore_type == "bks":

        # read version
        version = b4.unpack_from(data, pos)[0]
        pos += 4
        if version not in [1, 2]:
            sys.stderr.write("Unsupported BKS keystore version %s\n" % version)
            return

        # read salt
        size = b4.unpack_from(data, pos)[0]
        pos += 4
        salt = data[pos:pos+size]
        pos += size

        # read iterations
        iteration_count = b4.unpack_from(data, pos)[0]
        pos += 4

        # https://github.com/bcgit/bc-java/blob/master/prov/src/main/java/org/bouncycastle/jcajce/provider/keystore/bc/BcKeyStoreSpi.java
        # https://github.com/doublereedkurt/pyjks/blob/master/jks/bks.py
        initial_pos = pos
        while pos < len(data):
            _type = b1.unpack_from(data, pos)[0]
            pos += 1
            if _type == 0:
                break
            alias, pos = _read_utf(data, pos)
            # timestamp = b8.unpack_from(data, pos)[0]
            pos += 8
            chain_length = b4.unpack_from(data, pos)[0]
            pos += 4

            for n in range(chain_length):
                cert_type, pos = _read_utf(data, pos)
                cert_data, pos = _read_data(data, pos)

            if _type == 1:  # certificate
                cert_type, pos = _read_utf(data, pos)
                cert_data, pos = _read_data(data, pos)
            elif _type == 2:
                # key: plaintext key entry, i.e. same as sealed key but without
                # the PBEWithSHAAnd3KeyTripleDESCBC layer
                # key_type = b1.unpack_from(data, pos)[0]
                pos += 1
                key_format, pos = _read_utf(data, pos)
                key_algorithm, pos = _read_utf(data, pos)
                key_enc, pos = _read_data(data, pos)
            elif _type == 3:
                # secret key: opaque arbitrary data blob, stored as-is by the
                # keystore; can be anything (assumed to already be protected
                # when supplied).
                secret_data, pos = _read_data(data, pos)
            elif _type == 4:
                # sealed key; a well-formatted certificate, private key or
                # public key, encrypted by the BKS implementation with a
                # standard algorithm at save time
                sealed_data, pos = _read_data(data, pos)
            else:
                sys.stderr.write("Unexpected keystore entry type %d\n" % _type)

        store_data = data[initial_pos:pos]
        store_hmac = data[pos:pos+20]
        hmac_key_size = 20  # SHA1
        hmac_key_size = hmac_key_size*8 if version != 1 else hmac_key_size

        # 0 -> BKS keystore, 1 -> Uber keystore
        sys.stdout.write("%s:$bks$0$%s$%s$%s$%s$%s$%s$%s:::::%s\n" %
                         (os.path.basename(filename), version, hmac_key_size,
                          iteration_count, size, binascii.hexlify(salt),
                          binascii.hexlify(store_data),
                          binascii.hexlify(store_hmac), filename))
    else:  # Uber keystores
        pos = 0
        ver = b4.unpack_from(data, pos)[0]
        pos += 4
        if ver != 1:
            sys.stderr.write("Unsupported UBER keystore version %s\n" % ver)

        salt, pos = _read_data(data, pos)
        size = len(salt)
        iteration_count = b4.unpack_from(data, pos)[0]
        pos += 4
        encrypted_bks_store = data[pos:]
        hmac_key_size = 20  # unused for UBER keystore
        store_hmac = "\x00" * 20  # unused for UBER keystore
        # 0 -> BKS keystore, 1 -> Uber keystore
        sys.stdout.write("%s:$bks$1$%s$%s$%s$%s$%s$%s$%s:::::%s\n" %
                         (os.path.basename(filename), ver, hmac_key_size,
                          iteration_count, size, binascii.hexlify(salt),
                          binascii.hexlify(encrypted_bks_store),
                          binascii.hexlify(store_hmac), filename))


if __name__ == "__main__":
    parser = OptionParser(usage="Usage: %prog [options] <.bks / .uber file(s)>")
    parser.add_option("-t", "--type",
                      dest="type",
                      default="bks",
                      help="BKS keystore type (bks / uber)",)
    (options, args) = parser.parse_args()

    if len(args) < 1:
        parser.print_help()
        sys.exit(-1)

    for f in args:
        process_file(f, options.type)
