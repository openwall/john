#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Copyright (c) 2014 Thiébaud Weksteen <thiebaud at weksteen dot fr>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#
#  In OpenBSD 6.1, softraid crypto switched to bcrypt PBKDF instead of PKCS5
#  PBKDF2.
#
#  References,
#
#  http://thiébaud.fr/openbsd_softraid.html
#  http://www.openbsd.org/faq/upgrade61.html
#  https://github.com/openbsd/src/blob/master/sys/dev/softraid.c
#  https://github.com/openbsd/src/blob/master/sys/dev/softraidvar.h

import sys
import struct
import os.path
from binascii import hexlify

SR_CRYPTOKDFT_PKCS5_PBKDF2 = 1
SR_CRYPTOKDFT_KEYDISK = 2
SR_CRYPTOKDFT_BCRYPT_PBKDF = 3


def process_file(filename):

    headers = open(filename).read()[:0xaa0 + 81920]
    start = headers.find("marcCRAM")
    if start != -1:
        headers = headers[start:]

    if headers[:8] != "marcCRAM":
        sys.stderr.write(filename + " : Wrong magic\n")
        return
    if headers[72:81] != "SR CRYPTO":
        sys.stderr.write(filename + " : Wrong RAID type\n")
        return
    if headers[260] != "\x01":
        sys.stderr.write(filename + " : Wrong optional header type\n")
        return
    if headers[284] != "\x02":
        sys.stderr.write(filename + " : Wrong encryption type\n")
        return

    sr_crypto_genkdf_type = struct.unpack("<I", headers[2416:2420])[0]
    if (sr_crypto_genkdf_type != SR_CRYPTOKDFT_PKCS5_PBKDF2 and
            sr_crypto_genkdf_type != SR_CRYPTOKDFT_BCRYPT_PBKDF):
        sys.stderr.write("%s : kdf of type '%s' is not supported yet!\n" %
                         (os.path.basename(filename), sr_crypto_genkdf_type))
        return

    sys.stdout.write(os.path.basename(filename) + ":$openbsd-softraid$")

    # num_iterations and salt come from the "scm_kdfhint" field
    num_iterations = struct.unpack("<I", headers[2420:2424])[0]
    sys.stdout.write(str(num_iterations) + "$")
    sys.stdout.write(hexlify(headers[2424:2552]) + "$")  # salt

    # masked keys, sr_meta_crypto structure
    sys.stdout.write(hexlify(headers[364:2412]) + "$")

    # HMAC, chk_hmac_sha1 field
    sys.stdout.write(hexlify(headers[2676:2696]))

    sys.stdout.write("$%s\n" % sr_crypto_genkdf_type)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: openbsd_softraid2john [disk image]\n")
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
