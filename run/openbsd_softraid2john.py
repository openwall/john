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

import sys
import struct
import os.path
from binascii import hexlify

def process_file(filename):

    headers = open(filename).read()[:0xaa0]
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

    sys.stdout.write(os.path.basename(filename) + ":$openbsd-softraid$");

    num_iterations = struct.unpack("<I", headers[2420:2424])[0]
    sys.stdout.write(str(num_iterations) + "$")

    # salt
    sys.stdout.write(hexlify(headers[2424:2552]) + "$")

    # masked keys
    sys.stdout.write(hexlify(headers[364:2412]) + "$")

    # HMAC
    sys.stdout.write(hexlify(headers[2676:2696]) + "\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: openbsd_softraid2john [disk image]\n")
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
