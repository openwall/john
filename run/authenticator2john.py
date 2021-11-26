#!/usr/bin/env python

# This software is Copyright (c) 2021 Mark Silinio <mark.silinio-at-gmail.com>,
# and it is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Extract and format https://github.com/JeNeSuisPasDave/authenticator app password for cracking with JtR
# Usage: ./authenticator2john.py <authenticator.data file>

import os
import sys
from binascii import hexlify

if len(sys.argv) < 2:
    print('Usage: ./authenticator2john.py <authenticator.data files>')
    exit(1)

filenames = sys.argv[1:]

for filename in filenames:
    bname = os.path.basename(filename)
    try:
        f = open(filename, "rb")
        data = f.read()
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        exit(1)

    iv = data[:16]
    encrypted_data = data[16:32]
    iv = hexlify(iv).decode("ascii")
    encrypted_data = hexlify(encrypted_data).decode("ascii")
    sys.stdout.write("%s:$authenticator$0$%s$%s\n" % (bname, iv, encrypted_data))
