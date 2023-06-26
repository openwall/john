#!/usr/bin/env python

# JtR utility to convert native Adobe AEM (Adobe Experience Manager) hashes to
# an existing JtR hash format.

# This software is Copyright (c) 2018, Dhiru Kholia <kholia at kth.se> and it
# is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# See "generateHash" in PasswordUtil.java from the following project,
# https://github.com/apache/jackrabbit-oak.


import sys

PY3 = sys.version_info[0] == 3

if not PY3:
    reload(sys)
    sys.setdefaultencoding('utf8')

# Input,
#   {SHA-256}a9d4b340cb43807b-1000-33b8875ff3f9619e6ae984add262fb6b6f043e8ff9b065f4fb0863021aada275
#   jsmith:{SHA-256}fe90d85cdcd7e79c-1000-ef182cdc47e60b472784e42a6e167d26242648c6b2e063dfd9e27eec9aa38912
#   admin:{SHA-512}fe90d85cdcd7e79c-1000-4c29a0ac964e7bbc5380797f294d15928288cbcde3d501eb8746296de8d6c06b2b5ff27b56ae174744fe69ee157614ad126c1315ee3b67c891e42753e01a3e37
#
# Output,
#   $sspr$3$1000$a9d4b340cb43807b$33b8875ff3f9619e6ae984add262fb6b6f043e8ff9b065f4fb0863021aada275
#   jsmith:$sspr$3$1000$fe90d85cdcd7e79c$ef182cdc47e60b472784e42a6e167d26242648c6b2e063dfd9e27eec9aa38912
#   admin:$sspr$4$1000$fe90d85cdcd7e79c$4c29a0ac964e7bbc5380797f294d15928288cbcde3d501eb8746296de8d6c06b2b5ff27b56ae174744fe69ee157614ad126c1315ee3b67c891e42753e01a3e37
#
# Passwords -> admin, Aa12345678!@

tag = "{SHA-256}"
tag_length = len(tag)

def process_file(filename):
    with open(filename, "r") as f:
        for line in f.readlines():
            line = line.rstrip()
            if tag in line:
                algo = 3  # SHA-256
            elif "{SHA-512}" in line:
                algo = 4  # SHA-512
            else:
                sys.stderr.write("[!] Unknown hash format -> %s\n" % line[0:8])
                continue
            # Parse username
            user = ''
            if ':' in line:
                parts = line.split(':')
                user = parts[0] + ':'
                line = parts[1]
            # Split up hashing algo, salt, iterations, digest values
            line = line[tag_length:]
            data = line.split('-')
            try:
                salt, iterations, h = data
            except ValueError:
                import traceback
                traceback.print_exc()
                continue
            # Print out results $$$
            sys.stdout.write("%s$sspr$%s$%s$%s$%s\n" % (user, algo, iterations, salt, h))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <File(s)-with-Adobe-AEM-hashes>\n" % sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
