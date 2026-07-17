#!/usr/bin/env python

"""Extract age hashes for John the Ripper.

age (https://age-encryption.org/) passphrase encryption uses scrypt and
ChaCha20-Poly1305 to wrap a random file key.

Output:
    $age$*1*<logN>*<salt_hex>*<wrapped_key_hex>

This software is Copyright (c) 2026, trebla, and it is hereby released to the
general public under the following terms:

Redistribution and use in source and binary forms, with or without
modification, are permitted.
"""

from __future__ import print_function
import os, sys, base64, binascii


# b64 without padding
def b64raw(s):
    pad = (-len(s)) % 4
    # To make it work with both python2.7 and python3
    if isinstance(s, bytes):
        return base64.b64decode(s + b"=" * pad)
    return base64.b64decode(s + "=" * pad)


def err(filename, msg):
    sys.stderr.write("[ERROR] %s: %s\n" % (filename, msg))


def read_body(lines, i):
    """
    Consume base64 body lines
    returns (decoded_bytes, new_i).
    """
    body = b""
    while i < len(lines):
        line = lines[i].rstrip()
        if line.startswith(b"->") or line.startswith(b"---"):
            break
        try:
            chunk = b64raw(line)
        except Exception:
            break
        body += chunk
        i += 1
        if len(line) < 64:
            # short line = last line of stanza body
            break
    return body, i


def process_file(filename):
    try:
        raw = open(filename, "rb").read()
    except IOError as e:
        return err(filename, e)

    if raw.startswith(b"-----BEGIN AGE ENCRYPTED FILE-----"):
        try:
            raw = base64.b64decode(
                b"".join(l for l in raw.splitlines() if not l.startswith(b"-----"))
            )
        except Exception as e:
            return err(filename, "failed to decode armor: %s" % e)

    lines = raw.split(b"\n")
    if not lines or lines[0].rstrip() != b"age-encryption.org/v1":
        return err(filename, "not a valid age file")

    i = 1
    while i < len(lines):
        line = lines[i].rstrip()
        if line.startswith(b"---"):
            break
        if not line.startswith(b"->"):
            i += 1
            continue

        parts = line.split()
        i += 1

        if parts[1] != b"scrypt":
            _, i = read_body(lines, i)
            continue

        if len(parts) != 4:
            return err(filename, "malformed scrypt stanza")

        salt = b64raw(parts[2])
        logN = int(parts[3].decode("ascii"))
        if len(salt) != 16:
            return err(filename, "scrypt salt must be 16 bytes, got %d" % len(salt))

        body, _ = read_body(lines, i)
        if len(body) != 32:
            return err(filename, "wrapped key must be 32 bytes, got %d" % len(body))

        name = os.path.basename(filename)
        salt_hex = binascii.hexlify(salt).decode("ascii")
        wrapped_hex = binascii.hexlify(body).decode("ascii")
        print("%s:$age$*1*%d*%s*%s" % (name, logN, salt_hex, wrapped_hex))
        return

    err(filename, "no scrypt recipient stanza found")


# --- main ---

if len(sys.argv) < 2:
    sys.stderr.write("Usage: %s <age-file> [...]\n" % sys.argv[0])
    sys.exit(1)

for fname in sys.argv[1:]:
    process_file(fname)
