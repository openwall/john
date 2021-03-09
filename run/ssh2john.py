#!/usr/bin/python3

# Copyright (C) 2012, Dhiru Kholia <dhiru@openwall.com>
# Copyright (C) 2015, Dhiru Kholia <dhiru@openwall.com>
#
# Modified for JtR
#
# Copyright (C) 2011, Jeff Forcier <jeff@bitprophet.org>
#
# This software is Copyright (c) 2020 Valeriy Khromov <valery.khromov at gmail.com>,
# and it is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# This file is part of ssh.
#
# 'ssh' is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# 'ssh' is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with 'ssh'; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

import base64
import binascii
import codecs
from struct import unpack
import sys

DES3 = 0
AES = 1
AES_256 = 2
# known encryption types for private key files:
CIPHER_TABLE = {
    'AES-128-CBC': {'cipher': AES, 'keysize': 16, 'blocksize': 16, 'mode': "AES.MODE_CBC"},
    'DES-EDE3-CBC': {'cipher': DES3, 'keysize': 24, 'blocksize': 8, 'mode': "DES3.MODE_CBC"},
    'AES-256-CBC': {'cipher': AES_256, 'keysize': 32, 'blocksize': 16, 'mode': "AES.MODE_CBC"},
    'AES-192-CBC': {'cipher': AES, 'keysize': 24, 'blocksize': 16, 'mode': "AES.MODE_CBC"},
    'AES-256-CTR': {'cipher': AES_256, 'keysize': 32, 'blocksize': 16, 'mode': "AES.MODE_CTR"},
}


def read_private_key(filename):
    """
    Read an SSH2-format private key file, looking for a string of the type
    C{"BEGIN xxx PRIVATE KEY"} for some C{xxx}, base64-decode the text we
    find, and return it as a string.
    """
    try:
        f = open(filename, 'r')
    except IOError:
        e = sys.exc_info()[1]
        sys.stdout.write("%s\n" % str(e))
        return

    lines = f.readlines()
    all_lines = ''.join(lines)
    ktype = -1
    tag = None
    if "BEGIN RSA PRIVATE" in all_lines:
        tag = "RSA"
        ktype = 0
    elif "-----BEGIN OPENSSH PRIVATE KEY-----" in all_lines:
        # new private key format for OpenSSH (automatically enabled for
        # keys using ed25519 signatures), ed25519 stuff is not supported
        # yet!
        ktype = 2  # bcrypt pbkdf + aes-256-cbc
        tag = "OPENSSH"
    elif "-----BEGIN DSA PRIVATE KEY-----" in all_lines:
        ktype = 1
        tag = "DSA"
    elif "-----BEGIN EC PRIVATE KEY-----" in all_lines:
        ktype = 3
        tag = "EC"

    if not tag:
        sys.stderr.write("[%s] couldn't parse keyfile\n" % filename)
        return

    start = 0
    while (start < len(lines)) and ((lines[start].strip() != '-----BEGIN ' + tag + ' PRIVATE KEY-----') and (lines[start].strip() != '-----BEGIN OPENSSH PRIVATE KEY-----')):
        start += 1
    if start >= len(lines):
        sys.stderr.write("%s is not a valid private key file\n" % f.name)
        return

    # parse any headers first
    headers = {}
    start += 1
    while start < len(lines):
        l = lines[start].split(': ')
        if len(l) == 1:
            break
        headers[l[0].lower()] = l[1].strip()
        start += 1
    # find end
    end = start
    while (lines[end].strip() != '-----END ' + tag + ' PRIVATE KEY-----') and (end < len(lines)):
        end += 1
    # if we trudged to the end of the file, just try to cope.
    try:
        data = ''.join(lines[start:end]).encode()
        data = codecs.decode(data, 'base64_codec')
    except base64.binascii.Error:
        e = sys.exc_info()[1]
        raise Exception('base64 decoding error: ' + str(e))

    if 'proc-type' not in headers and ktype != 2:  # unencrypted key file?
        sys.stderr.write("%s has no password!\n" % f.name)
        return None

    try:
        encryption_type, saltstr = headers['dek-info'].split(',')
    except:
        if ktype != 2:
            raise Exception('Can\'t parse DEK-info in private key file')
        else:
            if b'aes256-cbc' in data:
                encryption_type = "AES-256-CBC"
            elif b'aes256-ctr' in data:
                encryption_type = "AES-256-CTR"
            else:
                raise Exception('Unknown encryption type')
            saltstr = "fefe"  # dummy value, not used
    if encryption_type not in CIPHER_TABLE:
        raise Exception('Unknown private key cipher "%s"' % encryption_type)

    cipher = CIPHER_TABLE[encryption_type]['cipher']
    keysize = CIPHER_TABLE[encryption_type]['keysize']
    # mode = CIPHER_TABLE[encryption_type]['mode']
    salt = binascii.unhexlify(saltstr)
    AUTH_MAGIC = b"openssh-key-v1"
    if ktype == 2:  # bcrypt_pbkdf format, see "sshkey_private_to_blob2" in sshkey.c
        salt_length = 16  # fixed value in sshkey.c
        # find offset to salt
        offset = 0
        if not data.startswith(AUTH_MAGIC):
            raise Exception('Missing AUTH_MAGIC!')
        offset = offset + len(AUTH_MAGIC) + 1  # sizeof(AUTH_MAGIC)
        length = unpack(">I", data[offset:offset+4])[0]  # ciphername length
        if length > 32:  # weak sanity check
            raise Exception('Unknown ciphername!')
        offset = offset + 4 + length
        length = unpack(">I", data[offset:offset+4])[0]  # kdfname length
        offset = offset + 4 + length
        length = unpack(">I", data[offset:offset+4])[0]  # kdf length
        salt_offset = offset + 4 + 4  # extra "4" to skip over salt length field
        # print(salt_offset)  # this should be 47, always?
        # find offset to check bytes
        offset = offset + 4 + length  # number of keys
        offset = offset + 4  # pubkey blob
        length = unpack(">I", data[offset:offset+4])[0]  # pubkey length
        offset = offset + 4 + length
        offset = offset + 4  # skip over length of "encrypted" blob
        if offset > len(data):
            raise Exception('Internal error in offset calculation!')
        ciphertext_begin_offset = offset
        saltstr = binascii.hexlify(data[salt_offset:salt_offset+salt_length]).decode("ascii")
        # rounds value appears after salt
        rounds_offset = salt_offset + salt_length
        rounds = data[rounds_offset: rounds_offset+4]
        rounds = unpack(">I", rounds)[0]
        if rounds == 0:
            rounds == 16

    data = binascii.hexlify(data).decode("ascii")
    if keysize == 24 and encryption_type == "AES-192-CBC" and (ktype == 0 or ktype == 1):  # RSA, DSA keys using AES-192
        hashline = "%s:$sshng$%s$%s$%s$%s$%s" % (f.name, 4, len(saltstr) // 2,
            saltstr, len(data) // 2, data)
    elif keysize == 32 and encryption_type == "AES-256-CBC" and (ktype == 0 or ktype == 1):  # RSA, DSA keys using AES-256
        hashline = "%s:$sshng$%s$%s$%s$%s$%s" % (f.name, 5, len(saltstr) // 2,
            saltstr, len(data) // 2, data)
    elif keysize == 24:
        hashline = "%s:$sshng$%s$%s$%s$%s$%s" % (f.name, 0,  # 0 -> 3DES
            len(salt), saltstr, len(data) // 2, data)
    elif keysize == 16 and (ktype == 0 or ktype == 1):  # RSA, DSA keys using AES-128
        hashline = "%s:$sshng$%s$%s$%s$%s$%s" % (f.name, 1, len(saltstr) // 2,
            saltstr, len(data) // 2, data)
    elif keysize == 16 and ktype == 3:  # EC keys using AES-128
        hashline = "%s:$sshng$%s$%s$%s$%s$%s" % (f.name, 3, len(saltstr) // 2,
            saltstr, len(data) // 2, data)
    elif keysize == 32 and encryption_type == "AES-256-CBC" and ktype == 2:  # bcrypt pbkdf + aes-256-cbc
        hashline = "%s:$sshng$%s$%s$%s$%s$%s$%d$%d" % (f.name, 2, len(saltstr) // 2,
            saltstr, len(data) // 2, data, rounds, ciphertext_begin_offset)
    elif keysize == 32 and encryption_type == "AES-256-CTR" and ktype == 2:  # bcrypt pbkdf + aes-256-ctr
        hashline = "%s:$sshng$%s$%s$%s$%s$%s$%d$%d" % (f.name, 6, len(saltstr) // 2,
            saltstr, len(data) // 2, data, rounds, ciphertext_begin_offset)
    else:
        sys.stderr.write("%s uses unsupported cipher, please file a bug!\n" % f.name)
        return None

    sys.stdout.write("%s\n" % hashline)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: %s <RSA/DSA/EC/OpenSSH private key file(s)>\n" %
                         sys.argv[0])

    for filename in sys.argv[1:]:
        read_private_key(filename)
