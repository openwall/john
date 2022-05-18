#!/usr/bin/env python

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

def get_all_tags_ktypes(lines):
    tags = []
    ktypes = []
    for line in lines:
        if "BEGIN RSA PRIVATE" in line:
            tags.append("RSA")
            ktypes.append(0)
        elif "BEGIN DSA PRIVATE KEY" in line:
            tags.append("DSA")
            ktypes.append(1)
        # new private key format for OpenSSH (automatically enabled for
        # keys using ed25519 signatures), ed25519 stuff is not supported
        # yet!
        elif "BEGIN OPENSSH PRIVATE KEY" in line:
            tags.append("OPENSSH")
            ktypes.append(2) # bcrypt pbkdf + aes-256-cbc
        elif "BEGIN EC PRIVATE KEY" in line:
            tags.append("EC")
            ktypes.append(3)

    return tags, ktypes

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
    start = 0
    num_processed_keys = 0
    tags, ktypes = get_all_tags_ktypes(lines)
    if not tags:
        sys.stderr.write("[%s] couldn't parse keyfile\n" % filename)
        return

    for tag, ktype in zip(tags, ktypes):
        join_lines = ''.join(lines[start:])
        if not join_lines:
            break

        while (start < len(lines)) and (lines[start].strip() != '-----BEGIN ' + tag + ' PRIVATE KEY-----'):
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
            data = base64.b64decode(data)
        except base64.binascii.Error:
            e = sys.exc_info()[1]
            raise Exception('base64 decoding error: ' + str(e))


        if ktype != 2:
            if 'proc-type' not in headers:  # unencrypted key file?
                sys.stderr.write("%s has no password!\n" % f.name)
                return

            try:
                encryption_type, saltstr = headers['dek-info'].split(',')
            except:
                raise Exception('Can\'t parse DEK-info in private key file')

            if encryption_type not in CIPHER_TABLE:
                raise Exception('Unknown private key cipher "%s"' % encryption_type)


        if ktype == 2:  # bcrypt_pbkdf format, see "sshkey_private_to_blob2" in sshkey.c
            AUTH_MAGIC = b"openssh-key-v1"
            salt_length = 16  # fixed value in sshkey.c
            # find offset to salt
            offset = 0
            if not data.startswith(AUTH_MAGIC):
                raise Exception('Missing AUTH_MAGIC!')
            offset = offset + len(AUTH_MAGIC) + 1  # sizeof(AUTH_MAGIC)
            length = unpack(">I", data[offset:offset+4])[0]  # ciphername length
            offset = offset + 4
            cipher_name = data[offset:offset+length].decode('ascii')
            if cipher_name == 'none':
                sys.stderr.write("%s has no password!\n" % f.name)
                return
            elif cipher_name == 'aes256-cbc':
                encryption_type = "AES-256-CBC"
            elif cipher_name == 'aes256-ctr':
                encryption_type = "AES-256-CTR"
            else:
                raise Exception('Unknown encryption type')
            offset = offset + length
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

        keysize = CIPHER_TABLE[encryption_type]['keysize']
        salt = binascii.unhexlify(saltstr)

        filename_idx = '' if len(tags) == 1 else '_' + str(num_processed_keys+1)
        data = binascii.hexlify(data).decode("ascii")
        if keysize == 24 and encryption_type == "AES-192-CBC" and (ktype == 0 or ktype == 1):  # RSA, DSA keys using AES-192
            hashline = "%s%s:$sshng$%s$%s$%s$%s$%s" % (f.name, filename_idx, 4, len(saltstr) // 2,
                saltstr, len(data) // 2, data)
        elif keysize == 32 and encryption_type == "AES-256-CBC" and (ktype == 0 or ktype == 1):  # RSA, DSA keys using AES-256
            hashline = "%s%s:$sshng$%s$%s$%s$%s$%s" % (f.name, filename_idx, 5, len(saltstr) // 2,
                saltstr, len(data) // 2, data)
        elif keysize == 24:
            hashline = "%s%s:$sshng$%s$%s$%s$%s$%s" % (f.name, filename_idx, 0,  # 0 -> 3DES
                len(salt), saltstr, len(data) // 2, data)
        elif keysize == 16 and (ktype == 0 or ktype == 1):  # RSA, DSA keys using AES-128
            hashline = "%s%s:$sshng$%s$%s$%s$%s$%s" % (f.name, filename_idx, 1, len(saltstr) // 2,
                saltstr, len(data) // 2, data)
        elif keysize == 16 and ktype == 3:  # EC keys using AES-128
            hashline = "%s%s:$sshng$%s$%s$%s$%s$%s" % (f.name, filename_idx, 3, len(saltstr) // 2,
                saltstr, len(data) // 2, data)
        elif keysize == 32 and encryption_type == "AES-256-CBC" and ktype == 2:  # bcrypt pbkdf + aes-256-cbc
            hashline = "%s%s:$sshng$%s$%s$%s$%s$%s$%d$%d" % (f.name, filename_idx, 2, len(saltstr) // 2,
                saltstr, len(data) // 2, data, rounds, ciphertext_begin_offset)
        elif keysize == 32 and encryption_type == "AES-256-CTR" and ktype == 2:  # bcrypt pbkdf + aes-256-ctr
            hashline = "%s%s:$sshng$%s$%s$%s$%s$%s$%d$%d" % (f.name, filename_idx, 6, len(saltstr) // 2,
                saltstr, len(data) // 2, data, rounds, ciphertext_begin_offset)
        else:
            sys.stderr.write("%s uses unsupported cipher, please file a bug!\n" % f.name)
            return

        sys.stdout.write("%s\n" % hashline)
        start = end + 1
        num_processed_keys += 1

    if num_processed_keys != len(tags):
        sys.stderr.write("Error likely in [%s], kindly remove erroneous keys and process again\n" % filename)
        return

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: %s <RSA/DSA/EC/OpenSSH private key file(s)>\n" %
                         sys.argv[0])

    for filename in sys.argv[1:]:
        read_private_key(filename)
