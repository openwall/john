#!/usr/bin/env python

# Copyright (C) 2012, Dhiru Kholia <dhiru@openwall.com>
# Copyright (C) 2015, Dhiru Kholia <dhiru@openwall.com>
#
# Modified for JtR
#
# Copyright (C) 2011  Jeff Forcier <jeff@bitprophet.org>
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
import sys
import binascii

DES3 = 0
AES = 1
AES_256 = 2
# known encryption types for private key files:
CIPHER_TABLE = {
    'AES-128-CBC': {'cipher': AES, 'keysize': 16, 'blocksize': 16, 'mode': "AES.MODE_CBC"},
    'DES-EDE3-CBC': {'cipher': DES3, 'keysize': 24, 'blocksize': 8, 'mode': "DES3.MODE_CBC"},
    'AES-256-CBC': {'cipher': AES_256, 'keysize': 32, 'blocksize': 16, 'mode': "AES.MODE_CBC"},
}


def read_private_key(f):
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
    ktype = -1

    tag = None
    if "BEGIN RSA PRIVATE" in lines[0]:  # XXX can we make this a bit more robust?
        tag = "RSA"
        ktype = 0
    elif "-----BEGIN OPENSSH PRIVATE KEY-----" in lines[0]:
        # new private key format for OpenSSH (automatically enabled for
        # keys using ed25519 signatures), ed25519 stuff is not supported
        # yet!
        ktype = 2  # bcrypt pbkdf + aes-256-cbc
        tag = "OPENSSH"
    elif "-----BEGIN DSA PRIVATE KEY-----" in lines[0]:
        ktype = 1
        tag = "DSA"
    elif "-----BEGIN EC PRIVATE KEY-----" in lines[0]:
        ktype = 3
        tag = "EC"

    if not tag:
        sys.stderr.write("[%s] couldn't parse line saying, %s" % (sys.argv[0], lines[0]));
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
        data = base64.decodestring(data)
    except base64.binascii.Error:
        e = sys.exc_info()[1]
        raise Exception('base64 decoding error: ' + str(e))

    if 'proc-type' not in headers and ktype != 2: # unencrypted key file?
        sys.stderr.write("%s has no password!\n" % f.name)
        return None

    try:
        encryption_type, saltstr = headers['dek-info'].split(',')
    except:
        if ktype != 2:
            raise Exception('Can\'t parse DEK-info in private key file')
        else:
            encryption_type = "AES-256-CBC"
            saltstr = "fefe"  # dummy value, not used
    if encryption_type not in CIPHER_TABLE:
        raise Exception('Unknown private key cipher "%s"' % encryption_type)

    cipher = CIPHER_TABLE[encryption_type]['cipher']
    keysize = CIPHER_TABLE[encryption_type]['keysize']
    # mode = CIPHER_TABLE[encryption_type]['mode']
    salt = binascii.unhexlify(saltstr)
    if ktype == 2: # bcrypt_pbkdf format
        salt_offset = 47  # XXX is this fixed?
        salt_length = 16
        saltstr = data[salt_offset:salt_offset+salt_length].encode("hex")

    data = binascii.hexlify(data).decode("ascii")
    print(keysize)
    if keysize == 24:
        hashline = "%s:$sshng$%s$%s$%s$%s$%s" % (f.name, 0,  # 0 -> 3DES
            len(salt), saltstr, len(data) // 2, data)
    elif keysize == 16 and (ktype == 0 or ktype == 1):  # RSA, DSA keys using AES-128
        hashline = "%s:$sshng$%s$%s$%s$%s$%s" % (f.name, 1, len(saltstr) // 2,
            saltstr, len(data) // 2, data)
    elif keysize == 16 and ktype == 3:  # EC keys using AES-128
        hashline = "%s:$sshng$%s$%s$%s$%s$%s" % (f.name, 3, len(saltstr) // 2,
            saltstr, len(data) // 2, data)
    elif keysize == 32 and ktype == 2:  # bcrypt pbkdf + aes-256-cbc
        # round value appears after salt
        rounds = 16
        hashline = "%s:$sshng$%s$%s$%s$%s$%s$%d" % (f.name, 2, len(saltstr) // 2,
            saltstr, len(data) // 2, data, rounds)
    else:
        sys.stderr.write("%s uses unsupported cipher, please file a bug!\n" % f.name)
        return None

    sys.stdout.write("%s\n" % hashline)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: %s < RSA/DSA private key files >\n" % \
                sys.argv[0])

    for filename in sys.argv[1:]:
        read_private_key(filename)
