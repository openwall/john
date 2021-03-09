#!/usr/bin/python3

"""
androidfde2john.py, program to "convert" Android FDE images / disks into JtR
friendly format. All the heavy lifting is done by the code written by Gary
Peck.

On ICS (Android 4.0.x), I found out that the encryption footer
resides in a separate partition (of size 8MB).

Copyright (c) 2013 Dhiru Kholia

Copyright (c) 2013, Gary Peck
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

"""

from collections import namedtuple
import os
import struct
import binascii
import sys
from warnings import warn

DEFAULT_DATA_LABEL = "userdata"

# from system/vold/cryptfs.h
# /* This structure starts 16,384 bytes before the end of a hardware
#  * partition that is encrypted.
#  * Immediately following this structure is the encrypted key.
#  * The keysize field tells how long the key is, in bytes.
#  * Then there is 32 bytes of padding,
#  * Finally there is the salt used with the user password.
#  * The salt is fixed at 16 bytes long.
#  * Obviously, the filesystem does not include the last 16 kbytes
#  * of the partition.
#  */

CRYPT_FOOTER_OFFSET = 0x4000

MAX_CRYPTO_TYPE_NAME_LEN = 64

SALT_LEN = 16
KEY_TO_SALT_PADDING = 32

# definitions of flags in the structure below
CRYPT_MNT_KEY_UNENCRYPTED = 0x1  # The key for the partition is not encrypted
CRYPT_ENCRYPTION_IN_PROGRESS = 0x2  # Set when starting encryption, clear when done before rebooting

CRYPT_MNT_MAGIC = 0xD0B5B1C4

# #define __le32 unsigned int
# #define __le16 unsigned short int
#
# struct crypt_mnt_ftr {
#   __le32 magic;         /* See above */
#   __le16 major_version;
#   __le16 minor_version;
#   __le32 ftr_size;      /* in bytes, not including key following */
#   __le32 flags;         /* See above */
#   __le32 keysize;       /* in bytes */
#   __le32 spare1;        /* ignored */
#   __le64 fs_size;       /* Size of the encrypted fs, in 512 byte sectors */
#   __le32 failed_decrypt_count; /* count of # of failed attempts to decrypt and
#                                   mount, set to 0 on successful mount */
#   unsigned char crypto_type_name[MAX_CRYPTO_TYPE_NAME_LEN]; /* The type of encryption
#                                                                needed to decrypt this
#                                                                partition, null terminated */
# };
# end system/vold/cryptfs.h

# from system/vold/cryptfs.c
HASH_COUNT = 2000
KEY_LEN_BYTES = 16
IV_LEN_BYTES = 16
# end system/vold/cryptfs.c


class CryptMntFtr(namedtuple('CryptMntFtr', (
        'magic',
        'major_version',
        'minor_version',
        'ftr_size',
        'flags',
        'keysize',
        'fs_size',
        'failed_decrypt_count',
        'crypto_type_name',
        ))):

    __slots__ = ()

    _struct = struct.Struct(
            '<I HH I I I 4x Q I {}s'.format(MAX_CRYPTO_TYPE_NAME_LEN))

    def __new__(cls, bytestring):
        footer_tuple = cls._struct.unpack(bytestring)
        named_footer = super(CryptMntFtr, cls).__new__(cls, *footer_tuple)
        return named_footer._replace(
                crypto_type_name=named_footer.crypto_type_name.decode("ascii").rstrip("\0"))

    @classmethod
    def struct_size(cls):
        return cls._struct.size


def parse_data(data):
    with open(data, 'rb') as fh:
        out = fh.read(512 * 3)
    return out


def parse_footer(data):
    with open(data, 'rb') as fh:
        # FIX re-enable this fast check
        # fh.seek(-CRYPT_FOOTER_OFFSET, os.SEEK_END)

        # FIXME optimize this stuff by reading less
        while True:
            footer = fh.read(CryptMntFtr.struct_size())
            if len(footer) < CryptMntFtr.struct_size():
                print("Cannot read disk image footer")
                return
            idx = footer.find(b"\xC4\xB1\xB5\xD0")
            if idx == 0:
                break

            fh.seek(- (CryptMntFtr.struct_size() - 1), os.SEEK_CUR)

        crypt_ftr = CryptMntFtr(footer)

        if crypt_ftr.magic != CRYPT_MNT_MAGIC:
            print(
                    data, crypt_ftr, "Bad magic in disk image footer")
        if crypt_ftr.major_version != 1:
            print(data, crypt_ftr,
                                "Cannot understand major version {} in "
                                "disk image footer".format(
                                    crypt_ftr.major_version))
        if crypt_ftr.minor_version != 0:
            warn("crypto footer minor version {}, expected 0".format(
                crypt_ftr.minor_version), UserWarning)

        if crypt_ftr.ftr_size > CryptMntFtr.struct_size():
            # skip to the end of the footer so we can read the key
            fh.seek(crypt_ftr.ftr_size - CryptMntFtr.struct_size(), os.SEEK_CUR)

        if crypt_ftr.keysize != KEY_LEN_BYTES:
            print(data, crypt_ftr,
                                "Keysize of {} bits not supported".format(
                                    crypt_ftr.keysize*8))
        key = fh.read(crypt_ftr.keysize)
        if len(key) != crypt_ftr.keysize:
            print(data, crypt_ftr,
                                "Cannot read key from disk image footer")

        fh.seek(KEY_TO_SALT_PADDING, os.SEEK_CUR)
        salt = fh.read(SALT_LEN)
        if len(salt) != SALT_LEN:
            print(data, crypt_ftr,
                                "Cannot read salt from disk image footer")

        return (crypt_ftr, key, salt)


def note():
    print("Note: This script only works for old Android <= 4.3 disk images and only aes256/cbc-essiv:sha256 images are supported!")


def main(args):

    if len(args) < 3:
        sys.stderr.write("Usage: %s <data partition / image> <footer partition / image>\n\n" % args[0])
        note()
        return

    note()

    data = parse_data(args[1])
    (crypt_ftr, encrypted_key, salt) = parse_footer(args[2])

    print("%s:$fde$%s$%s$%s$%s$%s" % (os.path.basename(args[1]), len(salt),
                                      binascii.hexlify(salt).decode("ascii"),
                                      crypt_ftr.keysize,
                                      binascii.hexlify(encrypted_key).decode("ascii"),
                                      binascii.hexlify(data).decode("ascii")))

if __name__ == '__main__':
    main(sys.argv)
