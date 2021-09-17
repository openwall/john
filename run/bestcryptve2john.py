#!/usr/bin/env python3

# This software is Copyright (c) 2021, trounce1 / HN
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

from binascii import hexlify, unhexlify
import argparse
import struct


class MyParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_help()
        exit(0)


def parseargs():

    parser = MyParser(description='Script to extract hashes from BestCrypt Volume encryption',
                      usage='bestcryptve2john.py [-h] disk_image [--offset xxx]',
                      epilog='\n\n Developed by Trounce - April 2020')
    parser.add_argument('disk_image',
                        help='The disk image or partition image')
    parser.add_argument('--offset', nargs='?', type=int,
                        default=0,
                        help='the offset number in bytes to the BestCrypt partition')
    args = parser.parse_args()
    return args


def get_metadata(disk_image, header_offset):
    bc_file = open(args.disk_image, 'rb')
    bc_file.seek(header_offset)
    bc_data = bc_file.read(0x512)
    bc_file.close()
    if bc_data[0:0x20] == unhexlify(b'dda26a7e3a59ff453e350a44bcb4cdd572eacea8fa6484bb8d6612aebf3c6f47'):
        crypto_type = bc_data[0x1e7:0x1e8]
        if bc_data[0x166:0x176] == b'\0' * 16:
            salt = bc_data[0x1e8:0x1f0]
            version = b'3'
        else:
            salt = bc_data[0x1e8:0x1f0] + bc_data[0x166:0x176]
            version = b'4'
        enc_data = bc_data[0x26:0x86]

        jtr_string = b'$bcve$' + version + b'$' + hexlify(crypto_type) + b'$' + hexlify(salt) + b'$' + hexlify(enc_data)
        print(jtr_string.decode())


def main(args):
    offset = args.offset
    bc_file = open(args.disk_image, 'rb')
    bc_file.seek(offset)
    bc_data = bc_file.read(0x512)
    bc_file.close()
    if bc_data[0x1fe:0x200] == b'\x55\xaa':
        for record in range(0, 64, 16):
            header_offset = offset + (0x200 * struct.unpack('<i', bc_data[0x1c6 + record:0x1ca + record])[0])
            get_metadata(args.disk_image, header_offset)

    else:
        get_metadata(args.disk_image, offset)

if __name__ == '__main__':
    args = parseargs()
    main(args)
