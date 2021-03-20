#!/usr/bin/env python

"""
keyring2john.py -> convert Gnome Keyring files to john format.

Copyright (c) 2015 Tonimir Kisasondi - http://github.com/tkisason

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


import argparse
import binascii


class GnomeKeyring_Parser():
    offset = 0
    keyring = ''
    KEYRING_FILE = ''

    def __init__(self, KEYRING_FILE):
        KEYRING_FILE_HEADER = b"GnomeKeyring\n\r\0\n"
        self.KEYRING_FILE = KEYRING_FILE
        self.keyring = open(KEYRING_FILE, 'rb').read()
        if self.keyring.find(KEYRING_FILE_HEADER) != 0:
            raise Exception ('Un-supported GNOME Keyring file!')

    def hexstr(self, bytestr):
        return binascii.hexlify(bytestr).decode('ascii')

    def read_keyring(self, length):
        value = self.keyring[:length]
        self.keyring = self.keyring[length:]
        self.offset += length
        return value

    def parse_keyring(self):
        self.read_keyring(16) # Keyring header
        version = self.read_keyring(2) # version
        crypto = self.read_keyring(1) # crypto
        hash_t = self.read_keyring(1) # hash_t
        name_length = self.read_keyring(4) # name_length
        name_length = int(self.hexstr(name_length), 16)
        name = self.read_keyring(name_length)
        ctime = self.read_keyring(8)
        mtime = self.read_keyring(8)
        flags = self.read_keyring(4)
        lock_timeout = self.read_keyring(4)
        iterations = self.read_keyring(4)
        iterations = int(self.hexstr(iterations), 16)
        salt = self.read_keyring(8)
        salt = self.hexstr(salt)
        reserved = self.read_keyring(16)
        num_items = self.read_keyring(8)
        num_items = int(self.hexstr(num_items), 16)
        hash_value = self.read_keyring(16)
        hash_value = self.hexstr(hash_value)
        crypto_size = len(hash_value)//2
        return self.KEYRING_FILE + ':$keyring$' + salt + '*' + str(iterations) + '*' + str(crypto_size) + '*0*'+ hash_value


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='keyring2john.py -> convert Gnome Keyring files to john format.')
    parser.add_argument('KEYRING_FILE', help='Input Gnome Keyring file')
    args=parser.parse_args()
    Parser = GnomeKeyring_Parser(args.KEYRING_FILE)
    print(Parser.parse_keyring())
