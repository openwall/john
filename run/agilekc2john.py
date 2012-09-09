#!/usr/bin/env python

# Modfied by Dhiru Kholia <dhiru at openwall.com> in July 2012
# for JtR project.
#
# Copyright (c) 2009 Antonin Amand <antonin.amand@gmail.com>
#
# Permission to use, copy, modify, and distribute this software and its
# documentation for any purpose and without fee is hereby granted,
# provided that the above copyright notice appear in all copies and that
# both that copyright notice and this permission notice appear in
# supporting documentation.
#
# THE AUTHOR PROVIDES THIS SOFTWARE ``AS IS'' AND ANY EXPRESSED OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
"""
    This module is a set of classes to decrypt and encrypt data using the
    "AgileKeychain" format developed for 1Password by Agile Web Solutions, Inc.
    http://agilewebsolutions.com/products/1Password

    Encryption keys are encrypted with the AES-CBC algorithm using a password
    which is derived using the PBKDF2 algorithm and a salt to provide more safety.

    Data is then encrypted with encryption keys using the same AES-CBC algorithm.

    This module depends on hashlib and PyCrypto available on PyPi
    The implementation of the PBKDF2 algorithm distributed with this module
    is courtesy of Dwayne C. Litzenberger <dlitz@dlitz.net>
"""

import os
import sys

try:
    import json
    assert json
except ImportError:
    import simplejson as json

from base64 import b64decode
import binascii


class Key(object):
    """ A Key in the keyring
    """

    SALTED_PREFIX = 'Salted__'
    ZERO_IV = "\0" * 16
    ITERATIONS = 1000
    BLOCK_SIZE = 16

    Nr = 14
    Nb = 4
    Nk = 8

    def __init__(self, identifier, level, data, validation, iterations):
        """ initialize key
        """
        self.identifier = identifier
        self.level = level
        self.validation = validation
        bin_data = data
        if self.__is_salted(bin_data):
            self.salt = bin_data[8:16]
            self.data = bin_data[16:]
        else:
            self.salt = self.ZERO_IV
            self.data = bin_data
        self.iterations = iterations

    def __is_salted(self, data):
        return self.SALTED_PREFIX == data[:len(self.SALTED_PREFIX)]


# Todo remove plist logic its not generic
class Keychain(object):
    """Manage the enc/dec key
    """

    def __init__(self):
        self.keys = list()

    def add_key(self, key):
        self.keys.append(key)


class AgileKeychain(Keychain):

    def __init__(self, path, name='default'):
        self.path = path
        self.name = name
        self.entries = None
        self.__open_keys_file()

    def __repr__(self):
        return '<%s.AgileKeychain path="%s">' % (self.__module__, self.path)

    def open(self, password):
        self.__decrypt_keys(password)
        del password

    def __open_keys_file(self):
        """Open the json file containing the keys for decrypting the
        real keychain and parse it
        """
        try:
            keys_file_path = \
                os.path.join(self.path, 'data', self.name, 'encryptionKeys.js')
            keys_file = open(keys_file_path, 'r')
            try:
                # seems that their is some \0 and the of base64 blobs
                # that makes expat parser fail
                # TODO: add some expat exception handling
                keys = json.loads(keys_file.read())
                self.keys = []
                for kd in keys['list']:
                    key = Key(kd['identifier'],
                              kd['level'],
                              b64decode(kd['data'][:-1]),
                              b64decode(kd['validation'][:-1]),
                              kd.get('iterations', Key.ITERATIONS))
                    self.keys.append(key)
            finally:
                keys_file.close()
        except (IOError, KeyError):
            print >> sys.stderr, 'error while opening the keychain'

    def john_output(self):
        sys.stdout.write("%s:$agilekeychain$%s" % (self.path, len(self.keys)))
        for i in range(0, len(self.keys)):
            sys.stdout.write("*%s*%s*%s*%s*%s" % (self.keys[i].iterations,
                len(self.keys[i].salt), binascii.hexlify(self.keys[i].salt),
                len(self.keys[i].data), binascii.hexlify(self.keys[i].data)))

        sys.stdout.write("\n")


def process_file(keychain):
    keychain = AgileKeychain(keychain)
    keychain.john_output()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print >>sys.stderr, "Usage: %s <1Password Agile Keychain(s)>" % sys.argv[0]
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
