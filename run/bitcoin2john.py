#!/usr/bin/env python

# This software is Copyright (c) 2012, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby placed in the public domain.
#
# This utility (bitcoin2john.py) is based on jackjack's pywallet.py [1] which
# is forked from Joric's pywallet.py whose licensing information follows,
#
# [1] https://github.com/jackjack-jj/pywallet
#
# PyWallet 1.2.1 (Public Domain)
# http://github.com/joric/pywallet
# Most of the actual PyWallet code placed in the public domain.
# PyWallet includes portions of free software, listed below.
#
# BitcoinTools (wallet.dat handling code, MIT License)
# https://github.com/gavinandresen/bitcointools
# Copyright (c) 2010 Gavin Andresen
#
# python-ecdsa (EC_KEY implementation, MIT License)
# http://github.com/warner/python-ecdsa
# "python-ecdsa" Copyright (c) 2010 Brian Warner
# Portions written in 2005 by Peter Pearson and placed in the public domain.
#
# SlowAES (aes.py code, Apache 2 License)
# http://code.google.com/p/slowaes/
# Copyright (c) 2008, Josh Davis (http://www.josh-davis.org),
# Alex Martelli (http://www.aleax.it)
# Ported from C code written by Laurent Haan (http://www.progressive-coding.com)

try:
        from bsddb.db import *
except:
        from bsddb3.db import *

import os, sys, time

try:
        import json
except:
        try:
                 import simplejson as json
        except:
                 sys.stdout.write("json or simplejson package is needed")

import logging
import struct
import traceback
import types
import string
import hashlib
import math
import binascii

addrtype = 0
json_db = {}

def hash_160(public_key):
        md = hashlib.new('ripemd160')
        md.update(hashlib.sha256(public_key).digest())
        return md.digest()

def public_key_to_bc_address(public_key):
        h160 = hash_160(public_key)
        return hash_160_to_bc_address(h160)

def hash_160_to_bc_address(h160):
        vh160 = chr(addrtype) + h160
        h = Hash(vh160)
        addr = vh160 + h[0:4]
        return b58encode(addr)

__b58chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
__b58base = len(__b58chars)

def b58encode(v):
        """ encode v, which is a string of bytes, to base58.
        """

        long_value = 0
        for (i, c) in enumerate(v[::-1]):
                long_value += (256 ** i) * ord(c)

        result = ''
        while long_value >= __b58base:
                div, mod = divmod(long_value, __b58base)
                result = __b58chars[mod] + result
                long_value = div
        result = __b58chars[long_value] + result

        # Bitcoin does a little leading-zero-compression:
        # leading 0-bytes in the input become leading-1s
        nPad = 0
        for c in v:
                if c == '\0': nPad += 1
                else: break

        return (__b58chars[0] * nPad) + result

# end of bitcointools base58 implementation

def Hash(data):
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# bitcointools wallet.dat handling code

class SerializationError(Exception):
        """ Thrown when there's a problem deserializing or serializing """

def bool_to_int(b):
        if b:
                return 1
        return 0

class BCDataStream(object):
        def __init__(self):
                self.input = None
                self.read_cursor = 0

        def clear(self):
                self.input = None
                self.read_cursor = 0

        def write(self, bytes):  # Initialize with string of bytes
                if self.input is None:
                        self.input = bytes
                else:
                        self.input += bytes

        def map_file(self, file, start):  # Initialize with bytes from file
                self.input = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
                self.read_cursor = start
        def seek_file(self, position):
                self.read_cursor = position
        def close_file(self):
                self.input.close()

        def read_string(self):
                # Strings are encoded depending on length:
                # 0 to 252 :    1-byte-length followed by bytes (if any)
                # 253 to 65,535 : byte'253' 2-byte-length followed by bytes
                # 65,536 to 4,294,967,295 : byte '254' 4-byte-length followed by bytes
                # ... and the Bitcoin client is coded to understand:
                # greater than 4,294,967,295 : byte '255' 8-byte-length followed by bytes of string
                # ... but I don't think it actually handles any strings that big.
                if self.input is None:
                        raise SerializationError("call write(bytes) before trying to deserialize")

                try:
                        length = self.read_compact_size()
                except IndexError:
                        raise SerializationError("attempt to read past end of buffer")

                return self.read_bytes(length)

        def write_string(self, string):
                # Length-encoded as with read-string
                self.write_compact_size(len(string))
                self.write(string)

        def read_bytes(self, length):
                try:
                        result = self.input[self.read_cursor:self.read_cursor + length]
                        self.read_cursor += length
                        return result
                except IndexError:
                        raise SerializationError("attempt to read past end of buffer")

                return ''

        def read_boolean(self): return self.read_bytes(1)[0] != chr(0)
        def read_int16(self): return self._read_num('<h')
        def read_uint16(self): return self._read_num('<H')
        def read_int32(self): return self._read_num('<i')
        def read_uint32(self): return self._read_num('<I')
        def read_int64(self): return self._read_num('<q')
        def read_uint64(self): return self._read_num('<Q')

        def write_boolean(self, val): return self.write(chr(bool_to_int(val)))
        def write_int16(self, val): return self._write_num('<h', val)
        def write_uint16(self, val): return self._write_num('<H', val)
        def write_int32(self, val): return self._write_num('<i', val)
        def write_uint32(self, val): return self._write_num('<I', val)
        def write_int64(self, val): return self._write_num('<q', val)
        def write_uint64(self, val): return self._write_num('<Q', val)

        def read_compact_size(self):
                size = self.input[self.read_cursor]
                if isinstance(size, str):
                    size = ord(self.input[self.read_cursor])
                self.read_cursor += 1
                if size == 253:
                        size = self._read_num('<H')
                elif size == 254:
                        size = self._read_num('<I')
                elif size == 255:
                        size = self._read_num('<Q')
                return size

        def write_compact_size(self, size):
                if size < 0:
                        raise SerializationError("attempt to write size < 0")
                elif size < 253:
                         self.write(chr(size))
                elif size < 2 ** 16:
                        self.write('\xfd')
                        self._write_num('<H', size)
                elif size < 2 ** 32:
                        self.write('\xfe')
                        self._write_num('<I', size)
                elif size < 2 ** 64:
                        self.write('\xff')
                        self._write_num('<Q', size)

        def _read_num(self, format):
                (i,) = struct.unpack_from(format, self.input, self.read_cursor)
                self.read_cursor += struct.calcsize(format)
                return i

        def _write_num(self, format, num):
                s = struct.pack(format, num)
                self.write(s)

def open_wallet(walletfile):
        db = DB()
        DB_TYPEOPEN = DB_RDONLY
        flags = DB_THREAD | DB_TYPEOPEN
        try:
                r = db.open(walletfile, "main", DB_BTREE, flags)
        except DBError as e:
                logging.error("{0}:{1}".format(e[0], e[1]))
                r = True

        if r is not None:
                logging.error("Couldn't open wallet.dat/main. Try quitting Bitcoin and running this again.")
                sys.exit(1)

        return db

def parse_wallet(db, item_callback):
        kds = BCDataStream()
        vds = BCDataStream()

        for (key, value) in db.items():
                d = { }

                kds.clear(); kds.write(key)
                vds.clear(); vds.write(value)

                type = kds.read_string()

                d["__key__"] = key
                d["__value__"] = value
                d["__type__"] = type

                try:
                        if type == "key":
                                d['public_key'] = kds.read_bytes(kds.read_compact_size())
                                d['private_key'] = vds.read_bytes(vds.read_compact_size())
                        elif type == "wkey":
                                d['public_key'] = kds.read_bytes(kds.read_compact_size())
                                d['private_key'] = vds.read_bytes(vds.read_compact_size())
                                d['created'] = vds.read_int64()
                                d['expires'] = vds.read_int64()
                                d['comment'] = vds.read_string()
                        elif type == "ckey":
                                d['public_key'] = kds.read_bytes(kds.read_compact_size())
                                d['encrypted_private_key'] = vds.read_bytes(vds.read_compact_size())
                        elif type == "mkey":
                                d['nID'] = kds.read_uint32()
                                d['encrypted_key'] = vds.read_string()
                                d['salt'] = vds.read_string()
                                d['nDerivationMethod'] = vds.read_uint32()
                                d['nDerivationIterations'] = vds.read_uint32()
                                d['otherParams'] = vds.read_string()

                        item_callback(type, d)

                except Exception:
                        traceback.print_exc()
                        sys.stdout.write("ERROR parsing wallet.dat, type %s" % type)
                        sys.stdout.write("key data: %s" % key)
                        sys.stdout.write("key data in hex: %s" % key.encode('hex_codec'))
                        sys.stdout.write("value data in hex: %s" % value.encode('hex_codec'))
                        sys.exit(1)


# end of bitcointools wallet.dat handling code

# wallet.dat reader / writer

def read_wallet(json_db, walletfile):
        crypted = False

        db = open_wallet(walletfile)

        json_db['keys'] = []
        json_db['ckey'] = []
        json_db['mkey'] = {}

        def item_callback(type, d):
                if type == "key":
                        addr = public_key_to_bc_address(d['public_key'])
                        compressed = d['public_key'][0] != '\04'
                        sec = SecretToASecret(PrivKeyToSecret(d['private_key']), compressed)
                        hexsec = ASecretToSecret(sec).encode('hex')
                        json_db['keys'].append({'addr' : addr, 'sec' : sec, 'hexsec' : hexsec, 'secret' : hexsec, 'pubkey':d['public_key'].encode('hex'), 'compressed':compressed, 'private':d['private_key'].encode('hex')})

                elif type == "wkey":
                        if not json_db.has_key('wkey'): json_db['wkey'] = []
                        json_db['wkey']['created'] = d['created']

                elif type == "ckey":
                        crypted = True
                        compressed = d['public_key'][0] != '\04'
                        json_db['keys'].append({ 'pubkey': d['public_key'].encode('hex'), 'addr': public_key_to_bc_address(d['public_key']), 'encrypted_privkey':  d['encrypted_private_key'].encode('hex_codec'), 'compressed':compressed})

                elif type == "mkey":
                        json_db['mkey']['nID'] = d['nID']
                        json_db['mkey']['encrypted_key'] = d['encrypted_key'].encode('hex_codec')
                        json_db['mkey']['salt'] = d['salt'].encode('hex_codec')
                        json_db['mkey']['nDerivationMethod'] = d['nDerivationMethod']
                        json_db['mkey']['nDerivationIterations'] = d['nDerivationIterations']
                        json_db['mkey']['otherParams'] = d['otherParams']

                else:
                        json_db[type] = 'unsupported'

        parse_wallet(db, item_callback)

        db.close()

        crypted = 'salt' in json_db['mkey']

        if not crypted:
                sys.stdout.write("%s : this wallet is not encrypted!" % walletfile)
                return -1

        for k in json_db['keys']:
                if k['compressed'] and 'secret' in k:
                        k['secret'] += "01"

        return {'crypted':crypted}



if __name__ == '__main__':


    if len(sys.argv) < 2:
        print >> sys.stderr, "Usage: %s [Bitcoin/Litecoin/PRiVCY wallet (.dat) files]" % sys.argv[0]
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        filename = sys.argv[i]
        if read_wallet(json_db, filename) == -1:
            continue

        cry_master = json_db['mkey']['encrypted_key'].decode('hex')
        cry_salt = json_db['mkey']['salt'].decode('hex')
        cry_rounds = json_db['mkey']['nDerivationIterations']
        cry_method = json_db['mkey']['nDerivationMethod']

        crypted = 'salt' in json_db['mkey']

        if not crypted:
                print >> sys.stderr, "%s : this wallet is not encrypted" % os.path.basename(filename)
                continue

        for k in json_db['keys']:
            pass  # dirty hack but it works!

        ckey = k['encrypted_privkey']
        public_key = k['pubkey']
        cry_master = json_db['mkey']['encrypted_key'][-64:]  # last two aes blocks should be enough
        cry_salt = json_db['mkey']['salt']

        sys.stdout.write("$bitcoin$%s$%s$%s$%s$%s$%s$%s$%s$%s\n" %
                (len(cry_master), cry_master, len(cry_salt),
                cry_salt, cry_rounds, len(ckey), ckey, len(public_key),
                public_key))
