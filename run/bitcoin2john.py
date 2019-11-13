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

import binascii
import hashlib
import logging
import struct
import sys
import traceback

try:
    from bsddb.db import *
except:
    try:
        from bsddb3.db import *
    except:
        sys.stderr.write("Error: This script needs bsddb3 to be installed!\n")
        sys.exit(1)


addrtype = 0
json_db = {}

def hexstr(bytestr):
    return binascii.hexlify(bytestr).decode('ascii')

def hash_160(public_key):
        md = hashlib.new('ripemd160')
        md.update(hashlib.sha256(public_key).digest())
        return md.digest()

def public_key_to_bc_address(public_key):
        h160 = hash_160(public_key)
        return hash_160_to_bc_address(h160)

def hash_160_to_bc_address(h160):
        vh160 = struct.pack('B', addrtype) + h160
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
                if isinstance(c, str):
                    c = ord(c)
                long_value += (256 ** i) * c

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
                if c == '\0' or c == 0: nPad += 1
                else: break

        return (__b58chars[0] * nPad) + result

# end of bitcointools base58 implementation

def Hash(data):
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# bitcointools wallet.dat handling code

class SerializationError(Exception):
        """ Thrown when there's a problem deserializing or serializing """

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

                return self.read_bytes(length).decode('ascii')

        def read_bytes(self, length):
                try:
                        result = self.input[self.read_cursor:self.read_cursor + length]
                        self.read_cursor += length
                        return result
                except IndexError:
                        raise SerializationError("attempt to read past end of buffer")

                return ''

        def read_uint32(self): return self._read_num('<I')
        def read_int64(self): return self._read_num('<q')

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

        def _read_num(self, format):
                (i,) = struct.unpack_from(format, self.input, self.read_cursor)
                self.read_cursor += struct.calcsize(format)
                return i

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
                                d['encrypted_key'] = vds.read_bytes(vds.read_compact_size())
                                d['salt'] = vds.read_bytes(vds.read_compact_size())
                                d['nDerivationMethod'] = vds.read_uint32()
                                d['nDerivationIterations'] = vds.read_uint32()
                                d['otherParams'] = vds.read_string()

                        item_callback(type, d)

                except Exception:
                        traceback.print_exc()
                        sys.stderr.write("ERROR parsing wallet.dat, type %s\n" % type)
                        sys.stderr.write("key data in hex: %s\n" % hexstr(key))
                        sys.stderr.write("value data in hex: %s\n" % hexstr(value))
                        sys.exit(1)


# end of bitcointools wallet.dat handling code

# wallet.dat reader / writer

def read_wallet(json_db, walletfile):
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
                        json_db['keys'].append({'addr': addr, 'sec': sec, 'hexsec': hexsec, 'secret': hexsec, 'pubkey': hexstr(d['public_key']), 'compressed': compressed, 'private': hexstr(d['private_key'])})

                elif type == "wkey":
                        if not json_db.has_key('wkey'): json_db['wkey'] = []
                        json_db['wkey']['created'] = d['created']

                elif type == "ckey":
                        compressed = d['public_key'][0] != '\04'
                        json_db['keys'].append({'pubkey': hexstr(d['public_key']), 'addr': public_key_to_bc_address(d['public_key']), 'encrypted_privkey':  hexstr(d['encrypted_private_key']), 'compressed':compressed})

                elif type == "mkey":
                        json_db['mkey']['nID'] = d['nID']
                        json_db['mkey']['encrypted_key'] = hexstr(d['encrypted_key'])
                        json_db['mkey']['salt'] = hexstr(d['salt'])
                        json_db['mkey']['nDerivationMethod'] = d['nDerivationMethod']
                        json_db['mkey']['nDerivationIterations'] = d['nDerivationIterations']
                        json_db['mkey']['otherParams'] = d['otherParams']

                else:
                        json_db[type] = 'unsupported'

        parse_wallet(db, item_callback)

        db.close()

        crypted = 'salt' in json_db['mkey']

        if not crypted:
                sys.stderr.write("%s: this wallet is not encrypted\n" % walletfile)
                return -1

        for k in json_db['keys']:
                if k['compressed'] and 'secret' in k:
                        k['secret'] += "01"

        return {'crypted':crypted}


if __name__ == '__main__':

    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [Bitcoin/Litecoin/PRiVCY wallet (.dat) files]\n" % sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        filename = sys.argv[i]
        if read_wallet(json_db, filename) == -1:
            continue

        cry_master = binascii.unhexlify(json_db['mkey']['encrypted_key'])
        cry_salt = binascii.unhexlify(json_db['mkey']['salt'])
        cry_rounds = json_db['mkey']['nDerivationIterations']
        cry_method = json_db['mkey']['nDerivationMethod']

        crypted = 'salt' in json_db['mkey']

        if not crypted:
            sys.stderr.write("%s: this wallet is not encrypted\n" % filename)
            continue

        for k in json_db['keys']:
            pass  # dirty hack but it works!

        ckey = k['encrypted_privkey']
        public_key = k['pubkey']
        cry_master = json_db['mkey']['encrypted_key'][-64:]  # last two aes blocks should be enough
        cry_salt = json_db['mkey']['salt']

        sys.stdout.write("$bitcoin$%s$%s$%s$%s$%s$2$00$2$00\n" %
            (len(cry_master), cry_master, len(cry_salt), cry_salt, cry_rounds))
