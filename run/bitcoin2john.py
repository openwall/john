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

missing_dep = []

try:
        from bsddb.db import *
except:
        from bsddb3.db import *
        # missing_dep.append('bsddb')

import os, sys, time
pyw_filename = sys.argv[0].split('/')[len(sys.argv[0].split('/')) - 1]
pyw_path = os.getcwd()

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
import random
import math
import binascii

max_version = 81000
addrtype = 0
json_db = {}
private_keys = []
private_hex_keys = []
passphrase = ""
global_merging_message = ["", ""]

wallet_dir = ""
wallet_name = ""

ko = 1e3
kio = 1024
Mo = 1e6
Mio = 1024 ** 2
Go = 1e9
Gio = 1024 ** 3
To = 1e12
Tio = 1024 ** 4

prekeys = [binascii.unhexlify("308201130201010420"), binascii.unhexlify("308201120201010420")]
postkeys = [binascii.unhexlify("a081a530"), binascii.unhexlify("81a530")]

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

def bc_address_to_hash_160(addr):
        bytes = b58decode(addr, 25)
        return bytes[1:21]

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

def b58decode(v, length):
        """ decode v into a string of len bytes
        """
        long_value = 0
        for (i, c) in enumerate(v[::-1]):
                long_value += __b58chars.find(c) * (__b58base ** i)

        result = ''
        while long_value >= 256:
                div, mod = divmod(long_value, 256)
                result = chr(mod) + result
                long_value = div
        result = chr(long_value) + result

        nPad = 0
        for c in v:
                if c == __b58chars[0]: nPad += 1
                else: break

        result = chr(0) * nPad + result
        if length is not None and len(result) != length:
                return None

        return result

# end of bitcointools base58 implementation

def Hash(data):
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

# bitcointools wallet.dat handling code

def create_env(db_dir):
        db_env = DBEnv(0)
        r = db_env.open(db_dir, (DB_CREATE | DB_INIT_LOCK | DB_INIT_LOG | DB_INIT_MPOOL | DB_INIT_TXN | DB_THREAD | DB_RECOVER))
        return db_env

def parse_CAddress(vds):
        d = {'ip':'0.0.0.0', 'port':0, 'nTime': 0}
        try:
                d['nVersion'] = vds.read_int32()
                d['nTime'] = vds.read_uint32()
                d['nServices'] = vds.read_uint64()
                d['pchReserved'] = vds.read_bytes(12)
                d['ip'] = socket.inet_ntoa(vds.read_bytes(4))
                d['port'] = vds.read_uint16()
        except:
                pass
        return d

def deserialize_CAddress(d):
        return d['ip'] + ":" + str(d['port'])

def parse_BlockLocator(vds):
        d = { 'hashes' : [] }
        nHashes = vds.read_compact_size()
        for i in xrange(nHashes):
                d['hashes'].append(vds.read_bytes(32))
                return d

def deserialize_BlockLocator(d):
  result = "Block Locator top: " + d['hashes'][0][::-1].encode('hex_codec')
  return result

def parse_setting(setting, vds):
        if setting[0] == "f":  # flag (boolean) settings
                return str(vds.read_boolean())
        elif setting[0:4] == "addr":  # CAddress
                d = parse_CAddress(vds)
                return deserialize_CAddress(d)
        elif setting == "nTransactionFee":
                return vds.read_int64()
        elif setting == "nLimitProcessors":
                return vds.read_int32()
        return 'unknown setting'

class SerializationError(Exception):
        """ Thrown when there's a problem deserializing or serializing """

def ts():
        return int(time.mktime(datetime.now().timetuple()))

def check_postkeys(key, postkeys):
        for i in postkeys:
                if key[:len(i)] == i:
                        return True
        return False

def one_element_in(a, string):
        for i in a:
                if i in string:
                        return True
        return False

def first_read(device, size, prekeys, inc=10000):
        t0 = ts() - 1
        try:
                fd = os.open (device, os.O_RDONLY)
        except:
                sys.stdout.write("Can't open %s, check the path or try as root" % device)
                exit(0)
        prekey = prekeys[0]
        data = ""
        i = 0
        data = os.read (fd, i)
        before_contained_key = False
        contains_key = False
        ranges = []

        while i < int(size):
                if i % (10 * Mio) > 0 and i % (10 * Mio) <= inc:
                        sys.stdout.write("\n%.2f/%.2f Go" % (i / 1e9, size / 1e9))
                        t = ts()
                        speed = i / (t - t0)
                        ETAts = size / speed + t0
                        d = datetime.fromtimestamp(ETAts)
                        sys.stdout.write(d.strftime("   ETA: %H:%M:%S"))

                try:
                        data = os.read (fd, inc)
                except Exception as exc:
                        os.lseek(fd, inc, os.SEEK_CUR)
                        sys.stdout.write(str(exc))
                        i += inc
                        continue

                contains_key = one_element_in(prekeys, data)

                if not before_contained_key and contains_key:
                        ranges.append(i)

                if before_contained_key and not contains_key:
                        ranges.append(i)

                before_contained_key = contains_key

                i += inc

        os.close (fd)
        return ranges

def shrink_intervals(device, ranges, prekeys, inc=1000):
        prekey = prekeys[0]
        nranges = []
        fd = os.open (device, os.O_RDONLY)
        for j in range(len(ranges) / 2):
                before_contained_key = False
                contains_key = False
                bi = ranges[2 * j]
                bf = ranges[2 * j + 1]

                mini_blocks = []
                k = bi
                while k <= bf + len(prekey) + 1:
                        mini_blocks.append(k)
                        k += inc
                        mini_blocks.append(k)

                for k in range(len(mini_blocks) / 2):
                        mini_blocks[2 * k] -= len(prekey) + 1
                        mini_blocks[2 * k + 1] += len(prekey) + 1


                        bi = mini_blocks[2 * k]
                        bf = mini_blocks[2 * k + 1]

                        os.lseek(fd, bi, 0)

                        data = os.read(fd, bf - bi + 1)
                        contains_key = one_element_in(prekeys, data)

                        if not before_contained_key and contains_key:
                                nranges.append(bi)

                        if before_contained_key and not contains_key:
                                nranges.append(bi + len(prekey) + 1 + len(prekey) + 1)

                        before_contained_key = contains_key

        os.close (fd)

        return nranges

def find_offsets(device, ranges, prekeys):
        prekey = prekeys[0]
        list_offsets = []
        to_read = 0
        fd = os.open (device, os.O_RDONLY)
        for i in range(len(ranges) / 2):
                bi = ranges[2 * i] - len(prekey) - 1
                os.lseek(fd, bi, 0)
                bf = ranges[2 * i + 1] + len(prekey) + 1
                to_read += bf - bi + 1
                buf = ""
                for j in range(len(prekey)):
                        buf += "\x00"
                curs = bi

                while curs <= bf:
                        data = os.read(fd, 1)
                        buf = buf[1:] + data
                        if buf in prekeys:
                                list_offsets.append(curs)
                        curs += 1

        os.close (fd)

        return [to_read, list_offsets]

def read_keys(device, list_offsets):
        found_hexkeys = []
        fd = os.open (device, os.O_RDONLY)
        for offset in list_offsets:
                os.lseek(fd, offset + 1, 0)
                data = os.read(fd, 40)
                hexkey = data[1:33].encode('hex')
                after_key = data[33:39].encode('hex')
                if hexkey not in found_hexkeys and check_postkeys(after_key.decode('hex'), postkeys):
                        found_hexkeys.append(hexkey)

        os.close (fd)

        return found_hexkeys


def md5_2(a):
        return hashlib.md5(a).digest()

def md5_file(nf):
        fichier = file(nf, 'r').read()
        return md5_2(fichier)


class KEY:

         def __init__ (self):
                  self.prikey = None
                  self.pubkey = None

         def generate (self, secret=None):
                  if secret:
                                exp = int ('0x' + secret.encode ('hex'), 16)
                                self.prikey = ecdsa.SigningKey.from_secret_exponent (exp, curve=secp256k1)
                  else:
                                self.prikey = ecdsa.SigningKey.generate (curve=secp256k1)
                  self.pubkey = self.prikey.get_verifying_key()
                  return self.prikey.to_der()

         def set_privkey (self, key):
                  if len(key) == 279:
                                seq1, rest = der.remove_sequence (key)
                                integer, rest = der.remove_integer (seq1)
                                octet_str, rest = der.remove_octet_string (rest)
                                tag1, cons1, rest, = der.remove_constructed (rest)
                                tag2, cons2, rest, = der.remove_constructed (rest)
                                point_str, rest = der.remove_bitstring (cons2)
                                self.prikey = ecdsa.SigningKey.from_string(octet_str, curve=secp256k1)
                  else:
                                self.prikey = ecdsa.SigningKey.from_der (key)

         def set_pubkey (self, key):
                  key = key[1:]
                  self.pubkey = ecdsa.VerifyingKey.from_string (key, curve=secp256k1)

         def get_privkey (self):
                  _p = self.prikey.curve.curve.p ()
                  _r = self.prikey.curve.generator.order ()
                  _Gx = self.prikey.curve.generator.x ()
                  _Gy = self.prikey.curve.generator.y ()
                  encoded_oid2 = der.encode_oid (*(1, 2, 840, 10045, 1, 1))
                  encoded_gxgy = "\x04" + ("%64x" % _Gx).decode('hex') + ("%64x" % _Gy).decode('hex')
                  param_sequence = der.encode_sequence (
                                ecdsa.der.encode_integer(1),
                                        der.encode_sequence (
                                        encoded_oid2,
                                        der.encode_integer (_p),
                                ),
                                der.encode_sequence (
                                        der.encode_octet_string("\x00"),
                                        der.encode_octet_string("\x07"),
                                ),
                                der.encode_octet_string (encoded_gxgy),
                                der.encode_integer (_r),
                                der.encode_integer (1),
                  );
                  encoded_vk = "\x00\x04" + self.pubkey.to_string ()
                  return der.encode_sequence (
                                der.encode_integer (1),
                                der.encode_octet_string (self.prikey.to_string ()),
                                der.encode_constructed (0, param_sequence),
                                der.encode_constructed (1, der.encode_bitstring (encoded_vk)),
                  )

         def get_pubkey (self):
                  return "\x04" + self.pubkey.to_string()

         def sign (self, hash):
                  sig = self.prikey.sign_digest (hash, sigencode=ecdsa.util.sigencode_der)
                  return sig.encode('hex')

         def verify (self, hash, sig):
                  return self.pubkey.verify_digest (sig, hash, sigdecode=ecdsa.util.sigdecode_der)

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

def open_wallet(walletfile, writable=False):
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

def inversetxid(txid):
        if len(txid) is not 64:
                sys.stdout.write("Bad txid")
                return "CORRUPTEDTXID:" + txid
        new_txid = ""
        for i in range(32):
                new_txid += txid[62 - 2 * i];
                new_txid += txid[62 - 2 * i + 1];
        return new_txid

def parse_wallet(db, item_callback):
        kds = BCDataStream()
        vds = BCDataStream()


        def parse_TxIn(vds):
                d = {}
                d['prevout_hash'] = vds.read_bytes(32).encode('hex')
                d['prevout_n'] = vds.read_uint32()
                d['scriptSig'] = vds.read_bytes(vds.read_compact_size()).encode('hex')
                d['sequence'] = vds.read_uint32()
                return d


        def parse_TxOut(vds):
                d = {}
                d['value'] = vds.read_int64() / 1e8
                d['scriptPubKey'] = vds.read_bytes(vds.read_compact_size()).encode('hex')
                return d


        for (key, value) in db.items():
                d = { }

                kds.clear(); kds.write(key)
                vds.clear(); vds.write(value)

                type = kds.read_string()

                d["__key__"] = key
                d["__value__"] = value
                d["__type__"] = type

                try:
                        if type == "tx":
                                d["tx_id"] = inversetxid(kds.read_bytes(32).encode('hex_codec'))
                                start = vds.read_cursor
                                d['version'] = vds.read_int32()
                                n_vin = vds.read_compact_size()
                                d['txIn'] = []
                                for i in xrange(n_vin):
                                        d['txIn'].append(parse_TxIn(vds))
                                n_vout = vds.read_compact_size()
                                d['txOut'] = []
                                for i in xrange(n_vout):
                                        d['txOut'].append(parse_TxOut(vds))
                                d['lockTime'] = vds.read_uint32()
                                d['tx'] = vds.input[start:vds.read_cursor].encode('hex_codec')
                                d['txv'] = value.encode('hex_codec')
                                d['txk'] = key.encode('hex_codec')
                        elif type == "name":
                                d['hash'] = kds.read_string()
                                d['name'] = vds.read_string()
                        elif type == "version":
                                d['version'] = vds.read_uint32()
                        elif type == "minversion":
                                d['minversion'] = vds.read_uint32()
                        elif type == "setting":
                                d['setting'] = kds.read_string()
                                d['value'] = parse_setting(d['setting'], vds)
                        elif type == "key":
                                d['public_key'] = kds.read_bytes(kds.read_compact_size())
                                d['private_key'] = vds.read_bytes(vds.read_compact_size())
                        elif type == "wkey":
                                d['public_key'] = kds.read_bytes(kds.read_compact_size())
                                d['private_key'] = vds.read_bytes(vds.read_compact_size())
                                d['created'] = vds.read_int64()
                                d['expires'] = vds.read_int64()
                                d['comment'] = vds.read_string()
                        elif type == "defaultkey":
                                d['key'] = vds.read_bytes(vds.read_compact_size())
                        elif type == "pool":
                                d['n'] = kds.read_int64()
                                d['nVersion'] = vds.read_int32()
                                d['nTime'] = vds.read_int64()
                                d['public_key'] = vds.read_bytes(vds.read_compact_size())
                        elif type == "acc":
                                d['account'] = kds.read_string()
                                d['nVersion'] = vds.read_int32()
                                d['public_key'] = vds.read_bytes(vds.read_compact_size())
                        elif type == "acentry":
                                d['account'] = kds.read_string()
                                d['n'] = kds.read_uint64()
                                d['nVersion'] = vds.read_int32()
                                d['nCreditDebit'] = vds.read_int64()
                                d['nTime'] = vds.read_int64()
                                d['otherAccount'] = vds.read_string()
                                d['comment'] = vds.read_string()
                        elif type == "bestblock":
                                d['nVersion'] = vds.read_int32()
                                # d.update(parse_BlockLocator(vds))
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

def read_wallet(json_db, walletfile, print_wallet, print_wallet_transactions, transaction_filter, include_balance, vers= -1, FillPool=False):
        global passphrase
        crypted = False

        private_keys = []
        private_hex_keys = []

        if vers > -1:
                global addrtype
                oldaddrtype = addrtype
                addrtype = vers

        db = open_wallet(walletfile, writable=FillPool)

        json_db['keys'] = []
        json_db['pool'] = []
        json_db['tx'] = []
        json_db['names'] = {}
        json_db['ckey'] = []
        json_db['mkey'] = {}

        def item_callback(type, d):
                if type == "tx":
                        json_db['tx'].append({"tx_id" : d['tx_id'], "txin" : d['txIn'], "txout" : d['txOut'], "tx_v" : d['txv'], "tx_k" : d['txk']})

                elif type == "name":
                        json_db['names'][d['hash']] = d['name']

                elif type == "version":
                        json_db['version'] = d['version']

                elif type == "minversion":
                        json_db['minversion'] = d['minversion']

                elif type == "setting":
                        if not json_db.has_key('settings'): json_db['settings'] = {}
                        json_db["settings"][d['setting']] = d['value']

                elif type == "defaultkey":
                        json_db['defaultkey'] = public_key_to_bc_address(d['key'])

                elif type == "key":
                        addr = public_key_to_bc_address(d['public_key'])
                        compressed = d['public_key'][0] != '\04'
                        sec = SecretToASecret(PrivKeyToSecret(d['private_key']), compressed)
                        hexsec = ASecretToSecret(sec).encode('hex')
                        private_keys.append(sec)
                        json_db['keys'].append({'addr' : addr, 'sec' : sec, 'hexsec' : hexsec, 'secret' : hexsec, 'pubkey':d['public_key'].encode('hex'), 'compressed':compressed, 'private':d['private_key'].encode('hex')})

                elif type == "wkey":
                        if not json_db.has_key('wkey'): json_db['wkey'] = []
                        json_db['wkey']['created'] = d['created']

                elif type == "pool":
                        """     d['n'] = kds.read_int64()
                                d['nVersion'] = vds.read_int32()
                                d['nTime'] = vds.read_int64()
                                d['public_key'] = vds.read_bytes(vds.read_compact_size())"""
                        try:
                                json_db['pool'].append({'n': d['n'], 'addr': public_key_to_bc_address(d['public_key']), 'addr2': public_key_to_bc_address(d['public_key'].decode('hex')), 'addr3': public_key_to_bc_address(d['public_key'].encode('hex')), 'nTime' : d['nTime'], 'nVersion' : d['nVersion'], 'public_key_hex' : d['public_key'] })
                        except:
                                json_db['pool'].append({'n': d['n'], 'addr': public_key_to_bc_address(d['public_key']), 'nTime' : d['nTime'], 'nVersion' : d['nVersion'], 'public_key_hex' : d['public_key'].encode('hex') })

                elif type == "acc":
                        json_db['acc'] = d['account']
                        sys.stdout.write("Account %s (current key: %s)" % (d['account'], public_key_to_bc_address(d['public_key'])))

                elif type == "acentry":
                        json_db['acentry'] = (d['account'], d['nCreditDebit'], d['otherAccount'], time.ctime(d['nTime']), d['n'], d['comment'])

                elif type == "bestblock":
                        pass
                        # json_db['bestblock'] = d['hashes'][0][::-1].encode('hex_codec')

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

                        if passphrase:
                                res = crypter.SetKeyFromPassphrase(passphrase, d['salt'], d['nDerivationIterations'], d['nDerivationMethod'])
                                if res == 0:
                                        logging.error("Unsupported derivation method")
                                        sys.exit(1)
                                masterkey = crypter.Decrypt(d['encrypted_key'])
                                crypter.SetKey(masterkey)

                else:
                        json_db[type] = 'unsupported'

        parse_wallet(db, item_callback)


        nkeys = len(json_db['keys'])
        i = 0
        for k in json_db['keys']:
                i += 1
                addr = k['addr']
                if addr in json_db['names'].keys():
                        k["label"] = json_db['names'][addr]
                        k["reserve"] = 0

        db.close()

        crypted = 'salt' in json_db['mkey']

        if not crypted:
                sys.stdout.write("%s : this wallet is not encrypted!" % walletfile)
                return -1

        for k in json_db['keys']:
                if k['compressed'] and 'secret' in k:
                        k['secret'] += "01"

        if vers > -1:
                addrtype = oldaddrtype

        return {'crypted':crypted}



if __name__ == '__main__':


    if len(sys.argv) < 2:
        print >> sys.stderr, "Usage: %s [Bitcoin/Litecoin/PRiVCY wallet (.dat) files]" % sys.argv[0]
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        filename = sys.argv[i]
        if read_wallet(json_db, filename, True, True, "", False) == -1:
            continue

        # Use btcrecover/btcrpass.py -> "Bitcoin Core" logic in case of problems
        # with the code in this file.
        minversion = json_db.get("minversion", None)
        if minversion and minversion > max_version:
            sys.stderr.write("WARNING: %s has previously unseen minversion '%s'!\n" %
                             (os.path.basename(filename), minversion))

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
