#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Modified (for JtR) by Dhiru Kholia in December, 2014.
#
# This file is part of DPAPIck
# Windows DPAPI decryption & forensic toolkit
#
# Copyright (C) 2010, 2011 Cassidian SAS. All rights reserved.
# This document is the property of Cassidian SAS, it may not be copied or
# circulated without prior licence
#
# Author: Jean-Michel Picod <jmichel.p@gmail.com>
#
# This program is distributed under GPLv3 licence (see LICENCE.txt)

import os
import re
import sys
import struct
import array
import hashlib
try:
    import M2Crypto
except ImportError:
    sys.stderr.write("For additional functionality, please install python-m2crypto package.\n")
import cPickle
from optparse import OptionParser
from collections import defaultdict


class Eater(object):
    """This class is a helper for parsing binary structures."""

    def __init__(self, raw, offset=0, end=None, endianness="<"):
        self.raw = raw
        self.ofs = offset
        if end is None:
            end = len(raw)
        self.end = end
        self.endianness = endianness

    def prepare_fmt(self, fmt):
        """Internal use. Prepend endianness to the given format if it is not
        already specified.

        fmt is a format string for struct.unpack()

        Returns a tuple of the format string and the corresponding data size.

        """
        if fmt[0] not in ["<", ">", "!", "@"]:
            fmt = self.endianness+fmt
        return fmt, struct.calcsize(fmt)

    def read(self, fmt):
        """Parses data with the given format string without taking away bytes.

        Returns an array of elements or just one element depending on fmt.

        """
        fmt, sz = self.prepare_fmt(fmt)
        v = struct.unpack_from(fmt, self.raw, self.ofs)
        if len(v) == 1:
            v = v[0]
        return v

    def eat(self, fmt):
        """Parses data with the given format string.

        Returns an array of elements or just one element depending on fmt.

        """
        fmt, sz = self.prepare_fmt(fmt)
        v = struct.unpack_from(fmt, self.raw, self.ofs)
        if len(v) == 1:
            v = v[0]
        self.ofs += sz
        return v

    def eat_string(self, length):
        """Eats and returns a string of length characters"""
        return self.eat("%us" % length)

    def eat_length_and_string(self, fmt):
        """Eats and returns a string which length is obtained after eating
        an integer represented by fmt

        """
        l = self.eat(fmt)
        return self.eat_string(l)

    def pop(self, fmt):
        """Eats a structure represented by fmt from the end of raw data"""
        fmt, sz = self.prepare_fmt(fmt)
        self.end -= sz
        v = struct.unpack_from(fmt, self.raw, self.end)
        if len(v) == 1:
            v = v[0]
        return v

    def pop_string(self, length):
        """Pops and returns a string of length characters"""
        return self.pop("%us" % length)

    def pop_length_and_string(self, fmt):
        """Pops and returns a string which length is obtained after poping an
        integer represented by fmt.

        """
        l = self.pop(fmt)
        return self.pop_string(l)

    def remain(self):
        """Returns all the bytes that have not been eated nor poped yet."""
        return self.raw[self.ofs:self.end]

    def eat_sub(self, length):
        """Eats a sub-structure that is contained in the next length bytes"""
        sub = self.__class__(self.raw[self.ofs:self.ofs+length], endianness=self.endianness)
        self.ofs += length
        return sub

    def __nonzero__(self):
        return self.ofs < self.end


class DataStruct(object):
    """Don't use this class unless you know what you are doing!"""

    def __init__(self, raw=None):
        if raw is not None:
            self.parse(Eater(raw, endianness="<"))

    def parse(self, eater_obj):
        raise NotImplementedError("This function must be implemented in subclasses")


class DPAPIBlob(DataStruct):
    """Represents a DPAPI blob"""

    def __init__(self, raw=None):
        """Constructs a DPAPIBlob. If raw is set, automatically calls
            parse().

        """
        self.version = None
        self.provider = None
        self.mkguid = None
        self.mkversion = None
        self.flags = None
        self.description = None
        self.cipherAlgo = None
        self.keyLen = 0
        self.hmac = None
        self.strong = None
        self.hashAlgo = None
        self.hashLen = 0
        self.cipherText = None
        self.salt = None
        self.blob = None
        self.sign = None
        self.cleartext = None
        self.decrypted = False
        self.signComputed = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        """Parses the given data. May raise exceptions if incorrect data are
            given. You should not call this function yourself; DataStruct does

            data is a DataStruct object.
            Returns nothing.

        """
        self.version = data.eat("L")
        self.provider = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % data.eat("L2H8B")

        # For HMAC computation
        blobStart = data.ofs

        self.mkversion = data.eat("L")
        self.mkguid = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % data.eat("L2H8B")

        self.flags = data.eat("L")
        self.description = data.eat_length_and_string("L").decode("UTF-16LE").encode("utf-8")
        self.cipherAlgo = CryptoAlgo(data.eat("L"))
        self.keyLen = data.eat("L")
        self.salt = data.eat_length_and_string("L")
        self.strong = data.eat_length_and_string("L")
        self.hashAlgo = CryptoAlgo(data.eat("L"))
        self.hashLen = data.eat("L")
        self.hmac = data.eat_length_and_string("L")
        self.cipherText = data.eat_length_and_string("L")

        # For HMAC computation
        self.blob = data.raw[blobStart:data.ofs]
        self.sign = data.eat_length_and_string("L")

    def decrypt(self, masterkey, entropy=None, strongPassword=None):
        """Try to decrypt the blob. Returns True/False
        :rtype : bool
        :param masterkey: decrypted masterkey value
        :param entropy: optional entropy for decrypting the blob
        :param strongPassword: optional password for decrypting the blob
        """
        for algo in [CryptSessionKeyXP, CryptSessionKeyWin7]:
            try:
                sessionkey = algo(masterkey, self.salt, self.hashAlgo, entropy=entropy, strongPassword=strongPassword)
                key = CryptDeriveKey(sessionkey, self.cipherAlgo, self.hashAlgo)
                cipher = M2Crypto.EVP.Cipher(self.cipherAlgo.m2name, key[:self.cipherAlgo.keyLength],
                                             "\x00" * self.cipherAlgo.ivLength, M2Crypto.decrypt, 0)
                cipher.set_padding(1)
                self.cleartext = cipher.update(self.cipherText) + cipher.final()
                # check against provided HMAC
                self.signComputed = algo(masterkey, self.hmac, self.hashAlgo, entropy=entropy, strongPassword=self.blob)
                self.decrypted = self.signComputed == self.sign
                if self.decrypted:
                    return True
            except M2Crypto.EVP.EVPError:
                pass
        self.decrypted = False
        return self.decrypted

    def __repr__(self):
        s = ["DPAPI BLOB"]
        s.append("\n".join(["\tversion      = %(version)d",
                            "\tprovider     = %(provider)s",
                            "\tmkey         = %(mkguid)s",
                            "\tflags        = %(flags)#x",
                            "\tdescr        = %(description)s",
                            "\tcipherAlgo   = %(cipherAlgo)r",
                            "\thashAlgo     = %(hashAlgo)r"]) % self.__dict__)
        s.append("\tsalt         = %s" % self.salt.encode('hex'))
        s.append("\thmac         = %s" % self.hmac.encode('hex'))
        s.append("\tcipher       = %s" % self.cipherText.encode('hex'))
        s.append("\tsign         = %s" % self.sign.encode('hex'))
        if self.signComputed is not None:
            s.append("\tsignComputed = %s" % self.signComputed.encode('hex'))
        if self.cleartext is not None:
            s.append("\tcleartext    = %r" % self.cleartext)
        return "\n".join(s)


class CryptoAlgo(object):
    """This class is used to wrap Microsoft algorithm IDs with M2Crypto"""

    class Algo(object):
        def __init__(self, data):
            self.data = data

        def __getattr__(self, attr):
            if attr in self.data:
                return self.data[attr]
            raise AttributeError(attr)

    _crypto_data = {}

    @classmethod
    def add_algo(cls, algnum, **kargs):
        cls._crypto_data[algnum] = cls.Algo(kargs)

    @classmethod
    def get_algo(cls, algnum):
        return cls._crypto_data[algnum]

    def __init__(self, i):
        self.algnum = i
        self.algo = CryptoAlgo.get_algo(i)

    name = property(lambda self: self.algo.name)
    m2name = property(lambda self: self.algo.m2)
    keyLength = property(lambda self: self.algo.keyLength / 8)
    ivLength = property(lambda self: self.algo.IVLength / 8)
    blockSize = property(lambda self: self.algo.blockLength / 8)
    digestLength = property(lambda self: self.algo.digestLength / 8)

    def do_fixup_key(self, key):
        try:
            return self.algo.keyFixup.__call__(key)
        except AttributeError:
            return key

    def __repr__(self):
        return "%s [%#x]" % (self.algo.name, self.algnum)


def des_set_odd_parity(key):
    _lut = [1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14, 16, 16, 19,
            19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31, 32, 32, 35, 35, 37,
            37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47, 49, 49, 50, 50, 52, 52, 55,
            55, 56, 56, 59, 59, 61, 61, 62, 62, 64, 64, 67, 67, 69, 69, 70, 70, 73,
            73, 74, 74, 76, 76, 79, 79, 81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91,
            91, 93, 93, 94, 94, 97, 97, 98, 98, 100, 100, 103, 103, 104, 104, 107,
            107, 109, 109, 110, 110, 112, 112, 115, 115, 117, 117, 118, 118, 121,
            121, 122, 122, 124, 124, 127, 127, 128, 128, 131, 131, 133, 133, 134,
            134, 137, 137, 138, 138, 140, 140, 143, 143, 145, 145, 146, 146, 148,
            148, 151, 151, 152, 152, 155, 155, 157, 157, 158, 158, 161, 161, 162,
            162, 164, 164, 167, 167, 168, 168, 171, 171, 173, 173, 174, 174, 176,
            176, 179, 179, 181, 181, 182, 182, 185, 185, 186, 186, 188, 188, 191,
            191, 193, 193, 194, 194, 196, 196, 199, 199, 200, 200, 203, 203, 205,
            205, 206, 206, 208, 208, 211, 211, 213, 213, 214, 214, 217, 217, 218,
            218, 220, 220, 223, 223, 224, 224, 227, 227, 229, 229, 230, 230, 233,
            233, 234, 234, 236, 236, 239, 239, 241, 241, 242, 242, 244, 244, 247,
            247, 248, 248, 251, 251, 253, 253, 254, 254]
    tmp = array.array("B")
    tmp.fromstring(key)
    for i, v in enumerate(tmp):
        tmp[i] = _lut[v]
    return tmp.tostring()


CryptoAlgo.add_algo(0x6603, name="DES3", keyLength=192, IVLength=64, blockLength=64, m2="des_ede3_cbc",
                    keyFixup=des_set_odd_parity)
CryptoAlgo.add_algo(0x6609, name="DES2", keyLength=128, IVLength=64, blockLength=64, m2="des_ede_cbc",
                    keyFixup=des_set_odd_parity)
CryptoAlgo.add_algo(0x6611, name="AES", keyLength=128, IVLength=128, blockLength=128, m2="aes_128_cbc")
CryptoAlgo.add_algo(0x660e, name="AES-128", keyLength=128, IVLength=128, blockLength=128, m2="aes_128_cbc")
CryptoAlgo.add_algo(0x660f, name="AES-192", keyLength=192, IVLength=128, blockLength=128, m2="aes_192_cbc")
CryptoAlgo.add_algo(0x6610, name="AES-256", keyLength=256, IVLength=128, blockLength=128, m2="aes_256_cbc")
CryptoAlgo.add_algo(0x6601, name="DES", keyLength=64, IVLength=64, blockLength=64, m2="des_cbc",
                    keyFixup=des_set_odd_parity)

CryptoAlgo.add_algo(0x8009, name="HMAC", digestLength=160, blockLength=512)

CryptoAlgo.add_algo(0x8001, name="md2", digestLength=128, blockLength=128)
CryptoAlgo.add_algo(0x8002, name="md4", digestLength=128, blockLength=512)
CryptoAlgo.add_algo(0x8003, name="md5", digestLength=128, blockLength=512)

CryptoAlgo.add_algo(0x8004, name="sha1", digestLength=160, blockLength=512)
CryptoAlgo.add_algo(0x800c, name="sha256", digestLength=256, blockLength=512)
CryptoAlgo.add_algo(0x800d, name="sha384", digestLength=384, blockLength=1024)
CryptoAlgo.add_algo(0x800e, name="sha512", digestLength=512, blockLength=1024)


def CryptSessionKeyXP(masterkey, nonce, hashAlgo, entropy=None, strongPassword=None):
    """Computes the decryption key for XP DPAPI blob, given the masterkey and optional information.

    This implementation relies on a faulty implementation from Microsoft that does not respect the HMAC RFC.
    Instead of updating the inner pad, we update the outer pad...
    This algorithm is also used when checking the HMAC for integrity after decryption

    :param masterkey: decrypted masterkey (should be 64 bytes long)
    :param nonce: this is the nonce contained in the blob or the HMAC in the blob (integrity check)
    :param entropy: this is the optional entropy from CryptProtectData() API
    :param strongPassword: optional password used for decryption or the blob itself (integrity check)
    :returns: decryption key
    :rtype : str
    """
    if len(masterkey) > 20:
        masterkey = hashlib.sha1(masterkey).digest()

    masterkey += "\x00" * hashAlgo.blockSize
    ipad = "".join(chr(ord(masterkey[i]) ^ 0x36) for i in range(hashAlgo.blockSize))
    opad = "".join(chr(ord(masterkey[i]) ^ 0x5c) for i in range(hashAlgo.blockSize))
    digest = hashlib.new(hashAlgo.name)
    digest.update(ipad)
    digest.update(nonce)
    tmp = digest.digest()

    digest = hashlib.new(hashAlgo.name)
    digest.update(opad)
    digest.update(tmp)
    if entropy is not None:
        digest.update(entropy)
    if strongPassword is not None:
        digest.update(strongPassword)
    return digest.digest()


def CryptSessionKeyWin7(masterkey, nonce, hashAlgo, entropy=None, strongPassword=None):
    """Computes the decryption key for XP DPAPI blob, given the masterkey and optional information.

    This implementation relies on an RFC compliant HMAC implementation
    This algorithm is also used when checking the HMAC for integrity after decryption

    :param masterkey: decrypted masterkey (should be 64 bytes long)
    :param nonce: this is the nonce contained in the blob or the HMAC in the blob (integrity check)
    :param entropy: this is the optional entropy from CryptProtectData() API
    :param strongPassword: optional password used for decryption or the blob itself (integrity check)
    :returns: decryption key
    :rtype : str
    """
    if len(masterkey) > 20:
        masterkey = hashlib.sha1(masterkey).digest()

    digest = M2Crypto.EVP.HMAC(masterkey, hashAlgo.name)
    digest.update(nonce)
    if entropy is not None:
        digest.update(entropy)
    if strongPassword is not None:
        digest.update(strongPassword)
    return digest.final()


def CryptDeriveKey(h, cipherAlgo, hashAlgo):
    """Internal use. Mimics the corresponding native Microsoft function"""
    if len(h) > hashAlgo.blockSize:
        h = hashlib.new(hashAlgo.name, h).digest()
    if len(h) >= cipherAlgo.keyLength:
        return h
    h += "\x00" * hashAlgo.blockSize
    ipad = "".join(chr(ord(h[i]) ^ 0x36) for i in range(hashAlgo.blockSize))
    opad = "".join(chr(ord(h[i]) ^ 0x5c) for i in range(hashAlgo.blockSize))
    k = hashlib.new(hashAlgo.name, ipad).digest() + hashlib.new(hashAlgo.name, opad).digest()
    k = cipherAlgo.do_fixup_key(k)
    return k


def decrypt_lsa_key_nt5(lsakey, syskey):
    """This function decrypts the LSA key using the syskey"""
    dg = hashlib.md5()
    dg.update(syskey)
    for i in xrange(1000):
        dg.update(lsakey[60:76])
    arcfour = M2Crypto.RC4.RC4(dg.digest())
    deskey = arcfour.update(lsakey[12:60]) + arcfour.final()
    return [deskey[16 * x:16 * (x + 1)] for x in xrange(3)]


def decrypt_lsa_key_nt6(lsakey, syskey):
    """This function decrypts the LSA keys using the syskey"""
    dg = hashlib.sha256()
    dg.update(syskey)
    for i in xrange(1000):
        dg.update(lsakey[28:60])
    c = M2Crypto.EVP.Cipher(alg="aes_256_ecb", key=dg.digest(), iv="", op=M2Crypto.decrypt)
    c.set_padding(0)
    keys = c.update(lsakey[60:]) + c.final()
    size = struct.unpack_from("<L", keys)[0]
    keys = keys[16:16 + size]
    currentkey = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % struct.unpack("<L2H8B", keys[4:20])
    nb = struct.unpack("<L", keys[24:28])[0]
    off = 28
    kd = {}
    for i in xrange(nb):
        g = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % struct.unpack("<L2H8B", keys[off:off + 16])
        t, l = struct.unpack_from("<2L", keys[off + 16:])
        k = keys[off + 24:off + 24 + l]
        kd[g] = {"type": t, "key": k}
        off += 24 + l
    return (currentkey, kd)


def SystemFunction005(secret, key):
    """This function is used to decrypt LSA secrets.
    Reproduces the corresponding Windows internal function.
    Taken from creddump project https://code.google.com/p/creddump/
    """
    decrypted_data = ''
    j = 0
    algo = CryptoAlgo(0x6603)
    for i in range(0, len(secret), 8):
        enc_block = secret[i:i + 8]
        block_key = key[j:j + 7]
        des_key = []
        des_key.append(ord(block_key[0]) >> 1)
        des_key.append(((ord(block_key[0]) & 0x01) << 6) | (ord(block_key[1]) >> 2))
        des_key.append(((ord(block_key[1]) & 0x03) << 5) | (ord(block_key[2]) >> 3))
        des_key.append(((ord(block_key[2]) & 0x07) << 4) | (ord(block_key[3]) >> 4))
        des_key.append(((ord(block_key[3]) & 0x0F) << 3) | (ord(block_key[4]) >> 5))
        des_key.append(((ord(block_key[4]) & 0x1F) << 2) | (ord(block_key[5]) >> 6))
        des_key.append(((ord(block_key[5]) & 0x3F) << 1) | (ord(block_key[6]) >> 7))
        des_key.append(ord(block_key[6]) & 0x7F)
        des_key = algo.do_fixup_key("".join([chr(x << 1) for x in des_key]))

        cipher = M2Crypto.EVP.Cipher(alg="des_ecb", key=des_key, iv="", op=M2Crypto.decrypt)
        cipher.set_padding(0)
        decrypted_data += cipher.update(enc_block) + cipher.final()
        j += 7
        if len(key[j:j + 7]) < 7:
            j = len(key[j:j + 7])
    dec_data_len = struct.unpack("<L", decrypted_data[:4])[0]
    return decrypted_data[8:8 + dec_data_len]


def decrypt_lsa_secret(secret, lsa_keys):
    """This function replaces SystemFunction005 for newer Windows"""
    keyid = "%0x-%0x-%0x-%0x%0x-%0x%0x%0x%0x%0x%0x" % struct.unpack("<L2H8B", secret[4:20])
    if keyid not in lsa_keys:
        return None
    # algo = struct.unpack("<L", secret[20:24])[0]
    dg = hashlib.sha256()
    dg.update(lsa_keys[keyid]["key"])
    for i in xrange(1000):
        dg.update(secret[28:60])
    c = M2Crypto.EVP.Cipher(alg="aes_256_ecb", key=dg.digest(), iv="", op=M2Crypto.decrypt)
    c.set_padding(0)
    clear = c.update(secret[60:]) + c.final()
    size = struct.unpack_from("<L", clear)[0]
    return clear[16:16 + size]


def pbkdf2(passphrase, salt, keylen, iterations, digest='sha1'):
    """Implementation of PBKDF2 that allows specifying digest algorithm.

    Returns the corresponding expanded key which is keylen long.
    """
    buff = ""
    i = 1
    while len(buff) < keylen:
        U = salt + struct.pack("!L", i)
        i += 1
        derived = M2Crypto.EVP.hmac(passphrase, U, digest)
        for r in xrange(iterations - 1):
            actual = M2Crypto.EVP.hmac(passphrase, derived, digest)
            derived = ''.join([chr(ord(x) ^ ord(y)) for (x, y) in zip(derived, actual)])
        buff += derived
    return buff[:keylen]


def derivePwdHash(pwdhash, userSID, digest='sha1'):
    """Internal use. Computes the encryption key from a user's password hash"""
    return M2Crypto.EVP.hmac(pwdhash, (userSID + "\0").encode("UTF-16LE"), digest)


def dataDecrypt(cipherAlgo, hashAlgo, raw, encKey, iv, rounds):
    """Internal use. Decrypts data stored in DPAPI structures."""
    hname = {"HMAC": "sha1"}.get(hashAlgo.name, hashAlgo.name)
    derived = pbkdf2(encKey, iv, cipherAlgo.keyLength + cipherAlgo.ivLength, rounds, hname)
    key, iv = derived[:cipherAlgo.keyLength], derived[cipherAlgo.keyLength:]
    key = key[:cipherAlgo.keyLength]
    iv = iv[:cipherAlgo.ivLength]
    cipher = M2Crypto.EVP.Cipher(cipherAlgo.m2name, key, iv, M2Crypto.decrypt, 0)
    cipher.set_padding(0)
    cleartxt = cipher.update(raw) + cipher.final()
    return cleartxt


def DPAPIHmac(hashAlgo, pwdhash, hmacSalt, value):
    """Internal function used to compute HMACs of DPAPI structures"""
    hname = {"HMAC": "sha1"}.get(hashAlgo.name, hashAlgo.name)
    encKey = M2Crypto.EVP.HMAC(pwdhash, hname)
    encKey.update(hmacSalt)
    encKey = encKey.final()
    rv = M2Crypto.EVP.HMAC(encKey, hname)
    rv.update(value)
    return rv.final()


class MasterKey(DataStruct):
    """This class represents a MasterKey block contained in a MasterKeyFile"""

    def __init__(self, raw=None, SID=None):
        self.decrypted = False
        self.key = None
        self.key_hash = None
        self.hmacSalt = None
        self.hmac = None
        self.hmacComputed = None
        self.cipherAlgo = None
        self.hashAlgo = None
        self.rounds = None
        self.iv = None
        self.version = None
        self.ciphertext = None
        self.SID = SID
        DataStruct.__init__(self, raw)

    def __getstate__(self):
        d = dict(self.__dict__)
        for k in ["cipherAlgo", "hashAlgo"]:
            if k in d:
                d[k] = d[k].algnum
        return d

    def __setstate__(self, d):
        for k in ["cipherAlgo", "hashAlgo"]:
            if k in d:
                d[k] = CryptoAlgo(d[k])
        self.__dict__.update(d)

    def parse(self, data):
        self.version = data.eat("L")
        self.iv = data.eat("16s")
        self.rounds = data.eat("L")
        self.hashAlgo = CryptoAlgo(data.eat("L"))
        self.cipherAlgo = CryptoAlgo(data.eat("L"))
        self.ciphertext = data.remain()
        if self.SID:
            print self.jhash()

    def decryptWithHash(self, userSID, pwdhash):
        """Decrypts the masterkey with the given user's hash and SID.
        Simply computes the corresponding key then calls self.decryptWithKey()

        """
        self.decryptWithKey(derivePwdHash(pwdhash, userSID))

    def decryptWithPassword(self, userSID, pwd):
        """Decrypts the masterkey with the given user's password and SID.
        Simply computes the corresponding key, then calls self.decryptWithKey()

        """
        for algo in ["sha1", "md4"]:
            self.decryptWithKey(derivePwdHash(hashlib.new(algo, pwd.encode("UTF-16LE")).digest(), userSID))
            if self.decrypted:
                break

    def jhash(self):
        s = "$efs$0$%s$%s$%s$%s" % (self.SID, self.iv.encode("hex"), self.rounds, self.ciphertext.encode("hex"))
        return s

    def setKeyHash(self, h):
        assert(len(h) == 20)
        self.decrypted = True
        self.key_hash = h

    def setDecryptedKey(self, data):
        assert len(data) == 64
        self.decrypted = True
        self.key = data
        self.key_hash = hashlib.sha1(data).digest()

    def decryptWithKey(self, pwdhash):
        """Decrypts the masterkey with the given encryption key. This function
        also extracts the HMAC part of the decrypted stuff and compare it with
        the computed one.

        Note that, once successfully decrypted, the masterkey will not be
        decrypted anymore; this function will simply return.

        """
        if self.decrypted:
            return
        if not self.ciphertext:
            return
        # Compute encryption key
        # print self.iv.encode("hex")

        cleartxt = dataDecrypt(self.cipherAlgo, self.hashAlgo, self.ciphertext, pwdhash, self.iv, self.rounds)
        self.key = cleartxt[-64:]
        self.hmacSalt = cleartxt[:16]
        self.hmac = cleartxt[16:16 + self.hashAlgo.digestLength]
        self.hmacComputed = DPAPIHmac(self.hashAlgo, pwdhash, self.hmacSalt, self.key)

        # print self.hmac.encode("hex")
        # print self.hmacComputed.encode("hex")
        self.decrypted = self.hmac == self.hmacComputed
        if self.decrypted:
            self.key_hash = hashlib.sha1(self.key).digest()

    def __repr__(self):
        s = ["Masterkey block"]
        if self.cipherAlgo is not None:
            s.append("\tcipher algo  = %s" % repr(self.cipherAlgo))
        if self.hashAlgo is not None:
            s.append("\thash algo    = %s" % repr(self.hashAlgo))
        if self.rounds is not None:
            s.append("\trounds       = %i" % self.rounds)
        if self.iv is not None:
            s.append("\tIV           = %s" % self.iv.encode("hex"))
        if self.key is not None:
            s.append("\tkey          = %s" % self.key.encode("hex"))
        if self.hmacSalt is not None:
            s.append("\thmacSalt     = %s" % self.hmacSalt.encode("hex"))
        if self.hmac is not None:
            s.append("\thmac         = %s" % self.hmac.encode("hex"))
        if self.hmacComputed is not None:
            s.append("\thmacComputed = %s" % self.hmacComputed.encode("hex"))
        if self.key_hash is not None:
            s.append("\tkey hash     = %s" % self.key_hash.encode("hex"))
        if self.ciphertext is not None:
            s.append("\tciphertext   = %s" % self.ciphertext.encode("hex"))
        return "\n".join(s)


class MasterKeyFile(DataStruct):
    """This class represents a masterkey file."""

    def __init__(self, raw=None, SID=None):
        self.masterkey = None
        self.backupkey = None
        self.credhist = None
        self.domainkey = None
        self.decrypted = False
        self.version = None
        self.guid = None
        self.policy = None
        self.masterkeyLen = self.backupkeyLen = self.credhistLen = self.domainkeyLen = 0
        self.SID = SID
        DataStruct.__init__(self, raw)

    def parse(self, data):
        self.version = data.eat("L")
        # print self.version
        data.eat("2L")
        self.guid = data.eat("72s").decode("UTF-16LE").encode("utf-8")
        # print "GUID", self.guid
        data.eat("2L")
        self.policy = data.eat("L")
        self.masterkeyLen = data.eat("Q")
        # print self.masterkeyLen
        self.backupkeyLen = data.eat("Q")
        self.credhistLen = data.eat("Q")
        self.domainkeyLen = data.eat("Q")

        if self.masterkeyLen > 0:
            self.masterkey = MasterKey(SID=self.SID)
            self.masterkey.parse(data.eat_sub(self.masterkeyLen))
        if self.backupkeyLen > 0:
            self.backupkey = MasterKey()
            self.backupkey.parse(data.eat_sub(self.backupkeyLen))

    def decryptWithHash(self, userSID, h):
        """See MasterKey.decryptWithHash()"""
        if not self.masterkey.decrypted:
            self.masterkey.decryptWithHash(userSID, h)
        if not self.backupkey.decrypted:
            self.backupkey.decryptWithHash(userSID, h)
        self.decrypted = self.masterkey.decrypted or self.backupkey.decrypted

    def decryptWithPassword(self, userSID, pwd):
        """See MasterKey.decryptWithPassword()"""
        for algo in ["sha1", "md4"]:
            self.decryptWithHash(userSID, hashlib.new(algo, pwd.encode('UTF-16LE')).digest())
            if self.decrypted:
                break

    def decryptWithKey(self, pwdhash):
        """See MasterKey.decryptWithKey()"""
        if not self.masterkey.decrypted:
            self.masterkey.decryptWithKey(pwdhash)
        if not self.backupkey.decrypted:
            self.backupkey.decryptWithKey(pwdhash)
        self.decrypted = self.masterkey.decrypted or self.backupkey.decrypted

    def addKeyHash(self, guid, h):
        self.guid = guid
        self.masterkey = MasterKey()
        self.backupkey = MasterKey()
        self.masterkey.setKeyHash(h)
        self.decrypted = True

    def addDecryptedKey(self, guid, data):
        self.guid = guid
        self.masterkey = MasterKey()
        self.backupkey = MasterKey()
        self.masterkey.setDecryptedKey(data)
        self.decrypted = True

    def get_key(self):
        """Returns the first decrypted block between Masterkey and BackupKey.
        If none has been decrypted, returns the Masterkey block.

        """
        if self.masterkey.decrypted:
            return self.masterkey.key or self.masterkey.key_hash
        elif self.backupkey.decrypted:
            return self.backupkey.key
        return self.masterkey.key

    def __repr__(self):
        s = ["\n#### MasterKeyFile %s ####" % self.guid]
        if self.version is not None:
            s.append("\tversion   = %#d" % self.version)
        if self.policy is not None:
            s.append("\tPolicy    = %#x" % self.policy)
        if self.masterkeyLen > 0:
            s.append("\tMasterKey = %d" % self.masterkeyLen)
        if self.backupkeyLen > 0:
            s.append("\tBackupKey = %d" % self.backupkeyLen)
        if self.domainkeyLen > 0:
            s.append("\tDomainKey = %d" % self.domainkeyLen)
        if self.masterkey:
            s.append("    + Master Key: %s" % repr(self.masterkey))
        if self.backupkey:
            s.append("    + Backup Key: %s" % repr(self.backupkey))
        if self.domainkey:
            s.append("    + %s" % repr(self.domainkey))
        return "\n".join(s)


class MasterKeyPool(object):
    """This class is the pivot for using DPAPIck. It manages all the DPAPI
    structures and contains all the decryption intelligence.

    """

    def __init__(self):
        self.keys = defaultdict(lambda: [])
        self.creds = {}
        self.system = None
        self.passwords = set()

    def addMasterKey(self, mkey, SID=None):
        """Add a MasterKeyFile is the pool.

        mkey is a string representing the content of the file to add.

        """
        mkf = MasterKeyFile(mkey, SID=SID)
        self.keys[mkf.guid].append(mkf)

    def addMasterKeyHash(self, guid, h):
        self.keys[guid].append(MasterKeyFile().addKeyHash(guid, h))

    def getMasterKeys(self, guid):
        """Returns an array of Masterkeys corresponding the the given GUID.

        guid is a string.

        """
        return self.keys.get(guid, [])

    def addSystemCredential(self, blob):
        """Adds DPAPI_SYSTEM token to the pool.

        blob is a string representing the LSA secret token

        """
        pass

    def loadDirectory(self, directory):
        """Adds every masterkey contained in the given directory to the pool.
        If a file is not a valid Masterkey file, this function simply goes to
        the next file without complaining.

        directory is a string representing the directory path to add.

        """
        for k in os.listdir(directory):
            if re.match("^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", k, re.IGNORECASE):
                try:
                    with open(os.path.join(directory, k), 'rb') as f:
                        self.addMasterKey(f.read())
                except:
                    pass

    def pickle(self, filename=None):
        if filename is not None:
            cPickle.dump(self, filename, 2)
        else:
            return cPickle.dumps(self, 2)

    def __getstate__(self):
        d = dict(self.__dict__)
        d["keys"] = dict(d["keys"])
        return d

    def __setstate__(self, d):
        tmp = dict(d["keys"])
        d["keys"] = defaultdict(lambda: [])
        d["keys"].update(tmp)
        self.__dict__.update(d)

    @staticmethod
    def unpickle(data=None, filename=None):
        if data is not None:
            return cPickle.loads(data)
        if filename is not None:
            return cPickle.load(filename)
        raise ValueError("must provide either data or filename argument")

    def try_credential_hash(self, userSID, pwdhash):
        n = 0
        for mkl in self.keys.values():
            for mk in mkl:
                if not mk.decrypted:
                    if pwdhash is not None:
                        mk.decryptWithHash(userSID, pwdhash)
                        if not mk.decrypted and self.creds.get(userSID) is not None:
                            # process CREDHIST
                            self.creds[userSID].decryptWithHash(pwdhash)
                            for cred in self.creds[userSID].entries_list:
                                mk.decryptWithHash(userSID, cred.pwdhash)
                                if cred.ntlm is not None and not mk.decrypted:
                                    mk.decryptWithHash(userSID, cred.ntlm)
                                if mk.decrypted:
                                    self.creds[userSID].validate()
                                    break
                    if not mk.decrypted and self.system is not None:
                        # try DPAPI_SYSTEM creds
                        mk.decryptWithKey(self.system.user)
                        if not mk.decrypted:
                            mk.decryptWithKey(self.system.machine)
                        if userSID is not None and not mk.decrypted:
                            # try with an extra SID (just in case)
                            mk.decryptWithHash(userSID, self.system.user)
                            if not mk.decrypted:
                                mk.decryptWithHash(userSID, self.system.machine)
                    if mk.decrypted:
                        n += 1
        return n

    def try_credential(self, userSID, password):
        """This function tries to decrypt every masterkey contained in the pool
        that has not been successfully decrypted yet with the given password and
        SID.

        userSID is a string representing the user's SID
        password is a string representing the user's password.

        Returns the number of masterkey that has been successfully decrypted
        with those credentials.

        """
        n = 0
        for mkl in self.keys.values():
            for mk in mkl:
                if not mk.decrypted:
                    if password is not None:
                        mk.decryptWithPassword(userSID, password)
                        if not mk.decrypted and self.creds.get(userSID) is not None:
                            # process CREDHIST
                            self.creds[userSID].decryptWithPassword(password)
                            for cred in self.creds[userSID].entries_list:
                                mk.decryptWithHash(userSID, cred.pwdhash)
                                if cred.ntlm is not None and not mk.decrypted:
                                    mk.decryptWithHash(userSID, cred.ntlm)
                                if mk.decrypted:
                                    self.creds[userSID].validate()
                                    break
                    if not mk.decrypted and self.system is not None:
                        # try DPAPI_SYSTEM creds
                        mk.decryptWithHash(userSID, self.system.user)
                        if not mk.decrypted:
                            mk.decryptWithHash(userSID, self.system.machine)
                        if not mk.decrypted:
                            mk.decryptWithKey(self.system.user)
                        if not mk.decrypted:
                            mk.decryptWithKey(self.system.machine)
                    if mk.decrypted:
                        self.passwords.add(password)
                        n += 1
        return n

    def __repr__(self):
        s = ["MasterKeyPool:",
             "Passwords:",
             repr(self.passwords),
             "Keys:",
             repr(self.keys.items())]
        if self.system is not None:
            s.append(repr(self.system))
        for i in self.creds.keys():
            s.append("\tSID: %s" % i)
            s.append(repr(self.creds[i]))
        return "\n".join(s)


class DPAPIProbe(DataStruct):
    """This is the generic class for building DPAPIck probes.
        All probes must inherit this class.

    """
    def __init__(self, raw=None):
        """Constructs a DPAPIProbe object.
            If raw is set, automatically builds a DataStruct with that
            and calls parse() method with this.

        """
        self.dpapiblob = None
        self.cleartext = None
        self.entropy = None
        DataStruct.__init__(self, raw)

    def parse(self, data):
        """Parses raw data into structured data.
            Automatically called by __init__. You should not call it manually.

            data is a DataStruct object.

        """
        pass

    def preprocess(self, **k):
        """Optional. Apply tranformations to data before the decryption loop."""
        self.entropy = k.get("entropy")

    def postprocess(self, **k):
        """Optional. Apply transformations after a successful decryption."""
        if self.dpapiblob.decrypted:
            self.cleartext = self.dpapiblob.cleartext

    def try_decrypt_system(self, mkeypool, **k):
        """Decryption loop for SYSTEM account protected blob. eg. wifi blobs.
            Basic probes should not overload this function.

            Returns True/False upon decryption success/failure.

        """
        self.preprocess(**k)
        mkeypool.try_credential(None, None)
        for kguid in self.dpapiblob.guids:
            mks = mkeypool.getMasterKeys(kguid)
            for mk in mks:
                if mk.decrypted:
                    self.dpapiblob.decrypt(mk.get_key(), self.entropy, k.get("strong", None))
                    if self.dpapiblob.decrypted:
                        self.postprocess(**k)
                        return True
        return False

    def try_decrypt_with_hash(self, h, mkeypool, sid, **k):
        """Decryption loop for general blobs with given user's password hash.
            This function will call preprocess() first, then tries to decrypt.

            k may contain optional values such as:
                entropy: the optional entropy to use with that blob.
                strong: strong password given by the user

            Basic probes should not override this one as it contains the full
            decryption logic.

            Returns True/False upon decryption success/failure.

        """
        self.preprocess(**k)
        mkeypool.try_credential_hash(sid, h)
        mks = mkeypool.getMasterKeys(self.dpapiblob.mkguid)
        for mk in mks:
            if mk.decrypted:
                self.dpapiblob.decrypt(mk.get_key(), self.entropy, k.get("strong", None))
                if self.dpapiblob.decrypted:
                    self.postprocess(**k)
                    return True
        return False

    def try_decrypt_with_password(self, password, mkeypool, sid, **k):
        """Decryption loop for general blobs with given user's password.
            Simply computes the hash then calls try_decrypt_with_hash()

            Return True/False upon decryption success/failure.

        """
        self.preprocess(**k)
        mkeypool.try_credential(sid, password)
        mks = mkeypool.getMasterKeys(self.dpapiblob.mkguid)
        for mk in mks:
            if mk.decrypted:
                self.dpapiblob.decrypt(mk.get_key(), self.entropy, k.get("strong", None))
                if self.dpapiblob.decrypted:
                    self.postprocess(**k)
                    return True
        return False


def usage():
    print """Usage:

efs2john.py --masterkey=samples/openwall.efs/92573301-74fa-4e55-bd38-86fc558fa25e \\
    --sid="S-1-5-21-1482476501-1659004503-725345543-1003"

efs2john.py --masterkey=samples/openwall.efs.2/21d67870-8257-49e0-b2de-c58324271c42 \\
    --sid="S-1-5-21-1482476501-1659004503-725345543-1005"

efs2john.py --masterkey=samples/Win-2012-non-DC/1b52eb4f-440f-479e-b84a-654fdccad797 \\
    --sid="S-1-5-21-689418962-3671548705-686489014-1001" --password="openwall@123"
"""

if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("--sid", metavar="SID", dest="sid")
    parser.add_option("--masterkey", metavar="DIRECTORY", dest="masterkey")
    parser.add_option("--password", metavar="PASSWORD", dest="password")

    (options, args) = parser.parse_args()

    mkp = MasterKeyPool()
    if not options.sid:
        usage()
        sys.exit(-1)

    mkdata = open(options.masterkey, 'rb').read()
    mkp.addMasterKey(mkdata, SID=options.sid)
    if options.password:
        print mkp.try_credential(options.sid, options.password)
