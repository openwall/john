#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Modified (for JtR) by Dhiru Kholia in December, 2014.
# Modified (for JtR) by Jean-Christophe Delaunay
# <jean-christophe.delaunay at synacktiv.com> in 2017
# to support further options and JtR new hash format
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

import sys
import struct
import array
import hmac
import hashlib
try:
    from Crypto.Cipher import AES
    from Crypto.Cipher import DES
    from Crypto.Cipher import DES3
except ImportError:
    sys.stderr.write("For additional functionality, please install PyCrypto package.\n")
import argparse
from collections import defaultdict

debug = False


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
        if fmt[0] not in ("<", ">", "!", "@"):
            fmt = self.endianness + fmt
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

    def __repr__(self):
        s = ["DPAPI BLOB",
             "\n".join(("\tversion      = %(version)d",
                        "\tprovider     = %(provider)s",
                        "\tmkey         = %(mkguid)s",
                        "\tflags        = %(flags)#x",
                        "\tdescr        = %(description)s",
                        "\tcipherAlgo   = %(cipherAlgo)r",
                        "\thashAlgo     = %(hashAlgo)r")) % self.__dict__,
             "\tsalt         = %s" % self.salt.encode('hex'),
             "\thmac         = %s" % self.hmac.encode('hex'),
             "\tcipher       = %s" % self.cipherText.encode('hex'),
             "\tsign         = %s" % self.sign.encode('hex')]
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
        if 'name' in kargs:
            kargs['ID'] = algnum
            cls._crypto_data[kargs['name']] = cls.Algo(kargs)

    @classmethod
    def get_algo(cls, algnum):
        return cls._crypto_data[algnum]

    def __init__(self, i):
        self.algnum = i
        self.algo = CryptoAlgo.get_algo(i)

    name = property(lambda self: self.algo.name)
    module = property(lambda self: self.algo.module)
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


CryptoAlgo.add_algo(0x6603, name="DES3", keyLength=192, IVLength=64, blockLength=64, module=DES3,
                    keyFixup=des_set_odd_parity)
CryptoAlgo.add_algo(0x6611, name="AES", keyLength=128, IVLength=128, blockLength=128, module=AES)
CryptoAlgo.add_algo(0x660e, name="AES-128", keyLength=128, IVLength=128, blockLength=128, module=AES)
CryptoAlgo.add_algo(0x660f, name="AES-192", keyLength=192, IVLength=128, blockLength=128, module=AES)
CryptoAlgo.add_algo(0x6610, name="AES-256", keyLength=256, IVLength=128, blockLength=128, module=AES)
CryptoAlgo.add_algo(0x6601, name="DES", keyLength=64, IVLength=64, blockLength=64, module=DES,
                    keyFixup=des_set_odd_parity)
CryptoAlgo.add_algo(0x8009, name="HMAC", digestLength=160, blockLength=512)
CryptoAlgo.add_algo(0x8003, name="md5", digestLength=128, blockLength=512)
CryptoAlgo.add_algo(0x8004, name="sha1", digestLength=160, blockLength=512)
CryptoAlgo.add_algo(0x800c, name="sha256", digestLength=256, blockLength=512)
CryptoAlgo.add_algo(0x800d, name="sha384", digestLength=384, blockLength=1024)
CryptoAlgo.add_algo(0x800e, name="sha512", digestLength=512, blockLength=1024)

def pbkdf2_ms(passphrase, salt, keylen, iterations, digest='sha1'):
    """Implementation of PBKDF2 that allows specifying digest algorithm.

    Returns the corresponding expanded key which is keylen long.

    Note: This is not real pbkdf2, but instead a slight modification of it.
    Seems like Microsoft tried to implement pbkdf2 but got the xoring wrong.
    """
    buff = ""
    i = 1
    while len(buff) < keylen:
        U = salt + struct.pack("!L", i)
        i += 1
        derived = hmac.new(passphrase, U, digestmod=lambda: hashlib.new(digest)).digest()
        for r in xrange(iterations - 1):
            actual = hmac.new(passphrase, derived, digestmod=lambda: hashlib.new(digest)).digest()
            derived = ''.join([chr(ord(x) ^ ord(y)) for (x, y) in zip(derived, actual)])
        buff += derived
    return buff[:keylen]

def pbkdf2(passphrase, salt, keylen, iterations, digest='sha1'):
    """Implementation of PBKDF2 that allows specifying digest algorithm.

    Returns the corresponding expanded key which is keylen long.
    """
    buff = ""
    i = 1
    while len(buff) < keylen:
        U = salt + struct.pack("!L", i)
        i += 1
        derived = hmac.new(passphrase, U, digestmod=lambda: hashlib.new(digest)).digest()
        actual = derived
        for r in xrange(iterations - 1):
            actual = hmac.new(passphrase, actual, digestmod=lambda: hashlib.new(digest)).digest()
            derived = ''.join([chr(ord(x) ^ ord(y)) for (x, y) in zip(derived, actual)])
        buff += derived
    return buff[:keylen]

def derivePwdHash(pwdhash, userSID, digest='sha1'):
    """Internal use. Computes the encryption key from a user's password hash"""
    return hmac.new(pwdhash, (userSID + "\0").encode("UTF-16LE"), digestmod=lambda: hashlib.new(digest)).digest()


def dataDecrypt(cipherAlgo, hashAlgo, raw, encKey, iv, rounds):
    """Internal use. Decrypts data stored in DPAPI structures."""
    hname = {"HMAC": "sha1"}.get(hashAlgo.name, hashAlgo.name)
    derived = pbkdf2_ms(encKey, iv, cipherAlgo.keyLength + cipherAlgo.ivLength, rounds, hname)
    key, iv = derived[:cipherAlgo.keyLength], derived[cipherAlgo.keyLength:]
    key = key[:cipherAlgo.keyLength]
    iv = iv[:cipherAlgo.ivLength]
    cipher = cipherAlgo.module.new(key, mode=cipherAlgo.module.MODE_CBC, IV=iv)
    cleartxt = cipher.decrypt(raw)
    return cleartxt


def DPAPIHmac(hashAlgo, pwdhash, hmacSalt, value):
    """Internal function used to compute HMACs of DPAPI structures"""
    hname = {"HMAC": "sha1"}.get(hashAlgo.name, hashAlgo.name)
    encKey = hmac.new(pwdhash, digestmod=lambda: hashlib.new(hname))
    encKey.update(hmacSalt)
    encKey = encKey.digest()
    rv = hmac.new(encKey, digestmod=lambda: hashlib.new(hname))
    rv.update(value)
    return rv.digest()


def display_masterkey(Preferred):
    GUID1 = Preferred.read(8)
    GUID2 = Preferred.read(8)

    GUID = struct.unpack("<LHH", GUID1)
    GUID2 = struct.unpack(">HLH", GUID2)

    print "%s-%s-%s-%s-%s%s" % (format(GUID[0], '08x'), format(GUID[1], '04x'), format(GUID[2], '04x'), format(GUID2[0], '04x'), format(GUID2[1], '08x'), format(GUID2[2], '04x'))


class MasterKey(DataStruct):
    """This class represents a MasterKey block contained in a MasterKeyFile"""

    def __init__(self, raw=None, SID=None, context=None):
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
        self.context = context
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

    def jhash(self):
        version = -1
        hmac_algo = None
        cipher_algo = None
        if "des3" in str(self.cipherAlgo).lower() and "hmac" in str(self.hashAlgo).lower():
            version = 1
            hmac_algo = "sha1"
            cipher_algo = "des3"
        elif "aes-256" in str(self.cipherAlgo).lower() and "sha512" in str(self.hashAlgo).lower():
            version = 2
            hmac_algo = "sha512"
            cipher_algo = "aes256"
        else:
            return "Unsupported combination of cipher '%s' and hash algorithm '%s' found!" % (self.cipherAlgo, self.hashAlgo)
        context = 0

        if self.context == "domain":
            context = 2
            s = "$DPAPImk$%d*%d*%s*%s*%s*%d*%s*%d*%s" % (version, context, self.SID, cipher_algo, hmac_algo, self.rounds, self.iv.encode("hex"),
                                     len(self.ciphertext.encode("hex")), self.ciphertext.encode("hex"))
            context = 3
            s += "\n$DPAPImk$%d*%d*%s*%s*%s*%d*%s*%d*%s" % (version, context, self.SID, cipher_algo, hmac_algo, self.rounds,
                                     self.iv.encode("hex"), len(self.ciphertext.encode("hex")), self.ciphertext.encode("hex"))
        else:
            if self.context == "local":
                context = 1
            elif self.context == "domain1607-":
                context = 2
            elif self.context == "domain1607+":
                context = 3

            s = "$DPAPImk$%d*%d*%s*%s*%s*%d*%s*%d*%s" % (version, context, self.SID, cipher_algo, hmac_algo, self.rounds, self.iv.encode("hex"),
                                         len(self.ciphertext.encode("hex")), self.ciphertext.encode("hex"))
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

        cleartxt = dataDecrypt(self.cipherAlgo, self.hashAlgo, self.ciphertext, pwdhash, self.iv, self.rounds)
        self.key = cleartxt[-64:]
        self.hmacSalt = cleartxt[:16]
        self.hmac = cleartxt[16:16 + self.hashAlgo.digestLength]
        self.hmacComputed = DPAPIHmac(self.hashAlgo, pwdhash, self.hmacSalt, self.key)
        self.decrypted = self.hmac == self.hmacComputed

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

    def __init__(self, raw=None, SID=None, context=None):
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
        self.context = context
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
            self.masterkey = MasterKey(SID=self.SID, context=self.context)
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

    def decryptWithPassword(self, userSID, pwd, context):
        """See MasterKey.decryptWithPassword()"""
        algo = None
        if context == "domain1607-" or context == "domain":
            self.decryptWithHash(userSID, hashlib.new("md4", pwd.encode('UTF-16LE')).digest())
            if self.decrypted:
                print "Decrypted succesfully as domain1607-"
                return
        if context == "domain1607+" or context == "domain":
            SIDenc = userSID.encode("UTF-16LE")
            NTLMhash = hashlib.new("md4", pwd.encode('UTF-16LE')).digest()
            derived = pbkdf2(NTLMhash, SIDenc, 32, 10000, digest='sha256')
            derived = pbkdf2(derived, SIDenc, 16, 1, digest='sha256')
            self.decryptWithHash(userSID, derived)
            if self.decrypted:
                print "Decrypted succesfully as domain1607+"
                return
        if context == "local":
            self.decryptWithHash(userSID, hashlib.new("sha1", pwd.encode('UTF-16LE')).digest())

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
        self.passwords = set()

    def addMasterKey(self, mkey, SID=None, context=None):
        """Add a MasterKeyFile is the pool.

        mkey is a string representing the content of the file to add.

        """
        mkf = MasterKeyFile(mkey, SID=SID, context=context)
        self.keys[mkf.guid].append(mkf)

    def addMasterKeyHash(self, guid, h):
        self.keys[guid].append(MasterKeyFile().addKeyHash(guid, h))

    def try_credential(self, userSID, password, context):
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
            if debug:
                print(mkl)
            for mk in mkl:
                if not mk.decrypted:
                    if password is not None:
                        mk.decryptWithPassword(userSID, password, context)
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-S', '--sid', required=False, help="SID of account owning the masterkey file.")
    parser.add_argument('-mk', '--masterkey', required=False, help="masterkey file (usually in %%APPDATA%%\\Protect\\<SID>).")
    parser.add_argument('-d', '--debug', default=False, action='store_true', dest="debug")
    parser.add_argument('-c', '--context', required=False, help="context of user account. 1607 refers to Windows 10 1607 update.", choices=['domain', 'domain1607+', 'domain1607-', 'local'])
    parser.add_argument('-P', '--preferred', required=False, help="'Preferred' file containing GUID of masterkey file in use (usually in %%APPDATA%%\\Protect\\<SID>). Cannot be used with any other command.")
    parser.add_argument("--password", metavar="PASSWORD", dest="password", help="password to decrypt masterkey file.")

    options = parser.parse_args()
    debug = options.debug

    if options.preferred and (options.masterkey or options.sid or options.context):
        print "'Preferred' option cannot be used combined with any other, exiting."
        sys.exit(1)
    elif not options.preferred and not (options.masterkey and options.sid and options.context):
        print "masterkey file, SID and context are mandatory in order to extract hash from masterkey file, exiting."
        sys.exit(1)
    elif options.preferred:
        Preferred = open(options.preferred,'rb')
        display_masterkey(Preferred)
        Preferred.close()
        sys.exit(1)
    else:
        mkp = MasterKeyPool()
        masterkeyfile = open(options.masterkey,'rb')
        mkdata = masterkeyfile.read()
        masterkeyfile.close()
        mkp.addMasterKey(mkdata, SID=options.sid, context=options.context)
        if options.password:
            print mkp.try_credential(options.sid, options.password, options.context)
