# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <jean-christophe.delaunay (at) synacktiv.com> wrote this file.  As long as you
# retain this notice you can do whatever you want with this stuff. If we meet
# some day, and you think this stuff is worth it, you can buy me a beer in
# return.   Fist0urs
# ----------------------------------------------------------------------------

#!/usr/bin/python

# -*- coding: utf-8 -*-

# by Fist0urs

from random import getrandbits, sample
from struct import pack

from _crypto import ARC4, MD5, MD4
import hmac as HMAC

# supported encryptions
RC4_HMAC = 23

# suported checksum
RSA_MD5 = 7
HMAC_MD5 = 0xFFFFFF76

def random_bytes(n):
    return ''.join(chr(c) for c in sample(xrange(256), n))

def decrypt(etype, key, msg_type, encrypted):
    # MAGIC
    if etype != RC4_HMAC:
        return '31337313373133731337' + str(etype)

    chksum = encrypted[:16]
    data = encrypted[16:]
    k1 = HMAC.new(key, pack('<I', msg_type)).digest()
    k3 = HMAC.new(k1, chksum).digest()
    data = ARC4.new(k3).decrypt(data)
    if HMAC.new(k1, data).digest() != chksum:
        raise ValueError('Decryption failed! (checksum error)')
    return data[8:]

def encrypt(etype, key, msg_type, data):
    if etype != RC4_HMAC:
        raise NotImplementedError('Only RC4-HMAC supported!')
    k1 = HMAC.new(key, pack('<I', msg_type)).digest()
    data = random_bytes(8) + data
    chksum = HMAC.new(k1, data).digest()
    k3 = HMAC.new(k1, chksum).digest()
    return chksum + ARC4.new(k3).encrypt(data)

def checksum(cksumtype, data, key=None):
    if cksumtype == RSA_MD5:
        return MD5.new(data).digest()
    elif cksumtype == HMAC_MD5:
        return HMAC.new(key, data).digest()
    else:
        raise NotImplementedError('Only MD5 supported!')

def generate_subkey(etype=RC4_HMAC):
    if etype != RC4_HMAC:
        raise NotImplementedError('Only RC4-HMAC supported!')
    key = random_bytes(16)
    return (etype, key)

def ntlm_hash(pwd):
    return MD4.new(pwd.encode('utf-16le'))
