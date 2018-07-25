#!/usr/bin/env python3

# This software is Copyright (c) 2018, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Special thanks goes to https://github.com/NODESPLIT/tz-brute and Michael Senn
# (@MikeSenn on Telegram) for helping me bootstrap this project.

import re
import os
import sys
import json
import hashlib
import binascii

PY3 = sys.version_info[0] == 3

if not PY3:
    print("This program requires Python 3.6+ to run.")
    sys.exit(0)

### Borrowed code starts, The MIT License (MIT), Copyright (c) 2013 Vitalik Buterin, https://github.com/vbuterin/pybitcointools ###

def bytes_to_hex_string(b):
    if isinstance(b, str):
        return b

    return ''.join('{:02x}'.format(y) for y in b)

def safe_from_hex(s):
    return bytes.fromhex(s)

def from_int_representation_to_bytes(a):
    return bytes(str(a), 'utf-8')

def from_int_to_byte(a):
    return bytes([a])

def from_byte_to_int(a):
    return a

def from_string_to_bytes(a):
    return a if isinstance(a, bytes) else bytes(a, 'utf-8')

def safe_hexlify(a):
    return str(binascii.hexlify(a), 'utf-8')


string_types = (str)
string_or_bytes_types = (str, bytes)
int_types = (int, float)
# Base switching
code_strings = {
    2: '01',
    10: '0123456789',
    16: '0123456789abcdef',
    32: 'abcdefghijklmnopqrstuvwxyz234567',
    58: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz',
    256: ''.join([chr(x) for x in range(256)])
}

def encode(val, base, minlen=0):
    base, minlen = int(base), int(minlen)
    code_string = get_code_string(base)
    result_bytes = bytes()
    while val > 0:
        curcode = code_string[val % base]
        result_bytes = bytes([ord(curcode)]) + result_bytes
        val //= base

    pad_size = minlen - len(result_bytes)

    padding_element = b'\x00' if base == 256 else b'1' \
        if base == 58 else b'0'
    if (pad_size > 0):
        result_bytes = padding_element*pad_size + result_bytes

    result_string = ''.join([chr(y) for y in result_bytes])
    result = result_bytes if base == 256 else result_string

    return result

def decode(string, base):
    if base == 256 and isinstance(string, str):
        string = bytes(bytearray.fromhex(string))
    base = int(base)
    code_string = get_code_string(base)
    result = 0
    if base == 256:
        def extract(d, cs):
            return d
    else:
        def extract(d, cs):
            return cs.find(d if isinstance(d, str) else chr(d))

    if base == 16:
        string = string.lower()
    while len(string) > 0:
        result *= base
        result += extract(string[0], code_string)
        string = string[1:]
    return result



def bin_dbl_sha256(s):
    bytes_to_hash = from_string_to_bytes(s)
    return hashlib.sha256(hashlib.sha256(bytes_to_hash).digest()).digest()

def lpad(msg, symbol, length):
    if len(msg) >= length:
        return msg
    return symbol * (length - len(msg)) + msg

def get_code_string(base):
    if base in code_strings:
        return code_strings[base]
    else:
        raise ValueError("Invalid base!")

def changebase(string, frm, to, minlen=0):
    if frm == to:
        return lpad(string, get_code_string(frm)[0], minlen)
    return encode(decode(string, frm), to, minlen)

def b58check_to_bin(inp):
    leadingzbytes = len(re.match('^1*', inp).group(0))
    data = b'\x00' * leadingzbytes + changebase(inp, 58, 256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]

### Borrowed code ends ####

if __name__ == "__main__":
    if len(sys.argv) == 2:  # internal https://faucet.tzalpha.net/ files testing mode
        filename = sys.argv[1]
        data = open(filename).read()
        data = json.loads(data)
        mnemonic, email, address = (" ".join(data["mnemonic"]), data["email"], data["pkh"])
        raw_address = binascii.hexlify(b58check_to_bin(address)).decode("ascii")
        print("%s:$tezos$1*%s*%s*%s*%s*%s" % ("dummy", 2048, mnemonic, email, address, raw_address))
        sys.exit(0)
    if len(sys.argv) < 4:
        sys.stderr.write("Usage: %s \'mnemonic data (15 words)\' \'email\' \'public key\'\n" %
                         sys.argv[0])
        sys.stderr.write("""\nExample: %s 'put guide flat machine express cave hello connect stay local spike ski romance express brass' 'jbzbdybr.vpbdbxnn@tezos.example.org' 'tz1eTjPtwYjdcBMStwVdEcwY2YE3th1bXyMR'\n""" % sys.argv[0])
        sys.exit(-1)

    mnemonic, email, address = sys.argv[1:4]
    if len(email) > 51:
        sys.stderr.write("[WARNING] Very large salt (email address) found, which is unsupported by tezos-opencl format!\n")

    raw_address = binascii.hexlify(b58check_to_bin(address)).decode("ascii")

    print("%s:$tezos$1*%s*%s*%s*%s*%s" % ("dummy", 2048, mnemonic, email, address, raw_address))
