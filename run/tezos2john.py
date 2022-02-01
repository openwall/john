#!/usr/bin/env python3
# -*- coding: iso-8859-15 -*-
# This software is Copyright (c) 2018, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Special thanks goes to https://github.com/NODESPLIT/tz-brute and Michael Senn
# (@MikeSenn on Telegram) for helping me bootstrap this project.
#
# Contributor: LordDarkHelmet (https://github.com/LordDarkHelmet)


# code from https://github.com/trezor/python-mnemonic used.
# Copyright (c) 2013 Pavol Rusnak
# Copyright (c) 2017 mruddy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.




import re
import os
import sys
import json
import hashlib
import binascii
import argparse
import math
import unicodedata

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

bip39WordFileDirectory = os.path.join(os.path.abspath(os.path.dirname(sys.argv[0])) , "bip-0039")

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

def getSeedWordListFromString(seedWords):
    return [seedWord for seedWord in normalize_string(seedWords).split(' ')]

# from https://github.com/trezor/python-mnemonic/blob/master/mnemonic/mnemonic.py
def normalize_string(txt):
        if isinstance(txt, str if sys.version < "3" else bytes):
            utxt = txt.decode("utf8")
        elif isinstance(txt, unicode if sys.version < "3" else str):  # noqa: F821
            utxt = txt
        else:
            raise TypeError("String value expected")

        return unicodedata.normalize("NFKD", utxt)

### Check if the provided seed words conform to the Tezos ICO rules
def isICOValidSeed(seedWords):

    # Ensure that it meets the ICO spec of exactly 15 words.
    myWords = getSeedWordListFromString(seedWords)
    if len(myWords) != 15:
        sys.stderr.write("[WARNING] There must be 15 Seed Words to be a valid ICO mnemonic!\n")
        return False
    return True


### Check to see if it is a valid Mnemonic
def isValidMnemonic(seedWords):
    myWords = getSeedWordListFromString(seedWords)
    # Get a list of all avalible languages
    expectedNuberOfFiles = 8
    languageList = [str(os.path.join(bip39WordFileDirectory , files)) for files in os.listdir(bip39WordFileDirectory) if files.endswith(".txt")]
    if (len(languageList) < expectedNuberOfFiles):
        sys.stderr.write("[WARNING] Language List Error. Language files not detected! Files found=" + str(len(languageList)) + " expecting at least " + str(expectedNuberOfFiles) + "\n")
        return False

    for languageFile in languageList:
         f = open(languageFile, 'r', encoding="utf-8")
         x = f.readlines()
         f.close()
         bip39Words = list(map(lambda s: normalize_string(s.strip()), x))
         if len(bip39Words) != 2048:
            sys.stderr.write("[WARNING] Error in " + languageFile + " " + str(len(bip39Words)) + " words detected. There should be exactly 2048 words!\n")
            return False

         #Do all the words exist in the selected list? if so validate it.
         if set(myWords).issubset(bip39Words):
            if isValidChecksumForMnemonic(seedWords, bip39Words):
                return True
            return False

    sys.stderr.write("[WARNING] Provided Seed Words Are Not Valid Seed Words!\n")
    return False



### Check if the seed words form a valid checksum. All ICO wallets have a valid seed checksum.
### See Josh McIntyre's post for a good walkthrough. https://jmcintyre.net/?p=180
def isValidChecksumForMnemonic(seedWords, wordList):
    myWords = getSeedWordListFromString(seedWords)
    myWordPosBinString = ""

    #Must be a multiple of 3 to be valid. Currently the set of [12, 15, 18, 21, 24] are valid, but future versions may be different. Hence leaving it as % 3 instead of if len(myWords) not in [12, 15, 18, 21, 24]:
    if (len(myWords) % 3 != 0):
        sys.stderr.write("[WARNING] Seed Words Must be a Multple of 3!\n")
        return False

    #check to ensure that seed words are on the list, and to get a string for the checksum process
    try:
        for t in myWords:
            myWordPosBinString += str(bin(wordList.index(t)))[2:].zfill(11);
    except ValueError:
        sys.stderr.write("[WARNING] Seed Word Not Found On Word List!\n")
        return False

    lenOfChecksum = len(myWordPosBinString) // 33
    lenOfBody = lenOfChecksum * 32

    seedWordBody = myWordPosBinString[:lenOfBody]
    seedWordChecksum = myWordPosBinString[-lenOfChecksum:] #get just the checksum

    binaryRepresentationOfBody = binascii.unhexlify(hex(int(seedWordBody, 2))[2:].zfill(lenOfChecksum * 8))
    generatedChecksum = bin(int(hashlib.sha256(binaryRepresentationOfBody).hexdigest(), 16))[2:].zfill(256)[: lenOfChecksum]

    if generatedChecksum != seedWordChecksum:
        sys.stderr.write("[WARNING] Invalid mnemonic checksum! Check your seed words!\n")
        return False
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Creates Tezos File For John The Ripper')
    parser.add_argument('-i', '--ignoreRules', '--ignorerules', action='store_true', help='Ignore All Rules, seed words, checksum, ...', required=False)
    parser.add_argument('-I', '--ignoreICORules', '--ignoreicorules', action='store_true', help='Do Not Check To See If It Is A Valid ICO Format (15 seed words)', required=False)
    args, myArgs = parser.parse_known_args()

    if len(myArgs) == 1:  # internal https://faucet.tzalpha.net/ files testing mode
        filename = sys.argv[1]
        data = open(filename).read()
        data = json.loads(data)
        mnemonic, email, address = (" ".join(data["mnemonic"]), data["email"], data["pkh"])
        raw_address = binascii.hexlify(b58check_to_bin(address)).decode("ascii")
        print("%s:$tezos$1*%s*%s*%s*%s*%s" % (email, 2048, mnemonic, email, address, raw_address))
        sys.exit(0)
    if len(myArgs) != 3:
        sys.stderr.write("Usage: %s \'mnemonic data (15 words)\' \'email\' \'public key\'\n" %
                         sys.argv[0])
        sys.stderr.write("""\nExample: %s 'put guide flat machine express cave hello connect stay local spike ski romance express brass' 'jbzbdybr.vpbdbxnn@tezos.example.org' 'tz1eTjPtwYjdcBMStwVdEcwY2YE3th1bXyMR'\n""" % sys.argv[0])
        sys.exit(1)

    mnemonic, email, address = sys.argv[1:4]
    if len(email) > 51:
        sys.stderr.write("[WARNING] Very large salt (email address) found, which is unsupported by tezos-opencl format!\n")

    if args.ignoreRules == False:
        if args.ignoreICORules == False:
           if isICOValidSeed(mnemonic) == False:
                sys.stderr.write("[ERROR] ICO Rules Broken, Bad Seed Words! Use the -h argument for more options.\n")
                sys.exit(1)
        if  isValidMnemonic(mnemonic) == False:
            sys.stderr.write("[ERROR] Rules Broken, Bad Seed Words! Use the -h argument for more options.\n")
            sys.exit(1)
        #Check if it is a valid email address
        if not re.fullmatch(r"[^@]+@[^@]+\.[^@]+", email):
            sys.stderr.write("[ERROR] Rules Broken, Invalid Email Address! Use the -h argument for more options.\n")
            sys.exit(1)

    try:
        raw_address = binascii.hexlify(b58check_to_bin(address)).decode("ascii")
    except AssertionError:
        sys.stderr.write("[ERROR] Invalid address, Please Check before continuing.\n")
        sys.exit(1)

    print("%s:$tezos$1*%s*%s*%s*%s*%s" % (email, 2048, mnemonic, email, address, raw_address))
