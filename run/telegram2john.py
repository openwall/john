#!/usr/bin/python3

"""Utility to extract "hashes" from Telegram Android app's userconfing.xml
file(s) and from Telegram Desktop's local storage (map/key_datas) files"""

# Android App:
# Tested with Telegram for Android v4.8.4 in February, 2018.
#
# Special thanks goes to https://github.com/Banaanhangwagen for documenting
# this hashing scheme.
#
# See "UserConfig.java" and "SharedConfig.java" from
# https://github.com/DrKLO/Telegram/ for details on the hashing scheme.
#
# Written by Dhiru Kholia <dhiru at openwall.com> in February, 2018 for JtR
# project.
#
#
# Telegram Desktop:
# Tested with multiple Telegram Desktop versions in July, 2018
#
# Special thanks goes to https://github.com/MihaZupan for documenting
# this hashing scheme.
#
# Written by Dhiru Kholia <dhiru at openwall.com> in July, 2018 for JtR
# project.
#
#
# A newer and stronger algorithm was introduced with Telegram Desktop version
# 2.1.14: it uses PBKDF2-HMAC-SHA512 with higher iteration count and an initial
# sha512 hash of pass and salt (https://github.com/openwall/john/issues/4387).
# The supported Telegram Desktop file types are now the old "map0"/"map1" files
# and new "key_datas" (or similar named) files.
#
# Updated and refactored by philsmd <philsmd at hashcat.net> in October, 2020.
#
#
# This software is Copyright (c) 2018, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# pylint: disable=invalid-name,line-too-long


import os
import sys
import glob
import base64
import binascii
import xml.etree.ElementTree as ET
import struct
import hashlib

check_empty_pass = True

try:
    from Crypto.Cipher import AES
except ImportError:
    check_empty_pass = False
    sys.stderr.write("For additional functionality, please install the PyCrypto package.\n")
    sys.stderr.write("run 'pip install --user PyCrypto' to install it!\n")

PY3 = sys.version_info[0] == 3

if not PY3:
    reload(sys)
    sys.setdefaultencoding('utf8')

LocalEncryptIterCount = 4000
LocalEncryptNoPwdIterCount = 4
kStrongIterationsCount = 100000
LocalEncryptSaltSize = 32
LocalEncryptKeySize = 288 # 16 for the Message key, 16 for length and alignment and 256 bytes for the key

# these strings could be anything, our own common and distinct identifiers:
FILE_TYPE_XML = "xml"
FILE_TYPE_MAP0 = "map0"
FILE_TYPE_KEY_DATAS = "key_datas"

# Helper functions for empty password detection
# Note: if the user didn't set any password, the "Telegram Desktop" application
# uses a much smaller iteration count (if a zero-length password was detected)
# (this is probably done to improve user experience, faster response)

def xor_buf(buf1, buf2):
    out = bytearray()

    for i in range(0, 16):
        n1 = ord(buf1[i:i + 1])
        n2 = ord(buf2[i:i + 1])

        out += bytearray([n1 ^ n2])

    return bytes(out)

def aes_ige_decrypt(data, key, iv):
    # As an alternative to our aes_ige_decrypt() function we could also use:
    # from cryptg import decrypt_ige
    # from tgcrypto import ige256_decrypt
    # (are they compatible with old/new python versions ?
    #  Support for Crypto.Cipher.AES is better/guaranteed so we stick to it)

    out = b''

    cipher = AES.new(key, AES.MODE_ECB)

    x = iv[ 0:16]
    y = iv[16:32]

    for i in range(0, len(data), 16):
        d = data[i:i + 16]

        y = xor_buf(d, y)
        y = cipher.decrypt(y) # main decrypt call: AES-256-ECB
        y = xor_buf(x, y)

        out += y

        x = d

    return out

def is_correct_ige_decryption(file_path, key, data):
    checksum = data[ 0: 16]
    aes_data = data[16:288] # up to the end of the buffer

    data_a = checksum    + key[  8: 40]
    data_b = key[40: 56] + checksum     + key[56:72]
    data_c = key[72:104] + checksum
    data_d = checksum    + key[104:136]

    sha1_a = hashlib.sha1(data_a).digest()
    sha1_b = hashlib.sha1(data_b).digest()
    sha1_c = hashlib.sha1(data_c).digest()
    sha1_d = hashlib.sha1(data_d).digest()

    aes_key = sha1_a[0: 8] + sha1_b[8:20] + sha1_c[ 4:16]
    aes_iv  = sha1_a[8:20] + sha1_b[0: 8] + sha1_c[16:20] + sha1_d[0:8]

    decrypted = aes_ige_decrypt(aes_data, aes_key, aes_iv)

    digest = hashlib.sha1(decrypted).digest()

    digest = digest[0:16] # only first 16 bytes are used

    if digest == checksum:
        sys.stderr.write("ATTENTION: no password set for this file/account: '%s' (skipped)\n" % file_path)
        return True

    return False

def is_map0_empty_pass(file_path, salt_hex, data_hex):
    if not check_empty_pass:
        sys.stderr.write("ATTENTION: it couldn't be verified if a password was set for the file/account: '%s' (please install the PyCrypto package)\n" % file_path)
        return False

    salt = binascii.unhexlify(salt_hex)
    data = binascii.unhexlify(data_hex)

    key = hashlib.pbkdf2_hmac('SHA1', b'', salt, LocalEncryptNoPwdIterCount, 136)

    return is_correct_ige_decryption(file_path, key, data)

def is_key_datas_empty_pass(file_path, salt_hex, data_hex):
    if not check_empty_pass:
        sys.stderr.write("ATTENTION: it couldn't be verified if a password was set for the file/account: '%s' (please install the PyCrypto package)\n" % file_path)
        return False

    salt = binascii.unhexlify(salt_hex)
    data = binascii.unhexlify(data_hex)

    pass_hash = hashlib.sha512(salt + salt).digest() # password is empty in sha512(s + p + s)

    key = hashlib.pbkdf2_hmac('SHA512', pass_hash, salt, 1, 136) # only 1 iteration

    return is_correct_ige_decryption(file_path, key, data)

def is_valid_xml(file_path):
    # in theory we could already check here if some salt/key information can
    # be found in the parsed XML tree (but we perform this action later on)
    try:
        ET.parse(file_path)
        return True
    except:
        return False

def is_valid_tdfs(file_path):
    f = None

    try:
        f = open(file_path, "rb")
    except:
        return False

    magic = f.read(4)
    if magic != b'TDF$':
        f.close()
        return False

    version = f.read(4)

    data = f.read()

    if len(data) < 16:
        f.close()
        return False

    actual_data = data[:-16]
    checksum = data[-16:]
    len_bytes = struct.pack("<I", len(actual_data))
    calculated_checksum = hashlib.md5(actual_data + len_bytes + version + magic).digest()

    f.close()

    if calculated_checksum != checksum:
        return False

    min_len = 4 + LocalEncryptSaltSize + 4 + LocalEncryptKeySize

    if len(actual_data) < min_len:
        return False

    # check the salt length:

    salt_len = actual_data[0:4]
    salt_len = struct.unpack(">I", salt_len)[0]

    if salt_len != LocalEncryptSaltSize:
        return False

    # check the encrypted key length:

    offset = 4 + LocalEncryptSaltSize

    key_len = actual_data[offset:offset + 4]
    key_len = struct.unpack(">I", key_len)[0]

    if key_len != LocalEncryptKeySize:
        return False

    return True

# only returns TDF file names for files with valid key/salt data
# (not all the TDFS files within the folder)

def find_tdfs_files(folder):
    tdfs_files = []

    # this function searches for all TDFS files with salt and key data.
    # common file names are:
    # - old map0/map1/maps files:
    #   - these older files are likely to be located in folders like:
    #     D877F783D5D3EF8C which stands for "data" (md5("data"), different byte order)
    #     A7FDF864FBC10B77 which stands for "data#2" etc
    # - newer key_* files:
    #   - these files are likely to be located directly in the "tdata" folder:
    #     key_datas but could also be a similar file name (key_*)
    #     key_data#2s ("key_" + dataName + "s")

    files = []

    # maximum number of allowed subfolder searches:
    # (or use glob() with parameter recursive = True,
    # but that can't be restricted to max_depth)

    MAX_DEPTH = 5 # do not set this to a too small value, if we want to find
                  # something like +"tdata" +"D877F783D5D3EF8C" too

    search_path = folder + os.path.sep

    for i in range(0, MAX_DEPTH):
        files += glob.glob(search_path + "map*") + glob.glob(search_path + "key_*")

        search_path += "*" + os.path.sep

    for f in files:
        if is_valid_tdfs(f):
            tdfs_files.append(f)

    return tdfs_files

def detect_file_type(file_path):
    file_type = None
    error_msg = ""

    is_xml       = False
    is_map0      = False
    is_key_datas = False

    file_name = os.path.basename(file_path)

    # checks based on file name:

    if len(file_name) >= 4:
        if ".xml" == file_name[-4:].lower():
            is_xml = True
        elif "key_" == file_name[:4]:
            is_key_datas = True
        elif "map" == file_name[:3]:
            is_map0 = True

    # check if it is a valid TDFS file (if it is for sure not an .xml file):

    if not is_xml:
        f = None
        try:
            f = open(file_path, "rb")
        except:
            error_msg = "could not open file for reading"
            return file_type, error_msg
        magic = f.read(4)
        if magic == b'TDF$':
            # determine the algorithm of the TDFS file based on the AppVersion number
            if not is_key_datas:
                version = f.read(4)

                if len(version) != 4:
                    error_msg = "could not read AppVersion from file"
                    return file_type, error_msg

                version = struct.unpack("<I", version)[0]

                if version >= 2001014: # Telegram Desktop 2.1.14+
                    is_key_datas = True
                else:
                    is_map0 = True
        else:
            is_key_datas = False
            is_map0 = False
            # detect XML validity here too (if file extension didn't match):
            is_xml = is_valid_xml(file_path)
        f.close()

    if is_xml:
        file_type = FILE_TYPE_XML
    elif is_map0:
        file_type = FILE_TYPE_MAP0
    elif is_key_datas:
        file_type = FILE_TYPE_KEY_DATAS
    else:
        error_msg = "not a known Telegram *.xml/map*/key_* file"

    return file_type, error_msg

def parse_tdfs(file_path):
    f = None
    try:
        f = open(file_path, "rb")
    except:
        return None

    f.read(4) # TDF$ magic
    f.read(4) # AppVersion 1003008 for Telegram Desktop 1.3.8
              # AppVersion 2001014 for Telegram Desktop 2.1.14
    data = f.read()
    f.close()

    if len(data) < 16:
        return None

    actual_data = data[:-16]
    return actual_data

def process_tdfs(file_path):
    # this function assumes that a valid TDFS file was already detected
    # and already doubled-checked with is_valid_tdfs()

    # read the encrypted data
    data = parse_tdfs(file_path)
    if not data:
        return None, None

    # read the salt
    # (bytes 0-3 are the length of salt: LocalEncryptSaltSize)
    offset = 4
    salt = data[offset:offset + LocalEncryptSaltSize]

    offset += LocalEncryptSaltSize

    # read the encrypted key
    # (next 4 bytes are the length of key: LocalEncryptKeySize)
    offset += 4
    encrypted_key = data[offset:offset + LocalEncryptKeySize]

    salt = binascii.hexlify(salt)
    encrypted_key = binascii.hexlify(encrypted_key)
    if PY3:
        salt = salt.decode("ascii")
        encrypted_key = encrypted_key.decode("ascii")

    return salt, encrypted_key

def process_xml(file_path):
    root = None

    # here we could also use is_valid_xml() again:
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()
    except:
        sys.stderr.write("ERROR: '%s' is not a valid XML file\n" % file_path)
        return

    h = None
    salt = None

    for item in root:
        # the "user" key doesn't seem very useful without cleaning it up
        if item.tag == 'string':
            name = item.attrib['name']
            if name == "passcodeHash1":
                h = item.text
            if name == "passcodeSalt":
                salt = item.text
    if not h:
        sys.stderr.write("ERROR: no hash found in XML file '%s'\n" % file_path)
        return

    h = h.lower()

    if not salt:
        sys.stderr.write("ERROR: no salt found in XML file '%s'\n" % file_path)
        return
    salt = binascii.hexlify(base64.b64decode(salt))
    if PY3:
        salt = salt.decode("ascii")

    print("%s:$dynamic_1528$%s$HEX$%s" % (os.path.basename(file_path), h, salt))

def process_map0(file_path):
    if not is_valid_tdfs(file_path):
        sys.stderr.write("ERROR: '%s' is not a valid map file\n" % file_path)
        return

    salt_hex, key_hex = process_tdfs(f)

    if not salt_hex:
        sys.stderr.write("ERROR: salt could not be extracted from map* file '%s'\n" % file_path)
        return
    elif not key_hex:
        sys.stderr.write("ERROR: encrypted key could not be extracted from map* file '%s'\n" % file_path)
        return

    if not is_map0_empty_pass(file_path, salt_hex, key_hex):
        print("%s:$telegram$1*%s*%s*%s" % (os.path.basename(file_path), LocalEncryptIterCount, salt_hex, key_hex))

def process_key_datas(file_path):
    if not is_valid_tdfs(file_path):
        sys.stderr.write("ERROR: '%s' is not a valid key_* file\n" % file_path)
        return

    salt_hex, key_hex = process_tdfs(f)

    if not salt_hex:
        sys.stderr.write("ERROR: salt could not be extracted from key_* file '%s'\n" % file_path)
        return
    elif not key_hex:
        sys.stderr.write("ERROR: encrypted key could not be extracted from key_* file '%s'\n" % file_path)
        return

    if not is_key_datas_empty_pass(file_path, salt_hex, key_hex):
        print("%s:$telegram$2*%s*%s*%s" % (os.path.basename(file_path), kStrongIterationsCount, salt_hex, key_hex))

def process_file(file_path, file_type):
    if file_type == FILE_TYPE_XML:
        process_xml(file_path)
    elif file_type == FILE_TYPE_MAP0:
        process_map0(file_path)
    elif file_type == FILE_TYPE_KEY_DATAS:
        process_key_datas(file_path)

def usage(command):
    sys.stderr.write("Usage: %s <userconfing.xml file(s)> / <map0 file(s)> / <key_datas file(s)> / <path to Telegram data directory>\n" % command)
    sys.stderr.write("\nExample (Linux): %s ~/.local/share/TelegramDesktop\n" % command)
    sys.stderr.write("Example (Windows): %s \"C:/Users/Name/AppData/Roaming/Telegram Desktop\"\n" % command)

if __name__ == "__main__":
    argc = len(sys.argv)

    if argc < 2:
        usage (sys.argv[0])
        sys.exit(-1)

    for i in range(1, argc):
        file_path = sys.argv[i]

        # deal with the trailing quote ex. "...\Telegram Desktop\":
        if file_path.endswith('"'):
            file_path = file_path[:-1]

        file_list = [] # multiple files allowed for profile folder search

        if os.path.isdir(file_path):
            # we assume that this is a "Telegram Desktop" or "tdata" folder:
            # we do not allow searching for .xml files (only TDFS files)
            file_list = find_tdfs_files(file_path)
        else:
            file_list.append(file_path)

        if len(file_list) < 1:
            sys.stderr.write("ERROR: no supported key_* or map* files found in '%s'\n" % file_path)
            continue

        for f in file_list:
            file_type, error_msg = detect_file_type(f)

            if not file_type:
                sys.stderr.write("ERROR: " + error_msg + ": '%s'\n" % f)
                continue

            process_file(f, file_type)
