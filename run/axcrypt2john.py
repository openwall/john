#!/usr/bin/python3

# AxCrypt 1.x and 2.x encrypted file parser for JtR.
#
# Written in 2016 by Fist0urs <eddy.maaalou at gmail.com>.
#
# This software is Copyright (c) 2016, Fist0urs <eddy.maaalou at gmail.com>,
# Copyright (c) 2018, Dhiru Kholia, and it is hereby released to the general
# public under the following terms:
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted.
#
# PEP 8 fixes, Python 3.x, and AxCrypt 2 support: Dhiru Kholia (August, 2018)
#
# See AxCryptVersion1AlgorithmsandFileFormat.pdf and AxCryptVersion2AlgorithmsandFileFormat.pdf
# for details on the .axx file format and the algorithms involved.
#
# TODO:
#   - Detect usage of ciphers other than AES-256 in AxCrypt 2.x files (not an
#     issue in practice currently).

import sys
import struct
import binascii

# file begins with a 16 bytes constant header
GUID = b'\xc0\xb9\x07\x2e\x4f\x93\xf1\x46\xa0\x15\x79\x2c\xa1\xd9\xe8\x21'
OFFSET_TYPE = 4
SIZE_KEYDATA = 24  # size of constant in keywrap (0xA6 * 8) + size of DEK (16)
SIZE_SALT = 16
SIZE_ITERATION = 4

StructKeys = []

PY3 = sys.version_info[0] == 3

if not PY3:
    reload(sys)
    sys.setdefaultencoding("utf8")


def usage():
    sys.stderr.write('Usage: %s <axxfile> [KEY-FILE]\n\n' % sys.argv[0])
    sys.stderr.write('Script to extract hash from AxCrypt encrypted file or self-decrypting binary\n\n')
    sys.stderr.write('Optional arguments:\n  KEY-FILE			 path to optional key-file provided\n')
    sys.exit(1)


def DWORD_to_int(string_dword):
    return struct.unpack("<I", string_dword)[0]


def parse_PE(axxdata):
    i = 0

    while axxdata[i:i+16] != GUID:
        i += 1

    return axxdata[i:]


def parse_axxfile2(axxdata, header_datalen, header_datalen_offset, headertype):
    version = 2
    SIZE_KEYDATA = 144
    SIZE_WRAP_SALT = 64
    SIZE_DERIV_SALT = 32

    offset_to_keydata = header_datalen_offset + OFFSET_TYPE + 1
    offset_to_wrap_iteration = offset_to_keydata + SIZE_KEYDATA + SIZE_WRAP_SALT
    offset_to_wrap_salt = offset_to_keydata + SIZE_KEYDATA
    dword_str = axxdata[offset_to_wrap_iteration:offset_to_wrap_iteration + SIZE_ITERATION]
    wrap_salt = axxdata[offset_to_wrap_salt:offset_to_wrap_salt+SIZE_WRAP_SALT]
    wrap_iterations = DWORD_to_int(dword_str)
    wrappedkey = axxdata[offset_to_keydata:offset_to_keydata + SIZE_KEYDATA]

    offset_to_deriv_salt = offset_to_keydata + SIZE_KEYDATA + SIZE_WRAP_SALT + 4
    deriv_salt = axxdata[offset_to_deriv_salt:offset_to_deriv_salt+SIZE_DERIV_SALT]
    offset_to_deriv_iteration = offset_to_deriv_salt + SIZE_DERIV_SALT
    dword_str = axxdata[offset_to_deriv_iteration:offset_to_deriv_iteration + SIZE_ITERATION]
    deriv_iterations = DWORD_to_int(dword_str)

    return version, wrappedkey, wrap_salt, wrap_iterations, deriv_iterations, deriv_salt


def parse_axxfile(axxfile):
    stream = open(axxfile, 'rb')
    axxdata = stream.read()
    stream.close()

    # if header is 'MZ'
    if axxdata[:2] == b'\x4D\x5a':
        offset_PE_magic = struct.unpack('<L', axxdata[60:64])[0]
        # if 'PE' assume PE
        if axxdata[offset_PE_magic:offset_PE_magic+2] == b'\x50\x45':
            axxdata = parse_PE(axxdata)

    sizeof_file = len(axxdata)

    if axxdata[:16] != GUID:
        print("Be careful, GUID is different from AxCrypt's one...")

    header_datalen_offset = 16
    headertype = b'\x02' # first type encountered

    version = 1

    # headertype of dataencrypted section is 0x3f
    while headertype != 63:
        if not PY3:
            header_datalen = ord(axxdata[header_datalen_offset])
            headertype = ord(axxdata[header_datalen_offset + OFFSET_TYPE])
        else:
            header_datalen = axxdata[header_datalen_offset]
            headertype = axxdata[header_datalen_offset + OFFSET_TYPE]

        if header_datalen in (252, 253) and headertype == 13:  # Header/Trailer. Symmetric Key Wrap -> AxCrypt 2.x
            version = 2
            return parse_axxfile2(axxdata, header_datalen, header_datalen_offset, headertype)

        # probably a StructKey
        if (header_datalen == 49 and headertype == 4):
            offset_to_keydata = header_datalen_offset + OFFSET_TYPE + 1
            offset_to_salt = offset_to_keydata + SIZE_KEYDATA
            offset_to_iteration = offset_to_salt + SIZE_SALT

            dword_str = axxdata[offset_to_iteration:offset_to_iteration + SIZE_ITERATION]

            StructKeys.append({'KeyData': axxdata[offset_to_keydata:offset_to_salt],
                'salt': axxdata[offset_to_salt:offset_to_iteration]
                ,'Iteration': DWORD_to_int(dword_str)})

        header_datalen_offset += header_datalen

        if header_datalen_offset >= sizeof_file:
            print("Could not parse file, exiting...")
            sys.exit(0)

    return version, StructKeys[0]['KeyData'], StructKeys[0]['salt'], StructKeys[0]['Iteration'], None, None


if __name__ == "__main__":
    if (len(sys.argv) != 2 and len(sys.argv) != 3):
        usage()

    # A_DEK == wrapped_key
    version, wrapped_key, salt, nb_iteration, deriv_iterations, deriv_salt = parse_axxfile(sys.argv[1])

    keyfile_content = ''
    key_file_name = ''
    # dummy strip to relative path
    axxfile = sys.argv[1][sys.argv[1].rfind("/")+1:]

    if len(sys.argv) == 3:
        keyfile = open(sys.argv[2], 'rb')
        data = binascii.hexlify(keyfile.read())
        if PY3:
            data = data.decode("ascii")
        keyfile_content = '*' + data
        key_file_name = '*' + sys.argv[2][sys.argv[2].rfind("/")+1:]
        keyfile.close()

    salt = binascii.hexlify(salt)
    wrapped_key = binascii.hexlify(wrapped_key)

    if PY3:
        salt = salt.decode("ascii")
        wrapped_key = wrapped_key.decode("ascii")

    if version == 1:
        print(axxfile + key_file_name + ":$axcrypt$" + "*" + str(version) + "*" + str(nb_iteration) + "*" + salt + "*" + wrapped_key + keyfile_content)
    elif version == 2:
        deriv_salt = binascii.hexlify(deriv_salt)
        if PY3:
            deriv_salt = deriv_salt.decode("ascii")
        print(axxfile + key_file_name + ":$axcrypt$" + "*" + str(version) + "*" + str(nb_iteration) + "*" + salt + "*" + wrapped_key + keyfile_content + "*" + str(deriv_iterations) + "*" +  deriv_salt)
