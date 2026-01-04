#!/usr/bin/env python3
#
# This software is Copyright (c) 2012-2013 Dhiru Kholia <dhiru at openwall.com>
# and Copyright (c) 2013-2026 magnum,
# and is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import sys
import os

try:
    from olefile import isOleFile, OleFileIO
except ImportError:
    print(f"{os.path.basename(sys.argv[0])}: olefile python module is missing, please install your distro's", file=sys.stderr)
    print("package, eg. 'sudo apt-get install python3-olefile' if available, otherwise", file=sys.stderr)
    print("'pip install --user olefile' (activate your venv if you already did that)", file=sys.stderr)
    sys.exit(1)

PY3 = sys.version_info[0] == 3

if not PY3:
    reload(sys)
    sys.setdefaultencoding("utf8")
if PY3:
    from io import BytesIO as StringIO
else:
    from StringIO import StringIO
from struct import unpack
import binascii

def find_rc4_passinfo_xls(filename, stream):
    """
    Initial version of this function was based on a blog entry posted by
    Worawit (sleepya) at http://auntitled.blogspot.in site.

    Since then this function has been heavily modified and extended.

    http://msdn.microsoft.com/en-us/library/dd908560%28v=office.12%29
    http://msdn.microsoft.com/en-us/library/dd920360%28v=office.12%29
    """

    while True:
        pos = stream.tell()
        if pos >= stream.size:
            break  # eof

        type = unpack("<h", stream.read(2))[0]
        length = unpack("<h", stream.read(2))[0]
        data = stream.read(length)

        if type == 0x2f:  # FILEPASS
            if length == 4:  # Excel 95 XOR obfuscation
                sys.stderr.write("%s : Excel 95 XOR obfuscation detected, key : %s, hash : %s\n" % \
                    (filename, binascii.hexlify(data[0:2]), binascii.hexlify(data[2:4])))
            elif data[0:2] == b"\x00\x00":  # XOR obfuscation
                sys.stderr.write("%s : XOR obfuscation detected, key : %s, hash : %s\n" % \
                    (filename, binascii.hexlify(data[2:4]), binascii.hexlify(data[4:6])))
            elif data[0:6] == b'\x01\x00\x01\x00\x01\x00':
                # RC4 encryption header structure
                data = data[6:]
                salt = data[:16]
                verifier = data[16:32]
                verifierHash = data[32:48]
                return (salt, verifier, verifierHash)
            elif data[0:4] == b'\x01\x00\x02\x00' or data[0:4] == b'\x01\x00\x03\x00' or data[0:4] == b'\x01\x00\x04\x00':
                # If RC4 CryptoAPI encryption is used, certain storages and streams are stored in Encryption Stream
                stm = StringIO(data)
                stm.read(2)  # unused
                # RC4 CryptoAPI Encryption Header
                unpack("<h", stm.read(2))[0]  # major_version
                unpack("<h", stm.read(2))[0]  # minor_version
                unpack("<I", stm.read(4))[0]  # encryptionFlags
                headerLength = unpack("<I", stm.read(4))[0]
                unpack("<I", stm.read(4))[0]  # skipFlags
                headerLength -= 4
                unpack("<I", stm.read(4))[0]  # sizeExtra
                headerLength -= 4
                unpack("<I", stm.read(4))[0]  # algId
                headerLength -= 4
                unpack("<I", stm.read(4))[0]  # algHashId
                headerLength -= 4
                keySize = unpack("<I", stm.read(4))[0]
                if keySize == 40:
                    typ = 3
                else:
                    typ = 4
                headerLength -= 4
                unpack("<I", stm.read(4))[0]  # providerType
                headerLength -= 4
                unpack("<I", stm.read(4))[0]  # unused
                headerLength -= 4
                unpack("<I", stm.read(4))[0]  # unused
                headerLength -= 4
                CSPName = stm.read(headerLength)
                provider = CSPName.decode('utf-16').lower()
                # Encryption verifier
                saltSize = unpack("<I", stm.read(4))[0]
                assert(saltSize == 16)
                salt = stm.read(saltSize)
                encryptedVerifier = stm.read(16)
                verifierHashSize = unpack("<I", stm.read(4))[0]
                assert(verifierHashSize == 20)
                encryptedVerifierHash = stm.read(verifierHashSize)

                second_block_extra = ""
                if typ == 3:
                    offset_cur = stream.tell()
                    assert(offset_cur < 1024)

                    skip = 1024 - offset_cur
                    stream.read(skip) # ignore remaining bytes of 1st block

                    second_block_bytes = stream.read(32)
                    second_block_extra = "*%s" % binascii.hexlify(second_block_bytes).decode("ascii")

                sys.stdout.write("%s:$oldoffice$%s*%s*%s*%s%s\n" % (os.path.basename(filename),
                    typ, binascii.hexlify(salt).decode("ascii"),
                    binascii.hexlify(encryptedVerifier).decode("ascii"),
                    binascii.hexlify(encryptedVerifierHash).decode("ascii"),
                    second_block_extra))

    return None


def find_table(filename, stream):
    w_ident = stream.read(2)
    assert(w_ident == b"\xec\xa5")
    stream.read(9)  # unused
    flags = ord(stream.read(1))
    if (flags & 1) != 0:
        F = 1
    else:
        F = 0
    if (flags & 2) != 0:
        G = 1
    else:
        G = 0
    if (flags & 128) != 0:
        M = 1
    else:
        M = 0
    if F == 1 and M == 1:
        stream.read(2)  # unused
        i_key = stream.read(4)
        sys.stderr.write("%s : XOR obfuscation detected, Password Verifier : %s\n" % \
                (filename, binascii.hexlify(i_key)))
        return "none"
    if F == 0:
        sys.stderr.write("%s : Document is not encrypted!\n" % (filename))
        return "none"
    if G == 0:
        return "0Table"
    else:
        return "1Table"


def find_ppt_type(filename, stream):
    # read CurrentUserRec's RecordHeader
    stream.read(2)  # unused
    unpack("<h", stream.read(2))[0]  # recType
    unpack("<L", stream.read(4))[0]  # recLen
    # read rest of CurrentUserRec
    unpack("<L", stream.read(4))[0]  # size
    unpack("<L", stream.read(4))[0]  # headerToken
    offsetToCurrentEdit = unpack("<L", stream.read(4))[0]
    return offsetToCurrentEdit


def find_rc4_passinfo_doc(filename, stream):
    major_version = unpack("<h", stream.read(2))[0]
    minor_version = unpack("<h", stream.read(2))[0]

    if major_version == 1 or minor_version == 1:
        data = stream.read(48)
        salt = data[:16]
        verifier = data[16:32]
        verifierHash = data[32:48]
        return (salt, verifier, verifierHash)
    elif major_version >= 2 and minor_version == 2:
        # RC4 CryptoAPI Encryption Header
        unpack("<I", stream.read(4))[0]  # encryptionFlags
        headerLength = unpack("<I", stream.read(4))[0]
        unpack("<I", stream.read(4))[0]  # skipFlags
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # sizeExtra
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # algId
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # algHashId
        headerLength -= 4
        keySize = unpack("<I", stream.read(4))[0]  # keySize
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # providerType
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # unused
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # unused
        headerLength -= 4
        CSPName = stream.read(headerLength)
        provider = CSPName.decode('utf-16').lower()
        if keySize == 128:
            typ = 4
        elif keySize == 40:
            typ = 3
        elif keySize == 56:
            typ = 5
        else:
            sys.stderr.write("%s : invalid keySize %u\n" % (filename, keySize))

        # Encryption verifier
        saltSize = unpack("<I", stream.read(4))[0]
        assert(saltSize == 16)
        salt = stream.read(saltSize)
        encryptedVerifier = stream.read(16)
        verifierHashSize = unpack("<I", stream.read(4))[0]
        assert(verifierHashSize == 20)
        encryptedVerifierHash = stream.read(verifierHashSize)

        second_block_extra = ""
        if typ == 3:
            offset_cur = stream.tell()
            assert(offset_cur < 512)

            skip = 512 - offset_cur
            stream.read(skip) # ignore remaining bytes of 1st block

            second_block_bytes = stream.read(32)
            second_block_extra = "*%s" % binascii.hexlify(second_block_bytes).decode("ascii")

        summary_extra = ""
        if have_summary:
            summary_extra = ":::%s::%s" % (summary, filename)

        sys.stdout.write("%s:$oldoffice$%s*%s*%s*%s%s%s\n" % (os.path.basename(filename),
            typ, binascii.hexlify(salt).decode("ascii"),
            binascii.hexlify(encryptedVerifier).decode("ascii"),
            binascii.hexlify(encryptedVerifierHash).decode("ascii"),
            second_block_extra,
            summary_extra))

    else:
        sys.stderr.write("%s : Cannot find RC4 pass info, is the document encrypted?\n" % filename)


def find_rc4_passinfo_ppt(filename, stream, offset):
    stream.read(offset)  # unused
    # read UserEditAtom's RecordHeader
    stream.read(2)  # unused
    recType = unpack("<h", stream.read(2))[0]
    recLen = unpack("<L", stream.read(4))[0]
    if recLen != 32:
        sys.stderr.write("%s : Document is not encrypted!\n" % (filename))
        return False
    if recType != 0x0FF5:
        sys.stderr.write("%s : Document is corrupt!\n" % (filename))
        return False
    # read reset of UserEditAtom
    unpack("<L", stream.read(4))[0]  # lastSlideRef
    unpack("<h", stream.read(2))[0]  # version
    ord(stream.read(1))  # minorVersion
    ord(stream.read(1))  # majorVersion
    unpack("<L", stream.read(4))[0]  # offsetLastEdit
    offsetPersistDirectory = unpack("<L", stream.read(4))[0]
    unpack("<L", stream.read(4))[0]  # docPersistIdRef
    unpack("<L", stream.read(4))[0]  # persistIdSeed
    unpack("<h", stream.read(2))[0]  # lastView
    unpack("<h", stream.read(2))[0]  # unused
    encryptSessionPersistIdRef = unpack("<h", stream.read(2))[0]
    # if( offset.LowPart < userAtom.offsetPersistDirectory ||
    # userAtom.offsetPersistDirectory < userAtom.offsetLastEdit )
    # goto CorruptFile;
    # jump and read RecordHeader
    stream.seek(offsetPersistDirectory, 0)
    stream.read(2)  # unused
    recType = unpack("<h", stream.read(2))[0]
    recLen = unpack("<L", stream.read(4))[0]
    # BUGGY: PersistDirectoryAtom and PersistDirectoryEntry processing
    i = 0
    stream.read(4)  # unused
    while i < encryptSessionPersistIdRef:
        i += 1
        try:
            persistOffset = unpack("<L", stream.read(4))[0]
        except:
            # sys.stderr.write("%s : Document is corrupt, or %s has a bug\n" % (filename, sys.argv[0]))
            return False
    # print persistOffset
    # go to the offset of encryption header
    stream.seek(persistOffset, 0)
    # read RecordHeader
    stream.read(2)  # unused
    recType = unpack("<h", stream.read(2))[0]
    recLen = unpack("<L", stream.read(4))[0]
    major_version = unpack("<h", stream.read(2))[0]
    minor_version = unpack("<h", stream.read(2))[0]

    if major_version >= 2 and minor_version == 2:
        # RC4 CryptoAPI Encryption Header
        unpack("<I", stream.read(4))[0]  # encryptionFlags
        headerLength = unpack("<I", stream.read(4))[0]
        unpack("<I", stream.read(4))[0]  # skipFlags
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # sizeExtra
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # algId
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # algHashId
        headerLength -= 4
        keySize = unpack("<I", stream.read(4))[0]  # keySize
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # providerType
        headerLength -= 4
        unpack("<I", stream.read(4))[0]
        headerLength -= 4
        unpack("<I", stream.read(4))[0]
        headerLength -= 4
        CSPName = stream.read(headerLength)
        typ = None
        if keySize == 128:
            typ = 4
        elif keySize == 40:
            typ = 3
        elif keySize == 0:
            typ = 3
        else:
            return False
        # Encryption verifier
        saltSize = unpack("<I", stream.read(4))[0]
        assert(saltSize == 16)
        salt = stream.read(saltSize)
        encryptedVerifier = stream.read(16)
        verifierHashSize = unpack("<I", stream.read(4))[0]
        assert(verifierHashSize == 20)
        encryptedVerifierHash = stream.read(verifierHashSize)

        second_block_extra = ""
        if typ == 3:
            # seek to the start and afterwards back to current pos:
            offset_cur = stream.tell()
            stream.seek(0)
            second_block_bytes = stream.read(32)
            second_block_extra = "*%s" % binascii.hexlify(second_block_bytes).decode("ascii")
            stream.seek(offset_cur) # to be safe, seek back to old pos (not really needed)

        sys.stdout.write("%s:$oldoffice$%s*%s*%s*%s%s\n" % (os.path.basename(filename),
            typ, binascii.hexlify(salt).decode("ascii"),
            binascii.hexlify(encryptedVerifier).decode("ascii"),
            binascii.hexlify(encryptedVerifierHash).decode("ascii"),
            second_block_extra))
        return True
    else:
        # sys.stderr.write("%s : Cannot find RC4 pass info, is the document encrypted?\n" % filename)
        return False


def find_rc4_passinfo_ppt_bf(filename, stream, offset):
    """We don't use stream and offset anymore! The current method is a bit slow for large files."""
    sys.stderr.write("This can take a while, please wait.\n")
    stream = open(filename, "rb")
    original = stream.read()
    found = False
    for i in range(0, len(original)):
        data = original[i:i+384]
        stream = StringIO(data)
        if len(data) < 128:
            return
        major_version = unpack("<h", stream.read(2))[0]
        minor_version = unpack("<h", stream.read(2))[0]
        if major_version >= 2 and minor_version == 2:
            pass
        else:
            continue
        # RC4 CryptoAPI Encryption Header, Section 2.3.5.1 - RC4 CryptoAPI
        # Encryption Header in [MS-OFFCRYPTO].pdf
        unpack("<I", stream.read(4))[0]  # encryptionFlags
        headerLength = unpack("<I", stream.read(4))[0]
        unpack("<I", stream.read(4))[0]  # skipFlags
        headerLength -= 4
        sizeExtra = unpack("<I", stream.read(4))[0]  # sizeExtra
        headerLength -= 4
        algId = unpack("<I", stream.read(4))[0]  # algId, 0x00006801 (RC4 encryption)
        headerLength -= 4
        algHashId = unpack("<I", stream.read(4))[0]  # algHashId, 0x00008004 (SHA-1)
        if not type or (sizeExtra != 0) or (algId != 0x6801) or (algHashId != 0x8004):
                continue
        headerLength -= 4
        keySize = unpack("<I", stream.read(4))[0]  # keySize, If set to 0, it MUST be interpreted as 40
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # providerType
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # unused
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # unused
        headerLength -= 4
        CSPName = stream.read(headerLength)
        typ = None
        if keySize == 128:
            typ = 4
        elif keySize == 40:
            typ = 3
        elif keySize == 0:
            typ = 3
        else:
            continue

        # Encryption verifier
        saltSize = unpack("<I", stream.read(4))[0]
        assert(saltSize == 16)
        salt = stream.read(saltSize)
        encryptedVerifier = stream.read(16)
        verifierHashSize = unpack("<I", stream.read(4))[0]
        assert(verifierHashSize == 20)
        encryptedVerifierHash = stream.read(verifierHashSize)

        second_block_extra = ""
        #  TODO: how to test this BF thing?
        # if typ == 3:
        #     offset_cur = stream.tell()
        #     assert(offset_cur < 512)
        #
        #     skip = 512 - offset_cur
        #     stream.read(skip) # ignore remaining bytes of 1st block
        #
        #     second_block_bytes = stream.read(32)
        #     second_block_extra = "*%s" % binascii.hexlify(second_block_bytes).decode("ascii")

        found = True
        sys.stdout.write("%s:$oldoffice$%s*%s*%s*%s%s\n" % (os.path.basename(filename),
            typ, binascii.hexlify(salt).decode("ascii"),
            binascii.hexlify(encryptedVerifier).decode("ascii"),
            binascii.hexlify(encryptedVerifierHash).decode("ascii"),
            second_block_extra))

    if not found:
        sys.stderr.write("%s : Cannot find RC4 pass info, is document encrypted?\n" % filename)


def process_access_2007_older_crypto(filename):
    """Dirty hash extractor for MS Office 2007 .accdb files which use CryptoAPI
    based encryption."""

    original = open(filename, "rb").read()

    for i in range(0, len(original)):
        data = original[i:40960]  # is this limit on data reasonable?
        stream = StringIO(data)
        if len(data) < 128:
            return

        major_version = unpack("<h", stream.read(2))[0]
        minor_version = unpack("<h", stream.read(2))[0]

        # RC4 CryptoAPI Encryption Header, Section 2.3.5.1 - RC4 CryptoAPI
        # Encryption Header in [MS-OFFCRYPTO].pdf
        unpack("<I", stream.read(4))[0]  # encryptionFlags
        headerLength = unpack("<I", stream.read(4))[0]
        unpack("<I", stream.read(4))[0]  # skipFlags
        headerLength -= 4
        sizeExtra = unpack("<I", stream.read(4))[0]  # sizeExtra
        headerLength -= 4
        algId = unpack("<I", stream.read(4))[0]  # algId, 0x00006801 (RC4 encryption)
        headerLength -= 4
        algHashId = unpack("<I", stream.read(4))[0]  # algHashId, 0x00008004 (SHA-1)
        headerLength -= 4
        keySize = unpack("<I", stream.read(4))[0]  # keySize, If set to 0, it MUST be interpreted as 40
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # providerType
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # unused
        headerLength -= 4
        unpack("<I", stream.read(4))[0]  # unused
        headerLength -= 4
        CSPName = stream.read(headerLength)
        try:
            provider = CSPName.decode('utf-16')
            if provider.startswith("Microsoft Base Cryptographic Provider"):
                pass
        except:
            continue

        typ = None
        if keySize == 128:
            typ = 4
        elif keySize == 40:
            typ = 3
        elif keySize == 0:
            typ = 3
        else:
            # sys.stderr.write("%s : invalid keySize %u\n" % (filename, keySize))
            continue

        if not type or (sizeExtra != 0) or (algId != 0x6801) or (algHashId != 0x8004):
            continue

        # Encryption verifier
        saltSize = unpack("<I", stream.read(4))[0]
        assert(saltSize == 16)
        salt = stream.read(saltSize)
        encryptedVerifier = stream.read(16)
        verifierHashSize = unpack("<I", stream.read(4))[0]
        assert(verifierHashSize == 20)
        encryptedVerifierHash = stream.read(verifierHashSize)

        second_block_extra = ""
        if typ == 3:
            offset_cur = stream.tell()
            assert(offset_cur < 512)

            skip = 512 - offset_cur
            stream.read(skip) # ignore remaining bytes of 1st block

            second_block_bytes = stream.read(32)
            second_block_extra = "*%s" % binascii.hexlify(second_block_bytes).decode("ascii")

        sys.stdout.write("%s:$oldoffice$%s*%s*%s*%s%s\n" % (os.path.basename(filename),
            typ, binascii.hexlify(salt).decode("ascii"),
            binascii.hexlify(encryptedVerifier).decode("ascii"),
            binascii.hexlify(encryptedVerifierHash).decode("ascii"),
            second_block_extra))
        break


from xml.etree.ElementTree import ElementTree
import base64


def process_new_office(filename):
    # detect version of new Office used by reading "EncryptionInfo" stream
    ole = OleFileIO(filename)
    stream = ole.openstream("EncryptionInfo")
    major_version = unpack("<h", stream.read(2))[0]
    minor_version = unpack("<h", stream.read(2))[0]
    encryptionFlags = unpack("<I", stream.read(4))[0]  # encryptionFlags
    if encryptionFlags == 16:  # fExternal
        sys.stderr.write("%s : An external cryptographic provider is not supported!\n" % filename)
        return -1

    if major_version == 0x04 and minor_version == 0x04:
        # Office 2010 and 2013 file detected
        if encryptionFlags != 0x40:  # fAgile
            sys.stderr.write("%s : The encryption flags are not consistent with the encryption type\n" % filename)
            return -2

        # rest of the data is in XML format
        data = stream.read()
        xml_metadata_parser(data, filename)
    else:
        # Office 2007 file detected, process CryptoAPI Encryption Header
        stm = stream
        headerLength = unpack("<I", stm.read(4))[0]
        unpack("<I", stm.read(4))[0]  # skipFlags
        headerLength -= 4
        unpack("<I", stm.read(4))[0]  # sizeExtra
        headerLength -= 4
        unpack("<I", stm.read(4))[0]  # algId
        headerLength -= 4
        unpack("<I", stm.read(4))[0]  # algHashId
        headerLength -= 4
        keySize = unpack("<I", stm.read(4))[0]
        headerLength -= 4
        unpack("<I", stm.read(4))[0]  # providerType
        headerLength -= 4
        unpack("<I", stm.read(4))[0]  # unused
        headerLength -= 4
        unpack("<I", stm.read(4))[0]  # unused
        headerLength -= 4
        CSPName = stm.read(headerLength)
        provider = CSPName.decode('utf-16').lower()
        # Encryption verifier
        saltSize = unpack("<I", stm.read(4))[0]
        assert(saltSize == 16)
        salt = stm.read(saltSize)
        encryptedVerifier = stm.read(16)
        verifierHashSize = unpack("<I", stm.read(4))[0]
        encryptedVerifierHash = stm.read(verifierHashSize)

        sys.stdout.write("%s:$office$*%d*%d*%d*%d*%s*%s*%s\n" % \
            (os.path.basename(filename), 2007, verifierHashSize,
             keySize, saltSize, binascii.hexlify(salt).decode("ascii"),
            binascii.hexlify(encryptedVerifier).decode("ascii"),
            binascii.hexlify(encryptedVerifierHash)[0:64].decode("ascii")))


def xml_metadata_parser(data, filename):
    # Assuming Office 2010 and 2013 file
    data = StringIO(data)
    tree = ElementTree()
    tree.parse(data)

    tree_iter = tree.iter if hasattr(ElementTree, 'iter') else tree.getiterator
    for node in tree_iter('{http://schemas.microsoft.com/office/2006/keyEncryptor/password}encryptedKey'):
        spinCount = node.attrib.get("spinCount")
        assert(spinCount)
        saltSize = node.attrib.get("saltSize")
        assert(saltSize)
        blockSize = node.attrib.get("blockSize")
        assert(blockSize)
        keyBits = node.attrib.get("keyBits")
        hashAlgorithm = node.attrib.get("hashAlgorithm")
        if hashAlgorithm == "SHA1":
            version = 2010
        elif hashAlgorithm == "SHA512":
            version = 2013
        else:
            sys.stderr.write("%s uses un-supported hashing algorithm %s, please file a bug! \n" \
                    % (filename, hashAlgorithm))
            return -3
        cipherAlgorithm = node.attrib.get("cipherAlgorithm")
        if not cipherAlgorithm.find("AES") > -1:
            sys.stderr.write("%s uses un-supported cipher algorithm %s, please file a bug! \n" \
                % (filename, cipherAlgorithm))
            return -4

        saltValue = node.attrib.get("saltValue")
        assert(saltValue)
        encryptedVerifierHashInput = node.attrib.get("encryptedVerifierHashInput")
        encryptedVerifierHashValue = node.attrib.get("encryptedVerifierHashValue")
        if PY3:
            encryptedVerifierHashValue = binascii.hexlify(base64.decodebytes(encryptedVerifierHashValue.encode()))
        else:
            encryptedVerifierHashValue = binascii.hexlify(base64.decodestring(encryptedVerifierHashValue.encode()))

        if PY3:
            saltAscii = binascii.hexlify(base64.decodebytes(saltValue.encode())).decode("ascii")
            encryptedVerifierHashAscii = binascii.hexlify(base64.decodebytes(encryptedVerifierHashInput.encode())).decode("ascii")
        else:
            saltAscii = binascii.hexlify(base64.decodestring(saltValue.encode())).decode("ascii")
            encryptedVerifierHashAscii = binascii.hexlify(base64.decodestring(encryptedVerifierHashInput.encode())).decode("ascii")

        sys.stdout.write("%s:$office$*%d*%d*%d*%d*%s*%s*%s\n" % \
            (os.path.basename(filename), version,
            int(spinCount), int(keyBits), int(saltSize),
            saltAscii,
            encryptedVerifierHashAscii,
            encryptedVerifierHashValue[0:64].decode("ascii")))
        return 0


have_summary = False
summary = []

import re
from binascii import unhexlify


def remove_html_tags(data):
    p = re.compile(r'<.*?>', re.DOTALL)
    return p.sub('', str(data))


def remove_extra_spaces(data):
    p = re.compile(r'\s+')
    return p.sub(' ', data)


def process_file(filename):
    # Test if a file is an OLE container
    try:
        f = open(filename, "rb")
        data = f.read(81920)  # is this enough?
        if data[0:2] == b"PK":
            sys.stderr.write("%s : zip container found, file is " \
                        "unencrypted?, invalid OLE file!\n" % filename)
            f.close()
            return 1
        f.close()

        # ACCDB handling hack for MS Access >= 2007 (Office 12)
        accdb_magic = b"Standard ACE DB"
        accdb_xml_start = b'<?xml version="1.0"'
        accdb_xml_trailer = b'</encryption>'
        if accdb_magic in data and accdb_xml_start in data:
            # find start and the end of the XML metadata stream
            start = data.find(accdb_xml_start)
            trailer = data.find(accdb_xml_trailer)
            xml_metadata_parser(data[start:trailer+len(accdb_xml_trailer)], filename)
            return
        elif accdb_magic in data:  # Access 2007 files using CryptoAPI
            process_access_2007_older_crypto(filename)
            return

        # OneNote handling hack for OneNote versions >= 2013, see [MS-ONESTORE].pdf
        onenote_magic = unhexlify("e4525c7b8cd8")
        onenote_xml_start = b'<?xml version="1.0"'
        onenote_xml_trailer = b'</encryption>'
        if data.startswith(onenote_magic) and onenote_xml_start in data:
            # find start and the end of the XML metadata stream
            start = data.find(onenote_xml_start)
            trailer = data.find(onenote_xml_trailer)
            xml_metadata_parser(data[start:trailer+len(onenote_xml_trailer)], filename)
            return

        if not isOleFile(filename):
            sys.stderr.write("%s : Invalid OLE file\n" % filename)
            return 1
    except Exception:
        e = sys.exc_info()[1]
        import traceback
        traceback.print_exc()
        sys.stderr.write("%s : OLE check failed, %s\n" % (filename, str(e)))
        return 2

    # Open OLE file:
    ole = OleFileIO(filename)

    stream = None

    # find "summary" streams
    global have_summary, summary
    have_summary = False
    summary = []

    for streamname in ole.listdir():
        streamname = streamname[-1]
        if streamname[0] == "\005":
            have_summary = True
            props = ole.getproperties(streamname)
            for k, v in props.items():
                if v is None:
                    continue
                if not PY3:
                    if not isinstance(v, unicode): # We are only interested in strings
                        continue
                else:
                    if not isinstance(v, str): # We are only interested in strings
                        continue
                v = remove_html_tags(v)
                v = v.replace(":", "")
                v = remove_extra_spaces(v)
                #words = v.split()
                #words = filter(lambda x: len(x) < 20, words)
                #v = " ".join(words)
                summary.append(v)
    summary = " ".join(summary)
    summary = remove_extra_spaces(summary)

    if ["EncryptionInfo"] in ole.listdir():
        # process Office 2003 / 2010 / 2013 files
        return process_new_office(filename)
    if ["Workbook"] in ole.listdir():
        stream = "Workbook"
    elif ["Book"] in ole.listdir():
        stream = "Book"
    elif ["WordDocument"] in ole.listdir():
        typ = 1
        sdoc = ole.openstream("WordDocument")
        stream = find_table(filename, sdoc)
        if stream == "none":
            return 5

    elif ["PowerPoint Document"] in ole.listdir():
        stream = "Current User"
    else:
        sys.stderr.write("%s : No supported streams found\n" % filename)
        return 2

    try:
        workbookStream = ole.openstream(stream)
    except:
        import traceback
        traceback.print_exc()
        sys.stderr.write("%s : stream %s not found!\n" % (filename, stream))
        return 2

    if workbookStream is None:
        sys.stderr.write("%s : Error opening stream, %s\n" % filename)
        (filename, stream)
        return 3

    if stream == "Workbook" or stream == "Book":
        typ = 0
        passinfo = find_rc4_passinfo_xls(filename, workbookStream)
        if passinfo is None:
            return 4
    elif stream == "0Table" or stream == "1Table":
        passinfo = find_rc4_passinfo_doc(filename, workbookStream)
        if passinfo is None:
            return 4
    else:
        sppt = ole.openstream("Current User")
        offset = find_ppt_type(filename, sppt)
        sppt = ole.openstream("PowerPoint Document")
        ret = find_rc4_passinfo_ppt(filename, sppt, offset)
        if not ret:
            find_rc4_passinfo_ppt_bf(filename, sppt, offset)

        return 6

    (salt, verifier, verifierHash) = passinfo

    summary_extra = ""
    if have_summary:
        summary_extra = ":::%s::%s" % (summary, filename)

    sys.stdout.write("%s:$oldoffice$%s*%s*%s*%s%s\n" % (os.path.basename(filename),
        typ, binascii.hexlify(salt).decode("ascii"),
        binascii.hexlify(verifier).decode("ascii"),
        binascii.hexlify(verifierHash).decode("ascii"),
        summary_extra))

    workbookStream.close()
    ole.close()

    return 0

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <encrypted Office file(s)>\n" % sys.argv[0])
        sys.exit(1)

    # set_debug_mode(1)

    for i in range(1, len(sys.argv)):
        if not PY3:
            ret = process_file(sys.argv[i].decode("utf8"))
        else:
            ret = process_file(sys.argv[i])
