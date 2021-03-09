#!/usr/bin/python3

# This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Written in August of 2017 based on PGPDesktop10.0.1_Source.zip.
#
# Tested with Symantec Encryption Desktop (SED) 10.4.1 MP1 running on Windows 7
# SP1 and macOS Sierra. Also tested with PGP 8.0 running on Windows XP SP3.

import os
import sys
import struct
from binascii import hexlify

PY3 = sys.version_info[0] == 3

"""
Random notes on PGP Virtual Disk feature.

The following files are informative,

clients2/disklib/shared/PGPDiskLib.c
clients2/disktool/shared/disktool-main.c
clients2/portable/qslib/common/PGPqsInterface.c
clients2/shared/PGPDiskTypes.h

See following functions,

sValidateUserPassphrase (clients2/disklib/shared/PGPDiskLib.c)
PGPDiskUtilUserPropsRef
kPGPDiskUtilRet_BadPassphrase
PGPDiskUtilMountDisk -> sOpenPGPDisk ->
PGPdiskUserEnableCiphering
CPGPdiskDiskImp::Mount
CPGPdiskHeaders::ReadHeaders

From clients2/diskengine/shared/CPGPdiskHeaders.cpp,

struct OnDiskHeaderInfo // parse this to get salt

From clients2/diskengine/shared/CPGPdiskUser.cpp,

struct OnDiskUserInfo  // parse this to get user records
struct OnDiskUserWithSym

// SymmetricKey stores a symmetric, unexpanded cryptographic key.
union SymmetricKey
{
        PGPByte         bytes[128];
        PGPUInt32       dwords[128/sizeof(PGPUInt32)];
};

typedef SymmetricKey EncryptedKey;

// CheckBytes contains 8 bytes of data for passphrase verification.
struct CheckBytes
{
        PGPByte bytes[16];
};

// PassphraseSalt contains 8 salt bytes.
union PassphraseSalt
{
        PGPByte         bytes[16];
        PGPUInt32       dwords[16/sizeof(PGPUInt32)];
};

// PassphraseKeyInfo stores a session key encrypted with a given
// passphrase. (The salt is stored separately in the main PGPdisk file
// header.)
struct PassphraseKeyInfo
{
        EncryptedKey    encryptedKey;
        CheckBytes      checkBytes;

        PGPUInt16       hashReps;       // # of hashes on passphrase
        PGPUInt16       reserved1;
        PGPUInt32       reserved2;
};

struct OnDiskUserInfo
{
        enum
        {
                kUserMagic              = 'RESU',
                kUserWithSymType        = 'MMYS',
                kUserWithPubType        = 'YEKP',
        };

        PGPUInt32       userMagic;
        PGPUInt32       userType;
        PGPUInt32       userSize;
        PGPUInt32       readOnly        : 1;
        PGPUInt32       locked          : 1;
        PGPUInt32       adminUser       : 1;
        PGPUInt32       disabled        : 1;
        PGPUInt32       unused          : 28;
        PGPUInt32       reserved[4];
};

struct OnDiskUserWithSym
{
        OnDiskUserInfo header;

        char userName[kPGPdiskMaxUserNameSize + 1];

        Crypto::PassphraseKeyInfo keyInfo;
};

// Main disk records

struct OnDiskHeaderInfo
{
        enum
        {
                kReservedHeaderBlocks       = 4,
                kMaxBlocksHeader            = 128,
                kReservedSparseHeaderBlocks = kMaxBlocksHeader,
        };

        enum
        {
                kHeaderMagic    = 'dPGP', // backwards since little-endian

                kMainType       = 'NIAM',
                kUserType       = 'RESU',
                kOldPubKeyType  = 'YEKP',
                kPortableType   = 'TROP',
        };

        PGPUInt32  headerMagic;
        PGPUInt32  headerType;  // One of the HeaderType enums
        PGPUInt32  headerSize;  // Total size of this header, in bytes

        PGPUInt32  headerCRC;   // CRC of this header
        PGPUInt64  nextHeaderOffset; // Offset to next header from file start
                                     // 0 = no additional headers
        PGPUInt32  reserved[2];
};

struct OnDiskMainHeader
{
        enum
        {
                kMajorVersion           = 7,
                kMinorVersion           = 0,

                kCompatMajorVersion     = 1,
                kPresparseMajorVersion  = 6,
                kPreSubKeyMajorVersion  = 5,
                kMaxSizeRoot            = 256,

                kPortableMajorVersion   = kPresparseMajorVersion,
                kPortableMinorVersion   = 1,
        };

        OnDiskHeaderInfo hdrInfo;

        PGPUInt8        majorVersion;
        PGPUInt8        minorVersion;
        PGPUInt16       reserved;

        PGPUInt64       numFileBlocks;    // Size of the file, in blocks
        PGPUInt64       numHeaderBlocks;  // Size of leading header data
        PGPUInt64       numDataBlocks;    // Size of encrypted data

        PGPdiskEncryptionAlgorithm  algorithm;     // unsigned int, likely
        Crypto::PassphraseSalt      salt;

        PGPUInt32       isBeingReEncrypted : 1;    // is disk being reencrypted?
        PGPUInt32       isWiped            : 1;    // users wiped?
        PGPUInt32       usesCustomTimeout  : 1;    // custom timeout?
        PGPUInt32       unused1            : 2;    // used on Mac version
        PGPUInt32       isSparse           : 1;    // sparse disk format
        PGPUInt32       unused             : 28;

        // Note:  There are 30 undocumented bits in this header.

        PGPUInt32       customTimeout;             // custom unmount timeout
        PGPUInt64       numBlocksReEncrypted;      // number of blocks reencrypted

        PGPUTF8         defaultRoot[kMaxSizeRoot]; // Preferred mount point
};

enum PGPdiskEncryptionAlgorithm_
{
        kPGPdiskInvalidAlgorithm        = 0,
        kPGPdiskCopyDataAlgorithm       = 1,
        kPGPdiskOldCAST5Algorithm       = 2,
        kPGPdiskCAST5Algorithm          = 3,
        kPGPdiskTwoFishAlgorithm        = 4,
        kPGPdiskAES256Algorithm         = 5,
        kPGPdiskAESAlgorithm            = 5,    /* two names for AES256 */
        kPGPdiskEMEAES256Algorithm      = 6,
        kPGPdiskEMEAESAlgorithm         = 6,
        kPGPdiskEME2AES256Algorithm     = 7,
        kPGPdiskEME2AESAlgorithm        = 7,

        /* All user-defined algorithms must be > 1000 */
        kPGPdiskDummyAlgorithm          = 0xFFFFFFFF    // force size to 4 bytes
};

enum PGPdiskDiskFormat_
{
        kPGPdiskDiskFormat_V6      = 0, /* Version 6 disk (PGP 7.0, 7.1, 8.0 Win32; PGP 8.0 Mac OS X) */
        kPGPdiskDiskFormat_OS9     = 1, /* (PGP any version Mac OS 9) */

        kPGPdiskDiskFormat_Invalid = 0xFFFFFFFF

};

#define kPGPdiskMaxUserNameSize 127

Next -> password validation login -> CPGPdiskUser::EnableCiphering
(clients2/diskengine/shared/CPGPdiskUser.cpp) -> DecryptPassphraseKey
(clients2/shared/disk/NativeCryptoModule/UNativeCryptoModule.cpp)
-> HashSaltSchedulePassphrase ->


Also look at "PGPdiskOnDiskPortableHeader" structure. We should be able to
support such "disk images" as well but I could not find a way to force creation
of such headers.

sDecryptDiskKeyWithSym

clients2/diskengine/osx/src/pgpDiskEngineDisk.c (most important file)

"""

OnDiskMainHeader_fmt = "< 4s 4s I I Q 8s " + "B B H Q Q Q I 16s Q I Q 256s"
OnDiskMainHeader_size = struct.calcsize(OnDiskMainHeader_fmt)
OnDiskUserWithSym_fmt = "< 4s 4s I I 16s 128s 128s 16s H 6s"
OnDiskUserWithSym_size = struct.calcsize(OnDiskUserWithSym_fmt)


def process_file(filename):
    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    data = f.read(4096)  # 4KiB

    for i in range(0, len(data) - OnDiskMainHeader_size):
        idata = data[i:i+OnDiskMainHeader_size]

        fields = struct.unpack(OnDiskMainHeader_fmt, idata)
        headerMagic, headerType, headerSize, headerCRC, nextHeaderOffset, reserved, majorVersion, minorVersion, _, _, _, _, algorithm, salt, something, customTimeout, numBlocksReEncrypted, defaultRoot  = fields[0:18]
        if headerMagic == b"PGPd" and headerType == b"MAIN":
            if algorithm != 7 and algorithm != 6 and algorithm != 5 and algorithm != 4 and algorithm != 3:
                sys.stderr.write("Only AES-256, Twofish, CAST5, EME-AES, EME2-AES algorithms are supported currently. Found (%d) instead!\n" % algorithm)
                return
            if majorVersion != 7 and majorVersion != 6:
                sys.stderr.write("Untested majorVersion (%d) found, not generating a hash!\n" % majorVersion)
                return
            # print(fields)
            # print(nextHeaderOffset)
            salt = hexlify(salt)
            if PY3:
                salt = str(salt, 'ascii')
            break

    # Read data from nextHeaderOffset, nextHeaderOffset can point to almost the end of the file!
    f.seek(nextHeaderOffset, 0)
    data = f.read(1<<20)  # 1 MB

    for i in range(0, len(data) - OnDiskUserWithSym_size):
        idata = data[i:i+OnDiskUserWithSym_size]

        fields = struct.unpack(OnDiskUserWithSym_fmt, idata)
        userMagic, userType, userSize, _, reserved, userName, EncryptedKey, CheckBytes, iterations, reserved2 = fields[0:10]
        if userMagic == b"USER" and userType == b"SYMM":
            # print(fields)
            userName = userName.strip(b"\x00")
            if PY3:
                userName = str(userName, 'utf8')
            if algorithm == 3:  # CAST5
                assert(CheckBytes[8:16] == b"\x00\x00\x00\x00\x00\x00\x00\x00")
            CheckBytes = hexlify(CheckBytes)
            if PY3:
                CheckBytes = str(CheckBytes, 'ascii')
            print("%s:$pgpdisk$0*%s*%s*%s*%s" % (userName, algorithm, iterations, salt, CheckBytes))

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [PGP Virtual Disk .pgd file(s)]\n" % sys.argv[0])

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
