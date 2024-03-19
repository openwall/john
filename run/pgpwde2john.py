#!/usr/bin/env python

# This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Written in August of 2017 based on PGPDesktop10.0.1_Source.zip.
#
# Only tested with Symantec Encryption Desktop 10.4.1 MP1 running on Ubuntu
# 12.04.5 LTS, Ubuntu 14.04 LTS, and Windows 7 SP1.

import os
import sys
import struct
from binascii import hexlify

PY3 = sys.version_info[0] == 3

"""
Random notes on PGP WDE.

$ pgpwde --auth --disk 4 -p 12345678

$ gdb --args /usr/bin/pgpwde --verify-user -p 12345678
Breakpoint 2, 0x00007ffff522035f in pgpWDEGetUserKeysWithPassphrase () from /usr/lib/libpgpwdeengine.so.0

The following files are informative,

clients2/wde/wdelib/src/pgpWDEUser.c
clients2/wde/bootguard/stage2/auth.c
clients2/wde/wdelib/include/pgpWDEUser.h
clients2/wde/wdelib/src/pgpSDKInterface-bootguard.c

kPGPdiskMaxUserNameSize = 127
PGP_WDE_RECORD_SALT_SIZE = 16
kPGPHashAlgorithm_SHA = 2

Whole Disk Recovery Token (WDRT)

BootGuard File System (BGFS) <-- We don't need to implement this when using our
structure brute-forcing logic.

typedef struct pgpDiskOnDiskUserWithSym_
{
        /** sizeof(pgpDiskOnDiskUserWithSym) */
        PGPUInt16       size;
        /** algorithm used to encrypt either of esks in CBC with empty IV */
        PGPByte         symmAlg;
        /** in bytes (always 128 in this version) */
        PGPUInt16       totalESKsize;
        PGPByte         reserved1[3];
        PGPByte         userName[kPGPdiskMaxUserNameSize + 1];
        /** always 0x03 OpenPGP iterated salted */
        // In version 10.4.1 MP1 this is actually 100, and 100 to 110 range implies
        // Private/Experimental S2K according to https://tools.ietf.org/html/rfc4880
        PGPByte         s2ktype;
        /** currently 0 -- default */
        PGPUInt32       hashIterations;
        PGPByte         reserved2[3];
        /** OpenPGP iterated-salted salt */
        PGPByte         salt[PGP_WDE_RECORD_SALT_SIZE];
        /**
         * 1 byte alg + disk session key in PKCS1 OAEP MGF1 SHA1 empty Parameters.
         * Requires 20 byte salt as well.
         *
         * The strength of string-to-key derivation is backed by two independent
         * mechanisms: new PKCS1 OAEP padding and OpenPGP s2k.
         * Since there is no compatibility issues with RFC 2440 here,
         * we may want to increase the size of OpenPGP s2K salt here to PGP_WDE_RECORD_SALT_SIZE bytes.
         * Right now we write / read 16 byte salt everywhere.
         *
         * This protection of random disk session key eliminates the need for
         * random salt for WDE or risky checksums to verify the passphrase.
         * Instead we rely on the decryption return code to verify the passphrase.
         */
        PGPByte         esk[PGP_WDE_MAX_MAIN_ESK/2];
} pgpDiskOnDiskUserWithSym;

#define SECTOR_SIZE 512
#define PAD_SIZE (SECTOR_SIZE - sizeof(PGPdiskOnDiskUserInfoHeader))

/**
 * This is a main record that defines protection
 * It is only used for currentRecord==0. Some user record types consist of only
 * this record, others require subsequent @ref pgpDiskOnDiskUserInfoSecondary.
*/
typedef struct pgpDiskOnDiskUserInfoMain_  {
        /** PGPdiskOnDiskUserFlags */
        PGPUInt16 userflags;
        /** simply copied */
        PGPUInt32 serialNumber;
        PGPUInt16 userLocalId;

        PGPByte reserved[3*2];

        /** @union records */
        union {
                pgpDiskOnDiskUserWithSym symmUser;
                pgpDiskOnDiskUserWithTokenPub tokenUser;
                pgpDiskOnDiskUserWithPub pubUser;
                pgpDiskOnDiskUserWithTpm tpmUser;
                pgpDiskOnDiskSessionKeys sessionKeys;
                pgpDiskOnDiskLinkKey linkKey;
        } UNNAMED;
} pgpDiskOnDiskUserInfoMain;

typedef struct PGPdiskOnDiskUserInfoHeader_  {
        /** sizeof(PGPdiskOnDiskUserInfo), etc -- describes the parent structure */
        PGPUInt16 size;
        /** starts from 0 */
        PGPByte version;
        /** sym/token/pub */
        PGPByte type;
        /** kPGPWDEUserInfoMagic -> (('W'<<24) | ('D'<<16) | ('i'<<8)) -> 1464101120 */
        PGPUInt32 magic;

        /** how many records represent a single logical record */
        PGPByte totalRecords;
        /** current record in a sequence */
        PGPByte currentRecord;
        PGPByte reserved[2];
} PGPdiskOnDiskUserInfoHeader;

typedef struct PGPdiskOnDiskUserInfo_  {
        PGPdiskOnDiskUserInfoHeader header;
        union  {
                pgpDiskOnDiskUserInfoMain main;
                pgpDiskOnDiskUserInfoSecondary secondary;
                /* needed to make sure that PGPdiskOnDiskUserInfo is sector aligned */
                PGPByte asOctets[PAD_SIZE];
        } UNNAMED;
} PGPdiskOnDiskUserInfo;

// clients2/wde/wdelib/src/pgpSDKInterface-bootguard.c
static struct PGP_WDE_EXTERNAL_CRYPTO_API gBGVector = {
    .begin = wdeBegin,
    .end = wdeEnd,
    .finalize = wdeFinalize,
    .memAlloc = wdeMemAlloc,
    .memFree = wdeMemFree,
    .decryptSymm = wdeDecryptSymmWithHashedPassphraseModuleCall,
    .encryptSymm = NULL,
    .hash = wdeHashPassphraseModuleCall,
    .decryptPub = wdeDecryptPubModuleCall,
    .decryptTpm = wdeDecryptTpmModuleCall,
    .reconstructData = wdeReconstructDataCall,
};

Bootguard uses indirect calls to minisdk, which resides in a bootguard module.

This "minisk" resides in following files,

clients2/wde/pgpsdkm/priv/pReconstruct.c
clients2/wde/pgpsdkm/priv/*

Also look at,

pgpWDEGetUserCryptoParams
wdeHashPassphraseModuleCall -> PAM_HashPassphrase -> sHashPassphrase
PGPWDEUserCryptoParams
SysCallDown
pgpWDEGetUserKeysWithPassphrase -> params->api->hash(paramsPriv->externalAPICtx, params, passphrase, passphraseSize, &myhashedPass);
clients2/wde/bg-modules/bg-sdk/bg-interface/pgpSDKInterface.c
clients2/wde/pgpsdkm/priv/pStr2Key.c
clients2/wde/wdelib/src/pgpSDKInterface-OS.c
sDecryptWDEESKWithHashedPassphrase
clients2/wde/pgpsdkm/priv/pKeyMisc.c
PGPPKCS1Unpack
pgpPKCS1oaepMGF1Unpack
PAM_DecryptWithHashedPassphrase

static PGPCipherVTBL const * const sCipherList[] =
{
    &cipher3DES,
#if PGP_AES
    &cipherAES128,
    &cipherAES192,
    &cipherAES256, // this seems to be fixed for the purpose of decrypting the ESK
#endif
};

enum PGPCipherAlgorithm_
{
    kPGPCipherAlgorithm_None        = 0,
    kPGPCipherAlgorithm_IDEA        = 1,
    kPGPCipherAlgorithm_3DES        = 2,
    kPGPCipherAlgorithm_CAST5       = 3,
    kPGPCipherAlgorithm_Blowfish    = 4,
    kPGPCipherAlgorithm_AES128      = 7,
    kPGPCipherAlgorithm_AES192      = 8,
    kPGPCipherAlgorithm_AES256      = 9,
    kPGPCipherAlgorithm_Twofish256  = 10,
};

P.type = type; // 8, kPGPdiskUserWithSymType
P.eskType = PGPWDEESKType_PKCS1_OAEP; // 1, hardcoded
"""

kPGPdiskUnknownKeysType = 0
kPGPdiskPseudoUserSessionKeysType = 0x01
kPGPdiskPseudoUserLinkKeyType = 0x02
kPGPdiskUserWithSymType = 0x08
kPGPdiskUserWithTokenPubType = 0x09
kPGPdiskUserWithPubType = 0x0A
kPGPdiskUserWithTpmType = 0x0B
# PGP_WDE_SALT_LOG_CHARS_CURRENT = 17  # this is 131072, 1<<17
PGPdiskOnDiskUserInfo_fmt = "< H B B I B B 2s " + "H I H 6s " + "H B H 3s 128s B I 3s 16s 144s"  # ESK is 128 bytes but let's grab 128 + 16
PGPdiskOnDiskUserInfo_size = struct.calcsize(PGPdiskOnDiskUserInfo_fmt)
pgpDiskOnDiskUserWithSym_fmt = '< H B H 3s 128s B I 3s 16s 128s'
pgpDiskOnDiskUserWithSym_size = struct.calcsize(pgpDiskOnDiskUserWithSym_fmt)  # this gives us 288 but on-disk size is 304!
# 32-bit PGP WDE on-disk pgpDiskOnDiskUserWithSym size -> 296
# 64-bit PGP WDE on-disk pgpDiskOnDiskUserWithSym size -> 304


def process_file(filename):
    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    data = f.read(1<<20)  # 1 MB

    for i in range(0, len(data) - PGPdiskOnDiskUserInfo_size):
        idata = data[i:i+PGPdiskOnDiskUserInfo_size]

        fields = struct.unpack(PGPdiskOnDiskUserInfo_fmt, idata)
        size, version, kind, magic, totalRecords, currentRecord, reserved = fields[0:7]
        if (size == 512 and version == 0 and magic == 1464101120 and currentRecord == 0):  # fairly safe test
            if kind != 0x08:
                sys.stderr.write("DEBUG: skipping over unsupported user record type %d!\n" % kind)
                continue
            userflags, serialNumber, userLocalId, reserved = fields[7:11]
            size, symmAlg, totalESKsize, reserved, userName, s2ktype, hashIterations, reserved2, salt, esk = fields[11:]
            userName = userName.strip(b"\x00").decode()
            if PY3:
                esk_hex = esk.hex()
                salt_hex = salt.hex()
            else:
                esk_hex = esk.encode("hex")
                salt_hex = salt.encode("hex")
            esk_cut = esk_hex[0:256]
            sys.stderr.write("DEBUG: %s, %s, %s, %s, %s, %s, %s\n" % (size, symmAlg, totalESKsize, userName, s2ktype, hashIterations, esk_hex))
            print("%s:$pgpwde$0*%s*%s*%s*%s*%s" % (userName, symmAlg, s2ktype, hashIterations, salt_hex, esk_cut))

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [PGP WDE / Symantec Encryption Destop encrypted whole disk images]\n" % sys.argv[0])
        sys.stderr.write("\nExample: %s hdd.raw\n" % sys.argv[0])
        sys.stderr.write("\nExample: %s /dev/sdb\n" % sys.argv[0])

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
