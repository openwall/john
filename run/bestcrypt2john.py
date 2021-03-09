#!/usr/bin/python3

# This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Written in March of 2017 based on BestCrypt-3.0.0.tar.gz.

import os
import sys
import struct
from binascii import hexlify


"""
libs/multi-lib/keygens/kgghost/db_header.h

kBCV8_HeaderSize        = 1024,
kBCV8_InitialDBSize     = 1024 * 4,
kBCV8_MaximumDBSize     = kBCV8_InitialDBSize * 4,
kBCV8_JmpCodeSize       = 3,
kBCV8_SignatureSize     = 8,
kBCV8_IdLength          = 4,
kBCV8_OccupiedTag       = 28,
kBCV8_VolumeLabel       = 11,
kBCV8_DescriptionLength = 42,
kBCV8_DigestSize32      = 32,
kBCV8_DigestSize64      = 64,
kBCV8_MaxKeys           = 64,
kBCV8_BlockSize         = 16,
kBCV8_IVSize            = 16,
kBCV8_HiddenPartMapIV   = 1,

kBCV8_InitialDataBlockSize      = 4096,
kBCV8_DataBlockExtentionUnit    = 4096,
kBCV8_MaximumExtKeyBlockSize    = kBCV8_DataBlockExtentionUnit * 4,
kBCV8_MaximumDataBlockSize      = kBCV8_InitialDataBlockSize + kBCV8_MaximumExtKeyBlockSize,
kBCV8_HiddenPartSpaceMapSize    = 4096

typedef struct {
        bc_u16          size;   // encoded key data size.
        bc_16           type;   // encoding type. signed 16 bit value.
        bc_u32          param;  // optional key parameter.
} BCKeySlot;

// V8 datablock header format.
typedef struct db_header
{
        bc_u8           jmpCode[kBCV8_JmpCodeSize];             // On old linux version holds container lock flag.
        bc_u8           signature[kBCV8_SignatureSize];         // Format version signature, i.e. LOCOSXX
        bc_u8           cid[kBCV8_IdLength];                    // Container id for central management authentication.
        bc_u8           occupiedTag[kBCV8_OccupiedTag];         // Unused?
        char            volumeLabel[kBCV8_VolumeLabel];         // "BC_KeyGenID" for this version

        bc_u16  wKeyGenId;              // Key generator ID 5 identifier...
        bc_u16  wVersion;               // Key generator ID 5 version...

        union {
                bc_u32  iterations;     // Key generator ID 5, allows iteration other then 256, but int does never uses the version field.
                bc_u32  version;        // Container version
        };

        char            description[kBCV8_DescriptionLength];   // Description string.
        bc_u64          sparced_position;
        bc_u64          data_start;                             // Encrypted body data start.
        bc_u64          data_length;                            // Encrypted body data size.
        bc_u32          alg_id;                                 // The algorithm used for container encryption
        bc_u32          mode_id;                                // Encryption mode for container algorithm
        bc_u32          hash_id;                                // Hash algorithm used for encryption keys generation
        BCKeySlot       keymap[kBCV8_MaxKeys];

        ...
} db_header;

// libs/multi-lib/keygens/kgghost/kgghost.h
kKeySlotSize        = 256, // Single encoded key slot.
kDigestSize32       = 32,  // Digest buffer length.
kDigestSize64       = 64,  // Digest buffer length.
kIVSize             = 16,  // IV buffer length.
kSeedLength         = 128, // random seed buffer size for key generation.
kEncryptedBlockSize = 16,  // Block cipher encryption block size.
kMaximumKeySize     = 64,  // Maximum stored key size.
kPoolSize           = 512  // Random data pool size.

// kgghost -> Default BestCrypt version 8 key generator

typedef struct {
        bc_u8           data[kKeySlotSize];
} KEY_BLOCK;

struct db_enc_block64 {
        db_header       header;
        bc_u8           padding[4];

        // ---------------------------------------------------------------------------------------------------------------
        // Data before this point can be encrypted and should be a multiple of kBCV8_BlockSize bytes in size.

        bc_u8           digest[kBCV8_DigestSize64];             // header digest.
        bc_u8           iv[kBCV8_IVSize];                       // random initial vector for header encryption.
}

typedef struct {
        db_enc_block64  header;
        bc_u8                   padding[1024 - sizeof(db_enc_block64)];
        // ---------------------------------------------------------------------------------------------
        // 1KB boundary

        bc_u8                   pool[kPoolSize];
        KEY_BLOCK               keys[0];        // real number of keys depends on total data block size.
} DATA_BLOCK_64;

"""

DB_HEADER_SIGNATURE = b"LOCOS94 "
kKGID = 4  # Keygen id
kKGID_V5 = 5  # Keygen id for BestCrypt version 5

db_header_fmt = '< 3s 8s 4s 28s 11s H H I 42s 24s I I I 512s'
db_enc_block64_fmt = "%s 4s 64s 16s" % db_header_fmt
DATA_BLOCK_64_fmt = "%s 288s 512s 2560s" % db_enc_block64_fmt  # hardcoded 2560s supports 10 KEY_BLOCK(s) while maximum is 64 (kBCV8_MaxKeys)
DATA_BLOCK_64_size = struct.calcsize(DATA_BLOCK_64_fmt)
db_enc_block64_size = struct.calcsize(db_enc_block64_fmt)
keymap_fmt = "< H h I"
keymap_size = struct.calcsize(keymap_fmt)
db_header_size = struct.calcsize(db_header_fmt)
key_slot_fmt = "< H h I"  # 8 bytes
key_slot_size = 8

# ciphers
bcsaRIJN = 240

# block cipher modes.
kBCMode_UDF = 0
kBCMode_CBC = 0xBC000002
kBCMode_LRW = 0xBC000001
kBCMode_XTS = 0xBC000004
kBCMode_ECB = 0xBC000008

# hashing algorithms
pgphaMD5 = 1
pgphaSHA1 = 2
pgphaRIPEMD160 = 3
pgphaSHA256 = 8
pgphaSHA512 = 10
bchaSHA256 = 0x80
bchaWhirlpool512 = 0x80 + 1  # 129
bchaSHA3_512 = 0x80 + 2
bchaSkein512 = 0x80 + 3

kBCKeyType_Salt = 5  # KeyGen V5 save salt at key map, see DATA_BLOCK::updateSalt
kBCV8_InitialDataBlockSize = 4096
DATA_BLOCK_size = 1536
kKeySlotSize = 256
kBCV8_MaxKeys = 64

# slot type
kBCKeyType_Part = -1
kBCKeyType_Empty = 0
kBCKeyType_PBE = 1
kBCKeyType_SSS = 2
kBCKeyType_PKE = 3
kBCKeyType_Salt = 5


def DataBlock_CapacityForSize(dbsize):
    if dbsize <= DATA_BLOCK_size:
        return 0

    capacity = ((dbsize - DATA_BLOCK_size) // kKeySlotSize)

    if capacity < kBCV8_MaxKeys:
        return capacity
    else:
        return kBCV8_MaxKeys


def process_file(filename):
    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    N = DATA_BLOCK_64_size
    data = f.read(N)
    if len(data) != N:
        sys.stdout.write("%s : parsing failed\n" % filename)
        return -1

    data = struct.unpack(DATA_BLOCK_64_fmt, data)

    (_, signature, cid, occupiedTag, volumeLabel, wKeyGenId, wVersion,
     iterations, description, _, alg_id, mode_id, hash_id, keymap, _, digest,
     iv, _, pool, keys) = data

    # libs/multi-lib/keygens/kgghost/kgghost.cpp -> readDBFromContainer
    # libs/multi-lib/keygens/kgghost/datablock.cpp -> DataBlock_DecodeKey
    # libs/multi-lib/keygens/kgghost/datablock.cpp -> walkNotEncrypted
    if signature != DB_HEADER_SIGNATURE or volumeLabel != b"BC_KeyGenID":
        print("%s: encrypted header found, not yet supported, patches welcome!" % os.path.basename(filename))
        # look at libs/multi-lib/keygens/kgghost/datablock.cpp -> DataBlock_DecodeKey
        return

    description = description.decode("utf-16-le").rstrip("\x00")

    if wKeyGenId == kKGID_V5:
        resolved_version = wVersion
    else:
        resolved_version = iterations  # union of iterations and version
        if (resolved_version != 3) or wKeyGenId != kKGID:
            print("Invalid header version %s, id %s" % (resolved_version, wKeyGenId))
            return

    if alg_id != bcsaRIJN:
        print("%s: cipher alg_id %s not supported, patches welcome!" % (os.path.basename(filename), alg_id))
        return

    if mode_id != kBCMode_CBC and mode_id != kBCMode_XTS:
        print("%s: cipher mode_id %s not supported, patches welcome!" % (os.path.basename(filename), hex(mode_id)))
        return

    # handle hash_id and salt
    if hash_id != bchaWhirlpool512 and hash_id != bchaSHA256 and hash_id != pgphaSHA512:
        print("%s: hash_id %s not supported, patches welcome!" % (os.path.basename(filename), hash_id))
        return 0
    salt_size = -1
    if hash_id == bchaWhirlpool512:
        salt_size = 64
    elif hash_id == bchaSHA256:
        salt_size = 32
    elif hash_id == pgphaSHA512:
        salt_size = 64
    salt = hexlify(keys[0:salt_size]).decode("ascii")  # this uses data from keys corresponding to slotnum = 0
    size, _type, param = struct.unpack(keymap_fmt, keymap[:keymap_size])  # this uses data from keymap with slotnum = 0
    if _type != kBCKeyType_Salt:
        print("%s: internal error while processing salt, please report this problem!" % os.path.basename(filename))
        return

    dbsize = kBCV8_InitialDataBlockSize
    maxSlots = DataBlock_CapacityForSize(dbsize)

    # find the active slots (look in keymap, data is in keys)
    slot_size = keymap_size
    version = 1  # internal format version, unused

    for slotnum in range(0, maxSlots):
        slot = keymap[slot_size * slotnum:slot_size * (slotnum + 1)]
        size, slot_type, _ = struct.unpack(keymap_fmt, slot)
        if slot_type == kBCKeyType_Part or slot_type == kBCKeyType_Salt or slot_type == kBCKeyType_Empty:
            continue
        # find the corresponding bits in "keys", keys[slotnum]
        active_key = keys[kKeySlotSize * slotnum:kKeySlotSize * (slotnum + 1)]

        # output one "hash" for every active key slot
        key = hexlify(active_key).decode("ascii")
        sys.stdout.write("%s:$BestCrypt$%s$%s$%s$%s$%s$%s$%s$%s$%s$%s$%s\n" %
                         (os.path.basename(filename), version, wKeyGenId,
                          wVersion, iterations, alg_id, mode_id, hash_id,
                          salt_size, salt, 1, key))

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [Jetico BestCrypt Containers, .jbc file(s)]\n" % sys.argv[0])

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
