#!/usr/bin/env python

# This software is Copyright (c) 2018, Ivan Freed <ivan.freed at protonmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Tested with DiskCryptor 1.1.846.118 running on Windows XP SP3.
#
# References:
#
# + https://diskcryptor.net/wiki/Volume
# + https://diskcryptor.net/wiki/Compilation
# + https://diskcryptor.net/wiki/Bootloader
#
# Debugging Note: Use Visual Studio 2010 Ultimate on Windows XP SP3 32-bit to
# compile DiskCryptor 1.1.846.118. Build the "driver" in "Release" mode.
#
# 17-Dec-2018: Only single AES, Twofish and Serpent ciphers are supported.
#
# pylint: disable=invalid-name,line-too-long,missing-docstring

import os
import sys
import math
import struct
from binascii import hexlify

PY3 = sys.version_info[0] == 3

"""
From boot/vc2008_src/include/volume.h,

#define DC_VOLM_SIGN 0x50524344

// Header key derivation
#define PKCS5_SALT_SIZE         64

// Master key + secondary key (LRW mode)
#define DISKKEY_SIZE            256
#define MAX_KEY_SIZE            (32*3)
#define PKCS_DERIVE_MAX         (MAX_KEY_SIZE*2)

#define SECTOR_SIZE             512
#define MAX_SECTOR_SIZE         2048
#define CD_SECTOR_SIZE          2048

#define MIN_PASSWORD            1    // Minimum password length
#define MAX_PASSWORD            128  // Maximum password length

#define DC_HDR_VERSION 1

#define VF_NONE           0x00
#define VF_TMP_MODE       0x01 /* temporary encryption mode */
#define VF_REENCRYPT      0x02 /* volume re-encryption in progress */
#define VF_STORAGE_FILE   0x04 /* redirected area are placed in file */
#define VF_NO_REDIR       0x08 /* redirection area is not present */
#define VF_EXTENDED       0x10 /* this volume placed on extended partition */

#define ENC_BLOCK_SIZE  (1280 * 1024)

static cipher_desc *algs[7][3] = {
        { &aes256,                          },
        { &twofish256,                      },
        { &serpent256,                      },
        { &twofish256, &aes256,             },
        { &serpent256, &twofish256,         },
        { &aes256,     &serpent256,         },
        { &serpent256, &twofish256, &aes256 }
};

void xts_set_key(const unsigned char *key, int alg, xts_key *skey)
{
        cipher_desc   *p_alg;
        unsigned char *p_ctx;
        int            i;

        /* set encryption key */
        for (i = 0, p_ctx = skey->crypt_k; (i < 3) && (p_alg = algs[alg][i]); i++) {
                p_alg->set_key(key, p_ctx); key += XTS_KEY_SIZE; p_ctx += p_alg->ctxsz;
        }
        /* set tweak key */
        for (i = 0, p_ctx = skey->tweak_k; (i < 3) && (p_alg = algs[alg][i]); i++) {
                p_alg->set_key(key, p_ctx); key += XTS_KEY_SIZE; p_ctx += p_alg->ctxsz;
        }
        skey->algs  = (void**)algs[alg];
        skey->max   = i-1;
        skey->ctxsz = p_ctx - skey->tweak_k;
}

typedef struct _dc_header {
        u8  salt[PKCS5_SALT_SIZE]; /* pkcs5.2 salt */
        u32 sign;                  /* signature 'DCRP' */
        u32 hdr_crc;               /* crc32 of decrypted volume header - CRC32 of the remaining part of the header (bytes 72-2047) */
        u16 version;               /* volume format version */
        u32 flags;                 /* volume flags */
        u32 disk_id;               /* unigue volume identifier */
        int alg_1;                 /* crypt algo 1 */
        u8  key_1[DISKKEY_SIZE];   /* crypt key 1  */
        int alg_2;                 /* crypt algo 2 */
        u8  key_2[DISKKEY_SIZE];   /* crypt key 2  */

        union {
                u64 stor_off;    /* redirection area offset */
                u64 data_off;    /* volume data offset, if redirection area is not used */
        };
        u64 use_size;    /* user available volume size */
        u64 tmp_size;    /* temporary part size      */
        u8  tmp_wp_mode; /* data wipe mode */

        u8  reserved[1422 - 1];

} dc_header;

Offset	Size	Encryption	Description
-------------------------------------------
0	64	No	        Salt. Random number used when deriving volume header key.
64	4	Yes	        DiskCryptor volume signature. Has the value of 0x50524344 (ascii 'DCRP').
68	4	Yes	        CRC32 of the remaining part of the header (bytes 72-2047).
72	2	Yes 	        Header format version. Has the value of 1 for DiskCryptor 0.5 volumes.
74	4	Yes	        Volume flags. Used for indicating volume's state.
78	4	Yes	        Unique volume identifier. Used to search for a partition when choosing to boot from the specified partition.
82	4	Yes	        Identifier of a main cryptoalgorithm, with which partition is encrypted.
86	256	Yes	        Main encryption key of user data on a volume.
342	4	Yes     	Identifier of an additional cryptoalgorithm, with which partition is encrypted. Indicates about a previously used cryptoalgorithm on re-encryption.
346	256	Yes	        Additional encryption key of user data on a volume. Used for storing the previous key on re-encryption.
602	8	Yes     	Offset in user data area, by which the first 2048 bytes of partition data have been relocated.
610	8	Yes	        Size of a user data area.
618	8	Yes	        Size of the encrypted area. Present only in a partially encrypted state.
626	1	Yes	        Partition wipe mode used on encryption. Present only in a partially encrypted state.
627	1421	Yes	        Reserved. Zero-filled.
"""


OnDiskHeaderFmt = "< 64s I I H I I i 256s i 256s Q Q Q B 1421s"
OnDiskHeaderSize = struct.calcsize(OnDiskHeaderFmt)


def entropy(string):
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]

    return - sum([p * math.log(p) / math.log(2.0) for p in prob])


def process_file(filename):
    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    header = f.read(OnDiskHeaderSize)  # 2 KiB

    # detect dumping of non-encrypted disks/partitions
    if b'BOOTMGR' in header or b'NTFS' in header or b'disk read' in header:
        sys.stderr.write("!!! You are trying to run this program on the wrong disk or a non-encrypted partition !!!\n")
        return
    ent = entropy(header)
    if ent < 6:
        sys.stderr.write("!!! Low entropy detected - is this really an encrypted DiskCryptor volume header? !!!\n\n")
        if not os.getenv("FORCE"):
            return
    header = hexlify(header)
    if PY3:
        header = str(header, 'ascii')

    name = os.path.basename(filename)

    print("%s:$diskcryptor$0*%s" % (name, header))

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [DiskCryptor Encrypted Device / Raw Disk Image]\n\n" % sys.argv[0])
        sys.stderr.write("Example: %s /dev/sdb1\n\n" % sys.argv[0])
        sys.stderr.write("Example: %s disk_image.raw\n\n" % sys.argv[0])
        sys.stderr.write("Tip: Use kpartx to 'mount' raw disk images on Linux. Run me against encrypted mapped partitions.\n\n")
        sys.stderr.write("Example: kpartx -av disk_image.raw; fdisk -l disk_image.raw; %s /dev/mapper/loop0p1\n\n" % sys.argv[0])
        sys.stderr.write("ATTENTION: Cascaded ciphers are NOT supported yet!\n")

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
