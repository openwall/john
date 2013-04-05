#!/usr/bin/env python

# Written by Dhiru Kholia <dhiru at openwall.com> in March, 2013
# My code is under "Simplified BSD License"

import sys
import os
import struct
from binascii import hexlify

# header structs are taken from vilefault and hashkill projects
v1_header_fmt = '> 48s I I 48s 32s I 296s I 300s I 48s 484s'
v1_header_size = struct.calcsize(v1_header_fmt)
v2_header_fmt = '> 8s I I I I I I I 16s I Q Q 24s I I I I 32s I 32s I I I I I 48s'
v2_header_size = struct.calcsize(v2_header_fmt)

def process_file(filename):
    cno = 0
    data_size = 0
    count = 0

    headerver = 0
    try:
        fd = open(filename, "r")
    except IOError, exc:
        print >> sys.stderr, str(exc)
        return

    buf8 = fd.read(8)
    if len(buf8) != 8:
        print >> sys.stderr, "%s is not a DMG file!" % filename
        return

    if buf8 == "encrcdsa":
        headerver = 2
    else:
        fd.seek(-8, 2)
        buf8 = fd.read(8)
        if len(buf8) != 8:
            print >> sys.stderr, "%s is not a DMG file!" % filename
            return

        if buf8 == "cdsaencr":
            headerver = 1

    if headerver == 0:
        print >> sys.stderr, "%s is not an encrypted DMG file!" % filename
        return

    print >> sys.stderr,  "Header version %d detected" % headerver

    if headerver == 1:
        fd.seek(- v1_header_size, 2)
        data = fd.read(v1_header_size)
        if len(data) != v1_header_size:
            print >> sys.stderr, "%s is not a DMG file!" % filename
            return

        data = struct.unpack(v1_header_fmt, data)

        (filler1, kdf_iteration_count, kdf_salt_len, kdf_salt, unwrap_iv,
                len_wrapped_aes_key, wrapped_aes_key, len_hmac_sha1_key,
                wrapped_hmac_sha1_key, len_integrity_key, wrapped_integrity_key,
                filler6) = data

        print "%s:$dmg$%d*%d*%s*%d*%s*%d*%s*%d::::%s" % (os.path.basename(filename), headerver,
                kdf_salt_len, hexlify(kdf_salt)[0:kdf_salt_len * 2], len_wrapped_aes_key, hexlify(wrapped_aes_key)[0:len_wrapped_aes_key * 2],
                len_hmac_sha1_key, hexlify(wrapped_hmac_sha1_key)[0:len_hmac_sha1_key * 2], kdf_iteration_count, filename)


    else:
        fd.seek(0, 0)
        data = fd.read(v2_header_size)
        if len(data) != v2_header_size:
            print >> sys.stderr, "%s is not a DMG file!" % filename
            return

        data = struct.unpack(v2_header_fmt, data)
        (sig, version, enc_iv_size, unk1, unk2, unk3, unk4,
                unk5, uuid, blocksize, datasize, dataoffset, filler1,
                kdf_algorithm, kdf_prng_algorithm, kdf_iteration_count,
                kdf_salt_len, kdf_salt, blob_enc_iv_size, blob_enc_iv,
                blob_enc_key_bits, blob_enc_algorithm, blob_enc_padding,
                blob_enc_mode, encrypted_keyblob_size, encrypted_keyblob) = data

        fd.seek(dataoffset, 0)
        cno = ((datasize + 4095) / 4096) - 2
        data_size = datasize - cno * 4096
        if data_size < 0:
            print >> sys.stderr, "%s is not a valid DMG file! " % filename
            return
        if kdf_salt_len > 32:
            print >> sys.stderr, "%s is not a valid DMG file. salt length is too long!" % filename
            return

        # read starting chunk(s)
        fd.seek(dataoffset + cno * 4096, 0)
        chunk1 = fd.read(data_size)
        if len(chunk1) != data_size:
            print >> sys.stderr, "%s is not a DMG file!" % filename
            return

        # read last chunk
        fd.seek(dataoffset, 0)
        chunk2 = fd.read(4096)
        if len(chunk2) != 4096:
            print >> sys.stderr, "%s is not a DMG file!" % filename
            return

        # output hash
        print "%s:$dmg$%d*%d*%s*32*%s*%d*%s*%d*%d*%s*1*%s*%d::::%s" % (os.path.basename(filename), headerver,
                kdf_salt_len, hexlify(kdf_salt)[0:kdf_salt_len*2], hexlify(blob_enc_iv)[0:64], encrypted_keyblob_size,
                hexlify(encrypted_keyblob)[0:encrypted_keyblob_size*2] + "0" * (encrypted_keyblob_size * 2 - len(encrypted_keyblob) * 2),
                cno, data_size, hexlify(chunk1), hexlify(chunk2),
                kdf_iteration_count, filename)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print >> sys.stderr, "Usage: %s [DMG files]" % sys.argv[0]
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
