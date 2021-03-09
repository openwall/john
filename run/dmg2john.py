#!/usr/bin/python3

# Written by Dhiru Kholia <dhiru at openwall.com> in March, 2013
# My code is under "Simplified BSD License"

import sys
import os
import struct
from binascii import hexlify

# header structs are taken from vilefault and hashkill projects
v1_header_fmt = '> 48s I I 48s 32s I 296s I 300s I 48s 484s'
v1_header_size = struct.calcsize(v1_header_fmt)
# v2_header_fmt = '> 8s I I I I I I I 16s I Q Q 24s I I I I 32s I 32s I I I I I 48s'
# encrypted_blob_size can be 64, handle such cases properly too, a value of 48
# is already handled well
v2_header_fmt = '> 8s I I I I I I I 16s I Q Q 24s I I I I 32s I 32s I I I I I 64s'
v2_header_size = struct.calcsize(v2_header_fmt)

PY3 = sys.version_info[0] == 3
PMV = sys.version_info[1] >= 6

if PY3 or PMV:
    exec('MAGICv1=b"cdsaencr"')
    exec('MAGICv2=b"encrcdsa"')
else:
    MAGICv1 = "cdsaencr"
    MAGICv2 = "encrcdsa"


def process_file(filename):
    cno = 0
    data_size = 0

    headerver = 0
    try:
        fd = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    buf8 = fd.read(8)
    if len(buf8) != 8:
        sys.stderr.write("%s is not a DMG file!\n" % filename)
        return

    if buf8 == MAGICv2:
        headerver = 2
    else:
        fd.seek(-8, 2)
        buf8 = fd.read(8)
        if len(buf8) != 8:
            sys.stderr.write("%s is not a DMG file!\n" % filename)
            return

        if buf8 == MAGICv1:
            headerver = 1

    if headerver == 0:
        sys.stderr.write("%s is not an encrypted DMG file!\n" % filename)
        return

    sys.stderr.write("Header version %d detected\n" % headerver)

    if headerver == 1:
        fd.seek(- v1_header_size, 2)
        data = fd.read(v1_header_size)
        if len(data) != v1_header_size:
            sys.stderr.write("%s is not a DMG file!\n" % filename)
            return

        data = struct.unpack(v1_header_fmt, data)

        (_, kdf_iteration_count, kdf_salt_len, kdf_salt, _,
                len_wrapped_aes_key, wrapped_aes_key, len_hmac_sha1_key,
                wrapped_hmac_sha1_key, _, _, _) = data

        sys.stdout.write("%s:$dmg$%d*%d*%s*%d*%s*%d*%s*%d::::%s\n" % \
            (os.path.basename(filename), headerver, kdf_salt_len,
             hexlify(kdf_salt)[0:kdf_salt_len * 2].decode("ascii"),
             len_wrapped_aes_key,
             hexlify(wrapped_aes_key)[0:len_wrapped_aes_key * 2].decode("ascii"),
             len_hmac_sha1_key,
             hexlify(wrapped_hmac_sha1_key)[0:len_hmac_sha1_key * 2].decode("ascii"),
             kdf_iteration_count, filename))
    else:
        fd.seek(0, 0)
        data = fd.read(v2_header_size)
        if len(data) != v2_header_size:
            sys.stderr.write("%s is not a DMG file!\n" % filename)
            return

        data = struct.unpack(v2_header_fmt, data)
        (sig, version, enc_iv_size, _, _, _, _,
                unk5, uuid, blocksize, datasize, dataoffset, filler1,
                kdf_algorithm, kdf_prng_algorithm, kdf_iteration_count,
                kdf_salt_len, kdf_salt, blob_enc_iv_size, blob_enc_iv,
                blob_enc_key_bits, blob_enc_algorithm, blob_enc_padding,
                blob_enc_mode, encrypted_keyblob_size, encrypted_keyblob) = data

        fd.seek(dataoffset, 0)
        cno = ((datasize + 4095) // 4096) - 2
        data_size = datasize - cno * 4096
        data_size = int(data_size)
        if data_size < 0:
            sys.stderr.write("%s is not a valid DMG file! \n" % filename)
            return
        if kdf_salt_len > 32:
            sys.stderr.write("%s is not a valid DMG file. salt length " \
                             "is too long!\n" % filename)
            return

        # read starting chunk(s)
        fd.seek(dataoffset + int(cno * 4096), 0)
        chunk1 = fd.read(data_size)
        if len(chunk1) != data_size:
            sys.stderr.write("%s is not a DMG file!\n" % filename)
            return

        # read last chunk
        fd.seek(dataoffset, 0)
        chunk2 = fd.read(4096)
        if len(chunk2) != 4096:
            sys.stderr.write("%s is not a DMG file!\n" % filename)
            return

        # output hash
        sys.stdout.write("%s:$dmg$%d*%d*%s*32*%s*%d*%s*%d*%d*%s*1*%s*%d::::%s\n" % \
                (os.path.basename(filename), headerver,
                kdf_salt_len,
                hexlify(kdf_salt)[0:kdf_salt_len*2].decode("ascii"),
                hexlify(blob_enc_iv)[0:64].decode("ascii"),
                encrypted_keyblob_size,
                hexlify(encrypted_keyblob)[0:encrypted_keyblob_size*2].decode("ascii") + \
                 "0" * (encrypted_keyblob_size * 2 - \
                len(encrypted_keyblob) * 2),
                cno, data_size, hexlify(chunk1).decode("ascii"),
                hexlify(chunk2).decode("ascii"),
                kdf_iteration_count, filename))

if __name__ == "__main__":
    sys.stderr.write("Using 'dmg2john' instead of this program (%s) is recommended!\n\n" % sys.argv[0])

    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [DMG files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
