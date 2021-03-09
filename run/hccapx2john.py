#!/usr/bin/python3
'''
Process hccapx file into a format suitable for use with JtR.
Implements AP nonce correction as user supplied argument or
through detection, based on message_pair flags as described here:
https://github.com/hashcat/hashcat/issues/1525
hccapx format v4 described here:
https://hashcat.net/wiki/doku.php?id=hccapx

This software is Copyright (c) 2018, Alex Stanev <alex at stanev.org> and it is
hereby released to the general public under the following terms:

Redistribution and use in source and binary forms, with or without
modification, are permitted.
'''

from __future__ import print_function
import argparse
import os
import sys
import binascii
import struct

try:
    from string import maketrans
except ImportError:
    maketrans = bytearray.maketrans  # pylint: disable=no-member


def pack_jtr(hccap, message_pair, hccapxfile, ncorr=0):
    '''prepare handshake in JtR format'''

    jtr = b'%s:$WPAPSK$%s#%s:%s:%s:%s::%s:%s:%s\n'
    hccap_fmt = '< 36s 6s 6s 32x 28x 4s 256x 4x I 16x'

    (essid, mac_ap, mac_sta, corr, keyver) = struct.unpack(hccap_fmt, hccap)

    # replay count checked
    if message_pair & 0x80 > 1:
        ver = b'verified'
    else:
        ver = b'not verified'

    # detect endian and apply nonce correction
    if ncorr != 0:
        try:
            if message_pair & 0x40 > 1:
                ver += b', fuzz ' + str(ncorr).encode() + b' BE'
                dcorr = struct.unpack('>L', corr)[0]
                corr = struct.pack('>L', dcorr + ncorr)
            if message_pair & 0x20 > 1:
                ver += b', fuzz ' + str(ncorr).encode() + b' LE'
                dcorr = struct.unpack('<L', corr)[0]
                corr = struct.pack('<L', dcorr + ncorr)
        except struct.error:
            pass

    # cut essid part and stuff correction
    newhccap = hccap[36:108] + corr + hccap[112:]

    # prepare values for JtR
    essid = essid.rstrip(b'\0')
    mac_sta = binascii.hexlify(mac_sta)
    mac_ap = binascii.hexlify(mac_ap)

    if keyver == 1:
        keyver = b'WPA'
    elif keyver == 2:
        keyver = b'WPA2'
    elif keyver >= 3:
        keyver = b'WPA CMAC'

    # prepare translation to base64 alphabet used by JtR
    encode_trans = maketrans(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/',
                             b'./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz')

    return jtr % (essid,
                  essid,
                  binascii.b2a_base64(newhccap).translate(encode_trans).rstrip(b'=\n'),
                  mac_sta,
                  mac_ap,
                  mac_ap,
                  keyver,
                  ver,
                  hccapxfile)


def hccapx2hccap(hccapx):
    '''convert hccapx to hccap struct

    https://hashcat.net/wiki/doku.php?id=hccapx
    struct hccapx
    {
      u32 signature;
      u32 version;
      u8  message_pair;
      u8  essid_len;
      u8  essid[32];
      u8  keyver;
      u8  keymic[16];
      u8  mac_ap[6];
      u8  nonce_ap[32];
      u8  mac_sta[6];
      u8  nonce_sta[32];
      u16 eapol_len;
      u8  eapol[256];

    } __attribute__((packed));

    https://hashcat.net/wiki/doku.php?id=hccap
    typedef struct
    {
      char          essid[36];

      unsigned char mac1[6];
      unsigned char mac2[6];
      unsigned char nonce1[32];
      unsigned char nonce2[32];

      unsigned char eapol[256];
      int           eapol_size;

      int           keyver;
      unsigned char keymic[16];

    } hccap_t;
    '''

    hccapx_fmt = '< 4x 4x B x 32s B 16s 6s 32s 6s 32s H 256s'
    hccap_fmt = '< 36s 6s 6s 32s 32s 256s I I 16s'

    (message_pair,
     essid,
     keyver, keymic,
     mac_ap, nonce_ap, mac_sta, nonce_sta,
     eapol_len, eapol) = struct.unpack(hccapx_fmt, hccapx)

    hccap = struct.pack(
        hccap_fmt,
        essid,
        mac_ap, mac_sta,
        nonce_sta, nonce_ap,
        eapol, eapol_len,
        keyver, keymic)

    return (hccap, message_pair)


def hccapx2john(hccapx, ncorr, message_pair_flag, hccapxfile):
    '''convert hccapx struct to JtR $WPAPSK$ and implement nonce correction'''

    if not hccapx.startswith(b'HCPX') or len(hccapx) != 393:
        return False

    hccapx = bytearray(hccapx)

    # convert hccapx to hccap and extract message_pair
    (hccap, message_pair) = hccapx2hccap(hccapx)

    # do we have to process message_pair flags?
    if not message_pair_flag:
        message_pair &= 0x8F

    # exact handshake
    hccaps = pack_jtr(hccap, message_pair, hccapxfile)
    if message_pair & 0x10 > 1:
        return hccaps

    # detect if we have endianness info
    flip = False
    if message_pair & 0x60 == 0:
        flip = True
        # set flag for LE
        message_pair |= 0x20

    # prepare nonce correction
    for i in range(1, ncorr+1):
        if flip:
            # this comes with LE set first time if we don't have endianness info
            hccaps += pack_jtr(hccap, message_pair, hccapxfile, i)
            hccaps += pack_jtr(hccap, message_pair, hccapxfile, -i)
            # toggle BE/LE bits
            message_pair ^= 0x60

        hccaps += pack_jtr(hccap, message_pair, hccapxfile, i)
        hccaps += pack_jtr(hccap, message_pair, hccapxfile, -i)

    return hccaps


def check_hccapx(arg):
    '''check if it's a valid hccapx file'''

    if not os.path.isfile(arg):
        raise argparse.ArgumentTypeError('The file %s does not exist!' % arg)
    if os.path.getsize(arg) % 393 != 0:
        raise argparse.ArgumentTypeError('The file %s size not valid!' % arg)

    return arg


def check_nc(arg):
    '''check if it's a valid nc'''

    arg = int(arg)
    if arg < 0:
        raise argparse.ArgumentTypeError('AP nonce correction must be a positive integer!')

    return arg

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='hccapx2john, process hccapx file into a format suitable for use with JtR')
    parser.add_argument(
        '-nc', type=check_nc, default=8,
        help='AP nonce correction to be used, 0 to disable, default 8')
    parser.add_argument(
        '--no-mp', dest='mp', action='store_false',
        help='disable message_pair BE/LE/nc detection')
    parser.add_argument(
        'hccapx', type=check_hccapx,
        help='hccapx file to process')
    parser.set_defaults(mp=True)

    try:
        args = parser.parse_args()
    except IOError as ex:
        parser.error(str(ex))

    # workaround encoding issues with python2
    if sys.version_info[0] == 2:
        reload(sys)                         # pylint: disable=undefined-variable
        sys.setdefaultencoding('utf-8')     # pylint: disable=no-member

    with open(args.hccapx, 'rb') as fd:
        while True:
            hccapxstruct = fd.read(393)
            if not hccapxstruct:
                break

            john = hccapx2john(
                hccapxstruct,
                args.nc,
                args.mp,
                args.hccapx.encode())
            if john:
                sys.stdout.write(john.decode('utf-8', errors='ignore'))
