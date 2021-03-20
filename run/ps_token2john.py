#!/usr/bin/env python

import argparse
import base64
import binascii
import hashlib
import sys
import zlib

# Use "generate.py from https://erpscan.io/wp-content/uploads/tools/ERPScan-tockenchpoken.zip
# to generate sample PS_TOKEN cookies.

print("""Based on tokenchpoken v0.5 beta's parse.py file
Oracle PS_TOKEN cracker. Token parser

Alexey Tyurin - a.tyurin at erpscan.io
ERPScan Research Group - https://www.erpscan.io
""")

def hexstr(bytestr):
    return binascii.hexlify(bytestr).decode('ascii')

parser = argparse.ArgumentParser()
parser.add_argument('-c', action='store', dest='cookie', required=True,
                    help='Set a victim\'s PS_TOKEN cookie for parsing')

args = parser.parse_args()

input = args.cookie

full_str = base64.b64decode(input)
sha_mac = hexstr(full_str[44:64])
inflate_data = full_str[76:]
data = zlib.decompress(inflate_data)

# parsing of compressed data
data_hash = hashlib.sha1(data).hexdigest()

user_length = data[20]
if isinstance(user_length, int):
    user_length = user_length.to_bytes(1, sys.byteorder)
loc = 21
user = data[loc:loc + int(hexstr(user_length), 16)].replace(b"\x00", b"").decode('utf-8')

# python generate.py -e 0 -u PS -l ENG -p "" -n PSFT_HR -d 2015-07-01-08.06.46
if data_hash == sha_mac:
    print("%s: there is no password for the attacking node!" % user)
else:
    # print hash
    sys.stdout.write("%s:$dynamic_1600$%s$HEX$%s\n" % (user, sha_mac, hexstr(data)))
