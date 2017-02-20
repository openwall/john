#!/usr/bin/env python
# coding: utf-8

"""
Modified for JtR by Dhiru Kholia in July, 2016

Copyright (c) 2015 Will Bond <will@wbond.net>

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import binascii
import sys
try:
    from asn1crypto import pkcs12
except ImportError:
    sys.stderr.write("asn1crypto is missing, run 'pip install --user asn1crypto' to install it!\n")
    sys.exit(-1)
import os


def parse_pkcs12(filename):
    data = open(filename, "rb").read()
    pfx = pkcs12.Pfx.load(data)

    auth_safe = pfx['auth_safe']
    if auth_safe['content_type'].native != 'data':
        raise ValueError(
            '''
            Only password-protected PKCS12 files are currently supported
            '''
        )

    mac_data = pfx['mac_data']
    if mac_data:
        mac_algo = mac_data['mac']['digest_algorithm']['algorithm'].native
        key_length = {
            'sha1': 20,
            'sha224': 28,
            'sha256': 32,
            'sha384': 48,
            'sha512': 64,
            'sha512_224': 28,
            'sha512_256': 32,
        }[mac_algo]

        salt = mac_data['mac_salt'].native
        iterations = mac_data['iterations'].native
        mac_algo_numeric = -1
        if mac_algo == "sha1":
            mac_algo_numeric = 1
        elif mac_algo == "sha224":
            mac_algo_numeric = 224
        elif mac_algo == "sha256":
            mac_algo_numeric = 256
        elif mac_algo == "sha384":
            mac_algo_numeric = 384
        elif mac_algo == "sha512":
            mac_algo_numeric = 512
        else:
            sys.stderr.write("mac_algo %s is not supported yet!\n" % mac_algo)
            return
        stored_hmac = mac_data['mac']['digest'].native
        data = auth_safe['content'].contents
        size = len(salt)
        sys.stdout.write("%s:$pfxng$%s$%s$%s$%s$%s$%s$%s:::::%s\n" %
                         (os.path.basename(filename), mac_algo_numeric,
                          key_length, iterations, size, binascii.hexlify(salt),
                          binascii.hexlify(data),
                          binascii.hexlify(stored_hmac), filename))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <.pfx file(s)>\n" % sys.argv[0])

    for i in range(1, len(sys.argv)):
        parse_pkcs12(sys.argv[1])
