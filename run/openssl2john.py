#!/usr/bin/env python

import sys
import base64
import optparse


def process(filename, plaintext=None, cipher=0, md=0):

    with open(filename, "rb") as f:
        data = f.read()
        data = base64.decodestring(data)

        if not data.startswith("Salted__"):
            sys.stderr.write("%s doesn't seem to be encrypted using OpenSSL's enc command!\n" % filename)
            return

        if len(data) < 32:
            sys.stderr.write("%s doesn't seem to be encrypted using OpenSSL's enc command!\n" % filename)
            return

        rlen = len(data) - 16
        salt = data[8:16]

        if rlen <= 16:
            last_chunk = data[-16:]
            if plaintext:
                s = "1$%s" % plaintext
            else:
                s = "0"
            sys.stdout.write("%s:$openssl$%s$%s$8$%s$%s$1$%s" % (filename, cipher, md, salt.encode("hex"),
                last_chunk.encode("hex"), s))
        else:
            last_chunk = data[-32:]
            # try to decode maximum of 16
            rdata = data[16:16*17]
            if plaintext:
                s = "1$%s" % plaintext
            else:
                s = "0"
            sys.stdout.write("%s:$openssl$%s$%s$8$%s$%s$0$%s$%s$%s\n" % (filename, cipher, md, salt.encode("hex"),
                last_chunk.encode("hex"), len(rdata), rdata.encode("hex"), s))


if __name__ == '__main__':

    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [-c cipher] [-m md] [-p plaintext] <OpenSSL encrypted files>\n" % sys.argv[0])
        sys.stderr.write("cipher: 0 => aes-256-cbc, 1 => aes-128-cbc\n")
        sys.stderr.write("md: 0 => md5, 1 => sha1\n")
        sys.exit(-1)

    parser = optparse.OptionParser()
    parser.add_option('-p', action="store", dest="plaintext")
    parser.add_option('-c', action="store", dest="cipher", default=0)
    parser.add_option('-m', action="store", dest="md", default=0)
    options, remainder = parser.parse_args()

    for j in range(0, len(remainder)):
        data = process(remainder[j], options.plaintext, options.cipher, options.md)
