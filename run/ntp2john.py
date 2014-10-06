#!/usr/bin/env python
# -*- coding: utf-8 -*-

# NTP authentication parser.
#
# http://tools.ietf.org/html/rfc5905
# http://tools.ietf.org/html/rfc1305
# http://www.eecis.udel.edu/~mills/ntp/html/authentic.html
#
# This software is Copyright (c) 2014 Spiros Fraganastasis <spirosfr.1985 at
# gmail.com> and Dhiru Kholia <dhiru at openwall.com>, and it is hereby
# released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import dpkt
import sys


def pcap_parser(fname):

    f = open(fname, "rb")
    pcap = dpkt.pcap.Reader(f)
    index = 0

    for _, buf in pcap:
        index = index + 1
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ip = eth.data

            if eth.type == dpkt.ethernet.ETH_TYPE_IP and ip.p != dpkt.ip.IP_PROTO_UDP:
                continue
            if eth.type == dpkt.ethernet.ETH_TYPE_IP6 and ip.nxt != dpkt.ip.IP_PROTO_UDP:
                continue

            udp = ip.data
            data = udp.data

            if udp.dport != 123:  # is this NTP traffic?
                continue

            if len(data) < 48:  # no authentication is being used
                continue

            # the whole NTP packet (till "Transmit Timestamp", 48 bytes)
            salt = data[0:48]
            data = data[48:]
            # skip of Key ID (4 bytes) or Extension length (4 bytes)
            data = data[4:]

            length = len(data)
            if length == 0:
                continue
            h = data

            if length == 16:  # MD5 hash
                sys.stdout.write("%s:$dynamic_1016$%s$HEX$%s\n" % (index, h.encode("hex"), salt.encode("hex")))
            elif length == 20:  # SHA1
                print "SHA-1 support is missing currently!"
            elif length == 28:
                print "SHA-224 support is missing currently!"
            elif length == 32:
                print "SHA-256 support is missing currently!"
            elif length == 48:
                print "SHA-384 support is missing currently!"
            elif length == 64:
                print "SHA-512 support is missing currently!"
            else:
                print "Unsupported hash of length %s found!" % len(data)


    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.pcap files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        pcap_parser(sys.argv[i])
