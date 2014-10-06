#!/usr/bin/env python
# -*- coding: utf-8 -*-

# NTP authentication parser.
#
# http://tools.ietf.org/html/rfc5905
# http://tools.ietf.org/html/rfc1305
# http://www.eecis.udel.edu/~mills/ntp/html/authentic.html
#
# TODO: Support SHA1 and other hashes
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

            # the whole NTP packet except the MAC (hash) and Key ID (48 bytes)
            salt = data[0:48]

            # hash is at at offset 52 (48 bytes of standard NTP data format + 4 bytes of Key ID)
            h = data[52:]

            # sys.stdout.write("%s:$ntp$%s$%s\n" % (index, salt.encode("hex"), h.encode("hex")))
            sys.stdout.write("%s:$dynamic_1016$%s$HEX$%s\n" % (index, h.encode("hex"), salt.encode("hex")))

    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.pcap files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        pcap_parser(sys.argv[i])
