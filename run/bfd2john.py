#!/usr/bin/env python

# Parser for BFD authentication packets.
#
# This software is Copyright (c) 2014 Dhiru Kholia <dhiru at openwall.com>, and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import dpkt
import sys


def pcap_parser(fname):

    f = open(fname, "rb")
    pcap = dpkt.pcap.Reader(f)

    for _, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            if ip.v != 4:
                continue

            if ip.p != dpkt.ip.IP_PROTO_UDP:
                continue

            udp = ip.data
            data = udp.data

            if udp.dport != 3784:  # bfd-control traffic
                continue

            message_flags = ord(data[1])
            if not message_flags & 0x05:  # Authentication is present
                continue

            authentication_type = ord(data[24])

            if authentication_type == 2:  # Keyed MD5
                h = data[-16:].encode("hex")  # MD5 hash
                salt = data[0:32].encode("hex")
                sys.stdout.write("$netmd5$%s$%s\n" % (salt, h))
            else:
                # http://tools.ietf.org/html/rfc5880 (TODO)
                assert 0

    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.pcap files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        pcap_parser(sys.argv[i])
