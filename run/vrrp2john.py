#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Cracker for VRRP authentication (cisco varient).
#
# Output Format,
# packet_number:$vrrp$algo_type$salt$have_extra_salt$extra_salt$hash
#
# $ md5sum i86bi-linux-l3-ipbase-12.4.bin
# 3e79a8010a4174dc316a55e6d1886f3c  i86bi-linux-l3-ipbase-12.4.bin
#
# $ md5sum i86bi-linux-l3-adventerprisek9-15.4.1T.bin
# 2eabae17778316c49cbc80e8e81262f9  i86bi-linux-l3-adventerprisek9-15.4.1T.bin
#
# This software is Copyright (c) 2014 m3g9tr0n (Spiros Fraganastasis)
# <spirosfr.1985 at gmail.com> and Dhiru Kholia <dhiru at openwall.com>, and it
# is hereby released to the general public under the following terms:
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

            if eth.type == dpkt.ethernet.ETH_TYPE_IP and ip.p != dpkt.ip.IP_PROTO_VRRP:
                continue
            if eth.type == dpkt.ethernet.ETH_TYPE_IP6 and ip.nxt != dpkt.ip.IP_PROTO_VRRP:
                continue

            data = ip.data  # VRRP object
            data = data.pack()  # raw data

            if ord(data[0]) != 0x21:  # Version 2, Packet type 1 (Advertisement)
                sys.stderr.write("Unsupported VRRP packet type %d, packet # %d\n" % (ord(data[0]), index))
                continue

            if len(data) < 40:  # XXX rough estimate ;)
                continue

            # hash is at the end of the packet
            h = data[len(data) - 16:].encode("hex")

            # salt extends from offset 0 to 20
            # zero-ize checksum (of length 2) at offset 6
            salt = data[0:6] + "\x00\x00" + data[8:20]

            # use the existing "hsrp" format to crack VRRP hashes ;)
            sys.stdout.write("%s:$hsrp$%s$%s\n" % (index, salt.encode("hex"), h))

    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.pcap files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        pcap_parser(sys.argv[i])
