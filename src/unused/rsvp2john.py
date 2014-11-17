#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Parser for RSVP authentication packets.

# Based on http://tools.ietf.org/html/rfc2747 and some reversing.
#
# Output Format: packet_number:$rsvp$algo_type$salt$$hash
#
# This software is Copyright (c) 2014 Dhiru Kholia <dhiru at openwall.com>,
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import dpkt
import sys
import struct


def pcap_parser(fname):

    f = open(fname, "rb")
    pcap = dpkt.pcap.Reader(f)
    index = 0

    for _, buf in pcap:
        index = index + 1
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ip = eth.data

            if eth.type == dpkt.ethernet.ETH_TYPE_IP and ip.p != dpkt.ip.IP_PROTO_RSVP:
                continue
            if eth.type == dpkt.ethernet.ETH_TYPE_IP6 and ip.nxt != dpkt.ip.IP_PROTO_RSVP:
                continue

            data = ip.data  # RSVP object

            # RSVP header is 8 bytes, skip over it
            offset = 8

            # does the INTEGRITY object always follows the RSVP Header?
            length = struct.unpack(">H", data[offset:offset+2])[0]

            # "Object class" is at offset 3 within the "INTEGRITY" object
            object_class = ord(data[offset + 2])

            if object_class != 4:
                continue

            # hash is at offset 20 within the "INTEGRITY" object
            hash_length = length - 20
            h = data[offset+20:][:hash_length]
            if hash_length == 16:
                algo_type = 1
            else:
                algo_type = 2

            # zero-out the hash during hash calculation
            salt = data.replace(h, "\x00" * len(h))
            sys.stdout.write("%s:$rsvp$%d$%s$%s\n" % (index, algo_type, salt.encode("hex"), h.encode("hex")))

    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.pcap files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        pcap_parser(sys.argv[i])
