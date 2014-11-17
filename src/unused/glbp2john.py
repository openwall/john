#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Cracker for GLBP authentication. Wireshark dissects GLBP messages pretty
# nicely.
#
# Output Format,
# packet_number:$glbp$algo_type$salt$have_extra_salt$extra_salt$hash
#
# $ md5sum i86bi-linux-l3-ipbase-12.4.bin  # GLBP TLV version 3.0
# 3e79a8010a4174dc316a55e6d1886f3c  i86bi-linux-l3-ipbase-12.4.bin
#
# $ md5sum i86bi-linux-l3-adventerprisek9-15.4.1T.bin  # GLBP TLV version 2.0
# 2eabae17778316c49cbc80e8e81262f9  i86bi-linux-l3-adventerprisek9-15.4.1T.bin
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

            ip_headers = ip.pack_hdr()
            source_geoip = ip_headers[-8:-4]

            udp = ip.data
            data = udp.data

            if udp.dport != 3222:  # is this GLBP traffic?
                continue

            if ord(data[0]) != 1:  # GLBP version
                continue

            if len(data) < 40:  # XXX rough estimate ;)
                continue

            # Authentication Type TLV is at offset 12
            # XXX We should do Authentication TLV processing with generic TLV
            # processing code below!
            tlv_type = ord(data[12])
            if tlv_type != 3:
                continue

            # Is this "MD5 chain" type authentication?
            algo_type = ord(data[14])
            if algo_type != 3:
                sys.stderr.write("[-] Ignoring non-MD5-chain auth type in packet %s!\n" % index)
                continue
            auth_length = ord(data[15])
            if auth_length != 20:
                continue

            # hash is at offset 20
            h = data[20:20 +16].encode("hex")

            # salt extends from offset 0 to 19 (hash starts from 20)
            salt = data[0:20]
            # append "Source GeoIP" + 12 zero bytes (XXX, verify this part) to
            # the salt
            salt = salt + source_geoip + ("\x00" * 12)

            # process extra TLVs
            offset = 36

            while True:
                try:
                    tlv_type = ord(data[offset:offset+1])
                    tlv_length = ord(data[offset+1:offset+2])
                    if tlv_type == 1:  # Hello TLV, extract "Virtual IPv4"
                        hello_salt = data[offset:offset+tlv_length]
                        salt = salt + hello_salt
                        offset = offset + tlv_length
                    elif tlv_type == 4:  # unknown TLV ;)
                        unknown_salt = data[offset:offset+tlv_length]
                        salt = salt + unknown_salt
                        offset = offset + tlv_length
                    elif tlv_type == 2:  # Request/Response TLV?
                        rr_salt = data[offset:offset+tlv_length]
                        salt = salt + rr_salt
                        offset = offset + tlv_length
                    else:
                        break
                except:
                    break

            sys.stdout.write("%s:$hsrp$%s$%s\n" % (index, salt.encode("hex"), h))

    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.pcap files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        pcap_parser(sys.argv[i])
