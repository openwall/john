#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Cracker for EIGRP authentication (MD5 and SHA-256 varients). Currently, this script is very speculative!
# http://tools.ietf.org/html/draft-savage-eigrp-02
#
# Wireshark dissects EIGRP messages pretty nicely.
# http://c0decafe.de/svn/codename_loki/trunk/modules/module_eigrp.py is cool
#
# Output Format,
# packet_number:$eigrp$algo_type$salt$have_extra_salt$extra_salt$hash
#
# $ md5sum i86bi-linux-l3-ipbase-12.4.bin  # EIGRP TLV version 3.0
# 3e79a8010a4174dc316a55e6d1886f3c  i86bi-linux-l3-ipbase-12.4.bin
#
# $ md5sum i86bi-linux-l3-adventerprisek9-15.4.1T.bin  # EIGRP TLV version 2.0
# 2eabae17778316c49cbc80e8e81262f9  i86bi-linux-l3-adventerprisek9-15.4.1T.bin
#
# "c3660-js-mz.124-11-T.image" uses EIGRP TLV version 1.2 and we can't crack
# such hashes currently (for unknown reasons).
#
# This is dedicated to Darya. You inspire me.
#
# This software is Copyright (c) 2014 Dhiru Kholia <dhiru at openwall.com>, and
# it is hereby released to the general public under the following terms:
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

            # IPv6 support is based on the following sample .pcap file
            # http://wiki.wireshark.org/SampleCaptures?action=AttachFile&do=get&target=eigrp-for-ipv6-auth.pcap
            if eth.type == dpkt.ethernet.ETH_TYPE_IP and ip.p != dpkt.ip.IP_PROTO_EIGRP:
                continue
            if eth.type == dpkt.ethernet.ETH_TYPE_IP6 and ip.nxt != dpkt.ip.IP_PROTO_EIGRP:
                continue

            data = ip.data

            if ord(data[0]) != 2:  # EIGRP version
                continue

            if len(data) < 40:  # XXX rough estimate ;)
                continue

            have_extra_salt = False
            extra_salt = "XXX"
            opcode = ord(data[1])

            # Check EIGRP Flags
            flags = struct.unpack(">I", data[4:8])[0]
            if opcode == 1 and flags == 1:  # Update with "Init" flags
                # sys.stderr.write("[-] Ignoring update packet (%s) with init flag!\n" % index)
                # these packets have MD5 hash but no password is actually involved in MD5 hash calculation, wow!
                continue

            # Authentication Type TLV is at offset 20
            tlv_type = struct.unpack(">H", data[20:22])[0]
            if tlv_type != 2:
                continue
            # Is this MD5 authentication? XXX
            algo_type = struct.unpack(">H", data[24:26])[0]
            if algo_type != 2 and algo_type != 3:  # MD5 and SHA-256
                sys.stderr.write("[-] Ignoring non-MD5 auth type in packet %s!\n" % index)
                continue

            # length = struct.unpack(">H", data[22:24])[0]
            hash_length = struct.unpack(">H", data[26:28])[0]

            # hash is at offset (28 + 16)
            h = data[28 + 16:][:hash_length].encode("hex")

            # salt extends from offset 0 to 44 (offset of Nullpad)
            # zero-ize checksum (of length 4) at offset 2
            salt = data[0:2] + "\x00\x00\x00\x00" + data[6:44]

            # process extra TLVs
            offset = 28 + 16 + 16
            while True:
                try:
                    tlv_type = struct.unpack(">H", data[offset:offset+2])[0]
                    tlv_length = struct.unpack(">H", data[offset+2:offset+2+2])[0]
                    if tlv_type == 1:  # Parameters TLV
                        assert tlv_length == 12  # XXX
                        tlv_data_parameters = data[offset:offset+tlv_length]
                        offset = offset + tlv_length
                    elif tlv_type == 4:  # Software Version
                        tlv_data_version = data[offset:offset+tlv_length]
                        offset = offset + tlv_length
                    elif tlv_type == 0x00f5:  # Peer Topology ID List
                        # does Peer Topology ID List trigger inclusion of Parameters TLV into the MD5 process?
                        tlv_data_peer = data[offset:offset+8] + "\x00"  # only 8 bytes seem to be used
                        offset = offset + tlv_length
                        have_extra_salt = 1
                        extra_salt = tlv_data_parameters.encode("hex")
                    elif tlv_type == 0x0003:  # Sequence TLV
                        # does Sequence / Next multicast sequence TLV trigger the inclusion of Parameters TLV, Type
                        # 0x0004 TLV and Peer Topology TLV? this stuff keeps getting weirder!
                        offset = offset + tlv_length
                        extra_salt = (tlv_data_parameters + tlv_data_version + tlv_data_peer).encode("hex")
                        have_extra_salt = 1
                    elif tlv_type == 0x00f2:  # Internal Route(MTR)
                        extra_salt = (data[offset:offset+22] + "\x00").encode("hex")  # only 22 bytes are used, wtaf? XXX
                        offset = offset + tlv_length
                        have_extra_salt = 1
                    elif tlv_type == 0x0602:  # Internal Router (seen with "Update" with Flags == 0)
                        extra_salt = (data[offset:offset+25]).encode("hex")
                        offset = offset + tlv_length
                        have_extra_salt = 1
                    else:
                        break
                except:
                    break

            sys.stdout.write("%s:$eigrp$%d$%s$%d$%s$%s\n" % (index, algo_type, salt.encode("hex"), have_extra_salt,
                                                             extra_salt, h))

    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.pcap files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        pcap_parser(sys.argv[i])
