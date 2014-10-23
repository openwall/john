#!/usr/bin/env python

# Parser for IS-IS MD5 authentication packets.
#
# This software is Copyright (c) 2014 Dhiru Kholia <dhiru at openwall.com>, and it is hereby released to the general
# public under the following terms:
#
# Redistribution and use in source and binary forms, with or without modification, are permitted.

import dpkt
import dpkt.ethernet as ethernet
import dpkt.stp as stp
import sys
import struct


class LLC(dpkt.Packet):  # borrowed from dpkt "trunk"
    _typesw = {}

    def _unpack_data(self, buf):
        if self.type == ethernet.ETH_TYPE_8021Q:
            self.tag, self.type = struct.unpack('>HH', buf[:4])
            buf = buf[4:]
        elif self.type == ethernet.ETH_TYPE_MPLS or self.type == ethernet.ETH_TYPE_MPLS_MCAST:
            # XXX - skip labels
            for i in range(24):
                if struct.unpack('>I', buf[i:i+4])[0] & 0x0100:  # MPLS_STACK_BOTTOM
                    break
            self.type = ethernet.ETH_TYPE_IP
            buf = buf[(i + 1) * 4:]
        try:
            self.data = self._typesw[self.type](buf)
            setattr(self, self.data.__class__.__name__.lower(), self.data)
        except (KeyError, dpkt.UnpackError):
            self.data = buf

    def unpack(self, buf):
        self.data = buf
        self.classification = None
        if self.data.startswith('\xaa\xaa'):
            # SNAP
            self.type = struct.unpack('>H', self.data[6:8])[0]
            self._unpack_data(self.data[8:])
        else:
            # non-SNAP
            dsap = ord(self.data[0])
            if dsap == 0x06:  # SAP_IP
                self.data = self.ip = self._typesw[ethernet.ETH_TYPE_IP](self.data[3:])
            elif dsap == 0x10 or dsap == 0xe0:  # SAP_NETWARE{1,2}
                self.data = self.ipx = self._typesw[ethernet.ETH_TYPE_IPX](self.data[3:])
            elif dsap == 0x42:  # SAP_STP
                self.data = self.stp = stp.STP(self.data[3:])
            elif dsap == 0xfe:  # ISO Network Layer (routed ISO PDU, RFC 1483)
                self.data = self.data[3:]
                self.classification = "ISO_PDU"  # dirty hack


def pcap_parser(fname):

    f = open(fname, "rb")
    pcap = dpkt.pcap.Reader(f)

    index = 0

    for _, buf in pcap:
        index = index + 1
        eth = dpkt.ethernet.Ethernet(buf)
        data = eth.data
        if isinstance(data, dpkt.cdp.CDP) or isinstance(data, dpkt.stp.STP):
            continue

        try:
            llc = LLC(data)
            data = llc.data
            classification = llc.classification
            if isinstance(data, dpkt.cdp.CDP) or isinstance(data, dpkt.stp.STP):
                continue
        except:
            continue

        if not classification:
            continue

        discriminator = ord(data[0])
        if discriminator != 0x83:  # IS-IS
            continue

        isis_data = data[8:]  # double check this!
        offset = 19  # TLVs start after this
        has_hash = False

        # process TLVs
        while True:
            tlv_type = ord(isis_data[offset])
            tlv_length = ord(isis_data[offset+1])
            if tlv_length == 0:  # dirty
                break
            if tlv_type == 0x0a:  # authentication TLV
                authentication_type = ord(isis_data[offset+2])
                if tlv_length == 17 and authentication_type == 0x36:  # hmac-md5 is being used
                    has_hash = True
                    h = isis_data[offset+3:offset+3+16]
                    break
            offset = offset + tlv_length

        if not has_hash:
            continue

        # http://tools.ietf.org/html/rfc1195
        salt = data.replace(h, "\x00" * 16)  # zero out the hash
        sys.stdout.write("%s:$rsvp$1$%s$%s\n" % (index, salt.encode("hex"), h.encode("hex")))

    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.pcap files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        pcap_parser(sys.argv[i])
