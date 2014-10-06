#!/usr/bin/env python

# Parser for VTP MD5 authentication packets.
#
# This software is Copyright (c) 2014 Alexey Lapitsky <lex at realisticgroup.com> and Dhiru Kholia <dhiru at
# openwall.com>, and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Output Hash Format:
#
# $vtp$1/2/3$vlans_data_length$vlans_data$salt_length$salt$hash


import dpkt
import dpkt.ethernet as ethernet
import dpkt.stp as stp
import sys
import struct

VTP_DOMAIN_SIZE = 32


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


def pcap_parser(fname):

    f = open(fname, "rb")
    pcap = dpkt.pcap.Reader(f)

    index = 0
    vlans_data_length = -1

    revision_to_subset_mapping = {}
    revision_to_summary_mapping = {}

    for _, buf in pcap:
        index = index + 1
        eth = dpkt.ethernet.Ethernet(buf)
        data = eth.data
        if isinstance(data, dpkt.cdp.CDP) or isinstance(data, dpkt.stp.STP):
            continue

        llc = LLC(data)
        data = llc.data
        if isinstance(data, dpkt.cdp.CDP) or isinstance(data, dpkt.stp.STP):
            continue

        if data.startswith("\x02\x02") or data.startswith("\x01\x02"):  # VTP_SUBSET_ADVERT, learn "vlans_len"
            # VLAN Information is at offset 40
            vlans_data = data[40:]
            revision = data[36:40]
            revision_to_subset_mapping[revision] = vlans_data

        if not (data.startswith("\x02\x01") or data.startswith("\x01\x01")):  # VTP Version + Summary Advertisement
            continue

        revision = data[36:40]
        revision_to_summary_mapping[revision] = data

    # process the mappings
    for revision, vlans_data in revision_to_subset_mapping.items():
        if revision in revision_to_summary_mapping:
            salt = revision_to_summary_mapping[revision]

            # hash is "towards" the end of the packet
            h = salt[56:56+16].encode("hex")
            vlans_data_length = len(vlans_data)

            if vlans_data_length != -1:
                sys.stdout.write("%s:$vtp$%d$%s$%s$%s$%s$%s\n" % (index, ord(salt[0]), vlans_data_length,
                                                                  vlans_data.encode("hex"), len(salt),
                                                                  salt.encode("hex"), h))

    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.pcap files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        pcap_parser(sys.argv[i])
