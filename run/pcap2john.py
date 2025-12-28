#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Combine of all of Dhiru Kholia pcap convert utilities
# into a single program.  The pcap2john.readme lists
# all of the original license statements. This merge was
# done by JimF, Nov 2014, somewhat as a learning experience
# for Python.
#
# The code itself is still a fabrication of Dhiru.

# This software is
#
# Copyright (c) 2013-2018 Dhiru Kholia <dhiru at openwall.com>
# Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
# Copyright (c) 2014 Alexey Lapitsky <lex at realisticgroup.com>
# Copyright (c) 2014 m3g9tr0n (Spiros Fraganastasis) <spirosfr.1985 at gmail.com>
# Copyright (c) 2021-2024 exploide <me at exploide.net>
# Copyright (c) 2025 Albert Veli <albert.veli at gmail.com>
#
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

# pcap_parser_s7() is under GNU GPL v3 per the below statement:

# s7tojohn.py, parse .pcap files and output JtR compatible hashes.
# Extended by Narendra Kangralkar <narendrakangralkar at gmail.com>
# and Dhiru Kholia <dhiru at openwall.com>
#
# S7 protocol, is used for communication between Engineering Stations,
# SCADA, HMI & PLC and can be protected by password.
#
# Original Authors: Alexander Timorin, Dmitry Sklyarov
#
# http://scadastrangelove.org
#
# __author__      = "Aleksandr Timorin"
# __copyright__   = "Copyright 2013, Positive Technologies"
# __license__     = "GNU GPL v3"
# __version__     = "1.2"
# __maintainer__  = "Aleksandr Timorin"
# __email__       = "atimorin@gmail.com"
# __status__      = "Development"

import base64
from binascii import hexlify
import os
import socket
import struct
import sys

import logging
l = logging.getLogger("scapy.runtime")
l.setLevel(49)

try:
    from scapy.all import *
    from scapy.layers.http import HTTPRequest
except ImportError:
    sys.stderr.write("Please install 'scapy' package for Python, running 'pip install --user scapy' should work\n")
    sys.exit(1)

try:
    import dpkt
    import dpkt.ethernet as ethernet
    from dpkt import ip as dip
    import dpkt.stp as stp
except ImportError:
    sys.stderr.write("Please install 'dpkt' package for Python, running 'pip install --user dpkt' should work\n")
    sys.exit(1)


def pcap_parser_bfd(fname):

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
            salt = data[0:32].encode("hex")

            if authentication_type == 2 or authentication_type == 3:  # Keyed MD5, Meticulous Keyed MD5
                h = data[-16:].encode("hex")  # MD5 hash
                # password needs to be padded to length 16 (password + ''.join(['\x00' * (16 - len(password))])),
                # "netmd5" format automagically handles this ;)
                print("$netmd5$%s$%s" % (salt, h))
            elif authentication_type == 4 or authentication_type == 5:  # Keyed SHA1, Meticulous Keyed SHA1
                # http://tools.ietf.org/html/rfc5880
                # password needs to be padded to length 20 (password + ''.join(['\x00' * (20 - len(password))])),
                h = data[-20:].encode("hex")  # SHA1 hash
                print("$netsha1$%s$%s" % (salt, h))
            else:
                assert 0

    f.close()


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


def pcap_parser_vtp(fname):

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

        # VTP v1 "Summary Advertisement" message, see "vtp_validate_md5_digest"
        # function in cisco_IOS-11.2-8_source.tar.bz2
        if data.startswith("\x01\x01"):
            # hash is "towards" the end of the packet
            h = data[56:56+16].encode("hex")
            sys.stderr.write("[WIP] VTP packet found with MD5 hash %s!\n" % (h))

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
                print("%s:$vtp$%d$%s$%s$%s$%s$%s" % (index, ord(salt[0]), vlans_data_length,
                                                                  vlans_data.encode("hex"), len(salt),
                                                                  salt.encode("hex"), h))

    f.close()


def pcap_parser_vrrp(fname):
    """
    Parse packets of the Virtual Router Redundancy Protocol (VRRP).
    """

    pcap = rdpcap(fname)

    for index, pkt in enumerate(pcap, start=1):
        if pkt.haslayer(VRRP):
            pkt = pkt['VRRP']
            # check for Version 2, Packet type 1 (Advertisement)
            if pkt.version != 2 or pkt.type != 1:
                sys.stderr.write("Unsupported VRRP packet version %d or type %d, packet # %d\n" % (pkt.version, pkt.type, index))
                continue
            # check for packets that are actually authenticated
            if pkt.authtype != 0:
                # hash is at the end of the packet
                h = bytes(pkt['Raw'])[-16:]
                # zero-ize checksum (of length 2)
                pkt.chksum = 0
                # salt extends from offset 0 to 20
                salt = bytes(pkt)
                print("%s:$hsrp$%s$%s" % (index, hexlify(salt).decode('ascii'), hexlify(h).decode('ascii')))


def pcap_parser_tcpmd5(fname):

    f = open(fname, "rb")
    pcap = dpkt.pcap.Reader(f)

    for _, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data

            if ip.v != 4:
                continue

            if ip.p != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data

            # this packet doesn't have MD5 signature (too small)
            if tcp.off * 4 < 40:
                continue

            raw_ip_data = ip.pack()
            raw_tcp_data = tcp.pack()
            length = len(raw_tcp_data)

            # connection_id = (ip.src, tcp.sport, ip.dst, tcp.dport)

            if len(tcp.opts) < 18:  # MD5 signature "option" is 18 bytes long
                continue

            found = False

            for opt_type, opt_data in dpkt.tcp.parse_opts(tcp.opts):
                # skip over "undesired" option fields
                # TCP_OPT_MD5 = 19 implies TCP MD5 signature, RFC 2385
                if opt_type != 19:
                    continue

                found = True
                break

            if not found:
                continue

            # MD5 signature "option" is 16 bytes long
            if len(opt_data) != 16:
                continue

            # TCP_OPT_MD5 = 19 implies TCP MD5 signature, RFC 2385
            if opt_type == 19:
                header_length = tcp.off * 4
                data_length = length - header_length
                # print length, header_length, data_length

                # TCP pseudo-header + TCP header + TCP segment data
                # salt_length = 12 + 20 + data_length
                # add TCP pseudo-header
                salt = raw_ip_data[12:12 + 8]  # src. and dest. IP
                salt = salt + "\x00"  # zero padding
                salt = salt + raw_ip_data[9]  # protocol
                salt = salt + "%c" % (length / 256)  # segment length
                salt = salt + "%c" % (length % 256)  # segment length
                # add TCP header
                salt = salt + raw_tcp_data[:16]  # TCP header without checksum
                salt = salt + ("\x00" * 4)  # add zero checksum
                # add segment data
                salt = salt + raw_tcp_data[header_length:header_length + data_length]
                # print len(salt)

                print("$tcpmd5$%s$%s" % (salt.encode("hex"),
                                                      opt_data.encode("hex")))

    f.close()


def pcap_parser_s7(cfg_pcap_file):
    found_something = False

    # s7-1500_brute_offline.py code
    #
    # Offline password bruteforse based on challenge-response data, extracted
    # from auth traffic dump file for Siemens S7-1500 PLC's.
    #
    # IMPORTANT:
    #
    # traffic dump should contains only traffic between plc and hmi/pc/etc.
    # filter dump file before parse
    result = {}
    challenge = ''
    response = ''

    for packet in rdpcap(cfg_pcap_file):
        try:
            payload = packet.load.encode('hex')
            # if payload[14:26]=='720200453200' and payload[46:52]=='100214' and abs(packet.len+14 - 138)<=1:
            if payload[14:20] == '720200' and payload[46:52] == '100214' and abs(packet.len+14 - 138) <= 1:
                challenge = payload[52:92]
            # elif payload[14:26]=='720200663100' and payload[64:70]=='100214'  and abs(packet.len+14 - 171)<=1:
            elif payload[14:20] == '720200' and payload[64:70] == '100214' and abs(packet.len+14 - 171) <= 1:
                response = payload[70:110]

            if challenge and response:
                result[challenge] = response
                challenge = ''
                response = ''
        except:
            pass

    outcome = 0  # XXX we don't know this currently!
    for c, r in result.items():
        found_something = True  # overkill ;(
        print("%s:$siemens-s7$%s$%s$%s" % (os.path.basename(cfg_pcap_file),
                                                        outcome, c, r))

    # s7-1200_brute_offline.py stuff below
    # try to find challenge packet
    r = rdpcap(cfg_pcap_file)

    lens = map(lambda x: x.len, r)
    pckt_lens = dict([(i, lens[i]) for i in range(0, len(lens))])

    pckt_108 = None  # challenge packet (from server)
    for (pckt_indx, pckt_len) in pckt_lens.items():
        if (pckt_len + 14 == 108 and
                hexlify(r[pckt_indx].load)[14:24] == '7202002732'):
            pckt_108 = pckt_indx
            break

    # try to find response packet
    pckt_141 = 0  # response packet (from client)
    _t1 = dict([(i, lens[i]) for i in pckt_lens.keys()[pckt_108:]])
    for pckt_indx in sorted(_t1.keys()):
        pckt_len = _t1[pckt_indx]
        if (pckt_len + 14 == 141 and
                hexlify(r[pckt_indx].load)[14:24] == '7202004831'):
            pckt_141 = pckt_indx
            break

    # try to find auth result packet
    pckt_84 = 0  # auth answer from plc: pckt_len==84 -> auth ok
    pckt_92 = 0  # auth answer from plc: pckt_len==92 -> auth bad
    for pckt_indx in sorted(_t1.keys()):
        pckt_len = _t1[pckt_indx]
        if (pckt_len + 14 == 84 and
                hexlify(r[pckt_indx].load)[14:24] == '7202000f32'):
            pckt_84 = pckt_indx
            assert(pckt_84)
            break
        if (pckt_len + 14 == 92 and
                hexlify(r[pckt_indx].load)[14:24] == '7202001732'):
            pckt_92 = pckt_indx
            assert(pckt_92)
            break

    # print "found packets indices: pckt_108=%d, pckt_141=%d, pckt_84=%d, pckt_92=%d" % (pckt_108, pckt_141, pckt_84,
    #   pckt_92) if pckt_84:
    #    print "auth ok"
    # else:
    #    print "auth bad. for brute we need right auth result. exit"
    #    sys.exit()

    challenge = None
    response = None

    if not pckt_108 and found_something:
        sys.exit(0)

    try:
        raw_challenge = hexlify(r[pckt_108].load)
    except (AttributeError):
        sys.stderr.write("%s : expected data not found!\n" % cfg_pcap_file)
        return
    if raw_challenge[46:52] == '100214' and raw_challenge[92:94] == '00':
        challenge = raw_challenge[52:92]
        # print("found challenge: %s" % challenge)
    else:
        sys.stderr.write("[-] cannot find challenge for %s. exiting...\n"
                         % os.path.basename(cfg_pcap_file))
        return

    raw_response = hexlify(r[pckt_141].load)
    if raw_response[64:70] == '100214' and raw_response[110:112] == '00':
        response = raw_response[70:110]
        # print("found  response: %s" % response)
    else:
        sys.stderr.write("[-] cannot find response for %s. exiting...\n"
                         % os.path.basename(cfg_pcap_file))
        return

    if pckt_84:
        outcome = 1
    else:
        outcome = 0
    print("%s:$siemens-s7$%s$%s$%s" % (os.path.basename(cfg_pcap_file),
                                                    outcome, challenge, response))


def pcap_parser_rsvp(fname):

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
            print("%s:$rsvp$%d$%s$%s" % (index, algo_type, salt.encode("hex"), h.encode("hex")))

    f.close()


def pcap_parser_ntp(fname):

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

            if length == 16:  # md5($p.$s)
                print("%s:$dynamic_2001$%s$HEX$%s" % (index, h.encode("hex"), salt.encode("hex")))
            elif length == 20:  # sha1($p.$s)
                print("%s:$dynamic_24$%s$HEX$%s" % (index, h.encode("hex"), salt.encode("hex")))
            elif length == 28:  # sha224($p.$s)
                print("%s:$dynamic_52$%s$HEX$%s" % (index, h.encode("hex"), salt.encode("hex")))
            elif length == 32:  # sha256($p.$s)
                print("%s:$dynamic_62$%s$HEX$%s" % (index, h.encode("hex"), salt.encode("hex")))
            elif length == 48:
                print("%s:$dynamic_72$%s$HEX$%s" % (index, h.encode("hex"), salt.encode("hex")))
            elif length == 64:
                print("%s:$dynamic_82$%s$HEX$%s" % (index, h.encode("hex"), salt.encode("hex")))
            else:
                print("Unsupported hash of length %s found!" % len(data), file=sys.stderr)

    f.close()


def pcap_parser_isis(fname):

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
            if isinstance(data, dpkt.cdp.CDP) or isinstance(data, dpkt.stp.STP):
                continue
        except:
            continue

        data = data[3:]  # dirty hack to skip over LLC stuff
        discriminator = ord(data[0])
        if discriminator != 0x83:  # IS-IS
            continue

        # Check PDU type (HELLO, LSP, CSNP), LSP needs additional treatment
        pdu_type = ord(data[4])
        if pdu_type == 18 or pdu_type == 20:  # LSP PDU, L1 and L2
            # zeroize the "lifetime" and "checksum" fields
            data = data[:10] + "\x00\x00" + data[12:24] + "\x00\x00" + data[26:]

        isis_data = data[8:]  # double check this!

        # find authentication TLV using brute-force
        for offset in range(0, len(isis_data) - 3):
            tlv_type = ord(isis_data[offset])
            tlv_length = ord(isis_data[offset+1])
            authentication_type = ord(isis_data[offset+2])

            if tlv_type == 0x0a and tlv_length == 17 and authentication_type == 0x36:  # hmac-md5 is being used
                    hash_length = 16
                    h = isis_data[offset+3:offset+3+hash_length]
                    # http://tools.ietf.org/html/rfc1195
                    salt = data.replace(h, "\x00" * hash_length)  # zero out the hash
                    print("%s:$rsvp$1$%s$%s" % (index, salt.encode("hex"), h.encode("hex")))
                    break
            # https://tools.ietf.org/html/rfc5310
            if tlv_type == 0x0a and tlv_length == 23 and authentication_type == 0x3:  # hmac-sha1
                    hash_length = 20
                    h = isis_data[offset+3+2:offset+3+2+hash_length]  # +2 is required to skip over "Key ID"
                    # ospf format supports such hashes!
                    salt = data.replace(h, "")  # remove the hash
                    print("%s:$ospf$1$%s$%s" % (index, salt.encode("hex"), h.encode("hex")))
                    break
            if tlv_type == 0x0a and tlv_length == 31 and authentication_type == 0x3:  # hmac-sha224
                    hash_length = 28
                    h = isis_data[offset+3+2:offset+3+2+hash_length]
                    salt = data.replace(h, "")  # remove the hash
                    print("%s:$ospf$5$%s$%s" % (index, salt.encode("hex"), h.encode("hex")))  # yes, 5 is out-of-order
                    break
            if tlv_type == 0x0a and tlv_length == 35 and authentication_type == 0x3:  # hmac-sha256
                    hash_length = 32
                    h = isis_data[offset+3+2:offset+3+2+hash_length]
                    salt = data.replace(h, "")  # remove the hash
                    print("%s:$ospf$2$%s$%s" % (index, salt.encode("hex"), h.encode("hex")))
                    break
            if tlv_type == 0x0a and tlv_length == 51 and authentication_type == 0x3:  # hmac-sha384
                    hash_length = 48
                    h = isis_data[offset+3+2:offset+3+2+hash_length]
                    salt = data.replace(h, "")  # remove the hash
                    print("%s:$ospf$3$%s$%s" % (index, salt.encode("hex"), h.encode("hex")))
                    break
            if tlv_type == 0x0a and tlv_length == 67 and authentication_type == 0x3:  # hmac-sha512
                    hash_length = 64
                    h = isis_data[offset+3+2:offset+3+2+hash_length]
                    salt = data.replace(h, "")  # remove the hash
                    print("%s:$ospf$4$%s$%s" % (index, salt.encode("hex"), h.encode("hex")))
                    break

    f.close()


def pcap_parser_hsrp(fname):
    """
    Parse packets of the Hot Standby Router Protocol (HSRP).
    https://www.rfc-editor.org/rfc/rfc2281
    """

    pcap = rdpcap(fname)

    for pkt in pcap:
        if pkt.haslayer(HSRPmd5):
            pkt = pkt['HSRP']
            if pkt['HSRPmd5'].type != 4:
                continue
            h = bytes(pkt['HSRPmd5'].authdigest)
            salt = bytes(pkt)[:34] + b"\x00"*16
            print("$hsrp$%s$%s" % (hexlify(salt).decode('ascii'), hexlify(h).decode('ascii')))


def pcap_parser_hsrp_v2(fname):
    f = open(fname, "rb")
    pcap = dpkt.pcap.Reader(f)

    index = 0
    for _, buf in pcap:
        index = index + 1
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data

            if eth.type == dpkt.ethernet.ETH_TYPE_IP and ip.p != dpkt.ip.IP_PROTO_UDP:
                continue
            if eth.type == dpkt.ethernet.ETH_TYPE_IP6 and ip.nxt != dpkt.ip.IP_PROTO_UDP:
                continue

            udp = ip.data
            if udp.dport != 1985:  # is this HSRP traffic?
                continue
            data = udp.data

            # HSRPv2 uses TLVs
            offset = 0
            uses_authentication = False
            salt = ""
            while True:
                try:
                    tlv_type = ord(data[offset:offset+1])
                    tlv_length = ord(data[offset+1:offset+2])
                    if tlv_type == 1:  # Group State TLV
                        salt = salt + data[offset:offset+tlv_length+2]
                        offset = offset + tlv_length + 2  # +2 for tlv_length and tlv_length
                    elif tlv_type == 4:  # MD5 Authentication TLV
                        h = data[offset+tlv_length+2-16:]  # MD5 hash, last 16 bytes
                        salt = salt + data[offset:offset+tlv_length+2].replace(h, "\x00" * 16)
                        uses_authentication = True
                        offset = offset + tlv_length + 2
                    else:
                        break
                except:
                    break

            if uses_authentication:
                print("%d:$hsrp$%s$%s" % (index, salt.encode("hex"), h.encode("hex")))

    f.close()


def pcap_parser_glbp(fname):

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

            if len(data) < 40:  # rough estimate ;)
                continue

            # Ideally, we should do Authentication TLV processing with generic TLV processing code below!
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
            h = data[20:20 + 16].encode("hex")

            # salt extends from offset 0 to 19 (hash starts from 20)
            salt = data[0:20]
            # append "Source GeoIP" + 12 zero bytes (verify this part) to
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

            print("%s:$hsrp$%s$%s" % (index, salt.encode("hex"), h))

    f.close()


# Parts are borrowed from "module_tacacs_plus.py" from the loki project which is
# Copyright 2015 Daniel Mende <dmende@ernw.de>. See the licensing blurb before
# "pcap_parser_wlccp" function.
#
#  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8  1 2 3 4 5 6 7 8
#
# +----------------+----------------+----------------+----------------+
# |major  | minor  |                |                |                |
# |version| version|      type      |     seq_no     |   flags        |
# +----------------+----------------+----------------+----------------+
# |                                                                   |
# |                            session_id                             |
# +----------------+----------------+----------------+----------------+
# |                                                                   |
# |                              length                               |
# +----------------+----------------+----------------+----------------+

def pcap_parser_tacacs_plus(fname):
    TACACS_PLUS_PORT = 49
    TACACS_PLUS_VERSION_MAJOR = 0xc
    TYPE_AUTHEN = 0x01
    FLAGS_UNENCRYPTED = 0x01

    f = open(fname, "rb")
    pcap = dpkt.pcap.Reader(f)
    index = 0

    for _, buf in pcap:
        index = index + 1
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ip = eth.data

            if eth.type == dpkt.ethernet.ETH_TYPE_IP and ip.p != dpkt.ip.IP_PROTO_TCP:
                continue
            if eth.type == dpkt.ethernet.ETH_TYPE_IP6 and ip.nxt != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            data = tcp.data

            if tcp.dport != TACACS_PLUS_PORT and tcp.sport != TACACS_PLUS_PORT:
                continue
            if len(tcp.data) <= 12:
                continue

            server = tcp.sport == TACACS_PLUS_PORT
            ver, kind, seq_no, flags, session_id, length = struct.unpack("!BBBBII", data[:12])
            if flags & FLAGS_UNENCRYPTED:
                continue
            version_minor = ver & 0x0F
            if not server or kind != TYPE_AUTHEN:
                continue
            ciphertext = data[12:]
            predata = struct.pack("!I", session_id)
            postdata = struct.pack("!BB", TACACS_PLUS_VERSION_MAJOR << 4 + version_minor, seq_no)
            print("%s:$tacacs-plus$0$%s$%s$%s" % (index,
                                                               predata.encode("hex"),
                                                               ciphertext.encode("hex"),
                                                               postdata.encode("hex")))
    f.close()

# This code is borrowed from "module_wlccp.py" from the loki project which is
# Copyright 2015 Daniel Mende <dmende@ernw.de>.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.


def pcap_parser_wlccp(fname):
    f = open(fname, "rb")
    pcap = dpkt.pcap.Reader(f)
    index = 0

    comms = {}  # "state machine", bugs introduced by me!

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

            if udp.dport != 2887 and udp.sport != 2887:
                continue
            if len(udp.data) <= 28 + 12 + 6 + 4 + 16:  # rough check
                continue

            # WLCCP header parse
            (version, sap, dst_type, length, msg_type, hopcount, iden, flags, orig_node_type) = struct.unpack("!BBHHBBHHH", data[:14])
            orig_node_mac = data[14:20]
            dst_node_type = struct.unpack("!H", data[20:22])
            dst_node_mac = data[22:28]
            data = data[28:]

            if msg_type & 0x3f == 0x0b:  # EAP AUTH
                # EAP header parse
                requestor_type = struct.unpack("!H", data[:2])
                requestor_mac = data[2:8]
                (aaa_msg_type, aaa_auth_type, aaa_key_mgmt_type, status_code) = struct.unpack("!BBBB", data[8:12])
                data = data[12:]
                host = requestor_mac.encode("hex")
                if host in comms:
                    leap = comms[host]
                elif not host == "000000000000":
                    comms[host] = (None, None, None, None)

                (eapol_version, eapol_type, eapol_len) = struct.unpack("!BBH", data[2:6])
                data = data[6:]
                # check EAP-TYPE
                if eapol_type == 0x00:
                    (eap_code, eap_id, eap_len) = struct.unpack("!BBH", data[:4])
                    data = data[4:]
                    # check EAP-CODE
                    if eap_code == 0x01:
                        (leap_type, leap_version, leap_reserved, leap_count) = struct.unpack("!BBBB", data[:4])
                        data = data[4:]
                        # EAP-REQUEST, check the leap hdr
                        if leap_type == 0x11 and leap_version == 0x01 and leap_reserved == 0x00 and leap_count == 0x08:
                            (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp) = leap
                            if not leap_auth_chall and not leap_auth_resp and not leap_supp_chall and not leap_supp_resp:
                                iden = eap_id
                                chall = data[:8]
                                user = data[8:16]
                                print("[DEBUG] WLCCP: EAP-AUTH challenge from authenticator seen for %s" % host, file=sys.stderr)
                                comms[host] = ((iden, chall, user), leap_auth_resp, leap_supp_chall, leap_supp_resp)
                            elif leap_auth_chall and leap_auth_resp and not leap_supp_chall and not leap_supp_resp:
                                chall = data[:8]
                                print("[DEBUG] WLCCP: EAP-AUTH challenge from supplicant seen for %s" % host, file=sys.stderr)
                                comms[host] = (leap_auth_chall, leap_auth_resp, chall, leap_supp_resp)
                    elif eap_code == 0x02:
                            (leap_type, leap_version, leap_reserved, leap_count) = struct.unpack("!BBBB", data[:4])
                            data = data[4:]
                            # EAP-RESPONSE, check the leap hdr
                            if leap_type == 0x11 and leap_version == 0x01 and leap_reserved == 0x00 and leap_count == 0x18:
                                (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp) = leap
                                if leap_auth_chall and not leap_auth_resp and not leap_supp_chall and not leap_supp_resp:
                                    resp = data[:24]
                                    print("[DEBUG] WLCCP: EAP-AUTH response from authenticator seen for %s" % host, file=sys.stderr)
                                    comms[host] = (leap_auth_chall, resp, leap_supp_chall, leap_supp_resp)
                                elif leap_auth_chall and leap_auth_resp and leap_supp_chall and not leap_supp_resp:
                                    resp = data[:24]
                                    print("[DEBUG] WLCCP: EAP-AUTH response from supplicant seen for %s" % host, file=sys.stderr)
                                    comms[host] = (leap_auth_chall, leap_auth_resp, leap_supp_chall, resp)

    for entry in comms:
        (leap_auth_chall, leap_auth_resp, leap_supp_chall, leap_supp_resp) = comms[entry]
        if leap_auth_chall:
            _, challenge, user = leap_auth_chall
            print("%s:$NETNTLM$%s$%s" % (user, challenge.encode("hex"), leap_auth_resp.encode("hex")))

    f.close()


def pcap_parser_gadu(fname):
    """
    Parse packets of the Gadu-Gadu instant messenger.
    """

    pcap = rdpcap(fname)

    ports = [8074]
    nonce = ""
    for pkt in pcap:
        if not TCP in pkt:
            continue
        if not pkt[TCP].dport in ports and not pkt[TCP].sport in ports:
            continue

        payload = hexlify(bytes(pkt[TCP].payload)).decode('ascii')
        if payload[:8] == '01000000':  # GG_WELCOME
            nonce = payload[16:]
        if payload[:8] == '31000000':  # GG_LOGIN80
            hashtype = payload[28:30]
            if hashtype == "02":
                uid = payload[16:24]
                sha1 = payload[30:70]
                if len(nonce) == 0:
                    continue
                # swap endianness
                uid = ''.join([uid[i:i+2] for i in range(0, len(uid), 2)][::-1])
                uid = int(uid, 16)
                print("%s:$dynamic_24$%s$HEX$%s" % (uid, sha1, nonce))
        if payload[:8] == '83000000':  # GG_LOGIN105
            # GG_LOGIN105 stores uid as hex encoded ASCII. 16th byte is the number of digits in uid.
            # uid begins at 17th byte. sha1 hash is separated from last digit of uid by two bytes.
            digits = int(payload[30:32], 16)
            uid = payload[32:32 + 2*digits].decode("hex")
            offset = 32 + 2*digits + 4
            sha1 = payload[offset:offset + 40]
            print("%s:$dynamic_24$%s$HEX$%s" % (uid, sha1, nonce))


def pcap_parser_eigrp(fname):

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
            destination = socket.inet_ntoa(ip.src)

            if ord(data[0]) != 2:  # EIGRP version
                continue

            if len(data) < 40:  # skip small packets
                continue

            have_extra_salt = False
            extra_salt = ""
            internal_routes = ""
            opcode = ord(data[1])

            # Check EIGRP Flags
            flags = struct.unpack(">I", data[4:8])[0]
            if opcode == 1 and flags == 1:  # Update with "Init" flags
                # sys.stderr.write("[-] Ignoring update packet (%s) with init flag!\n" % index)
                # these packets have MD5 hash but no password is actually involved in MD5 hash calculation, wow!
                continue

            # Authentication Type TLV is at offset 20, does this always hold?
            tlv_type = struct.unpack(">H", data[20:22])[0]
            if tlv_type != 2:
                continue
            # Is this MD5 authentication?
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
                        tlv_data_parameters = data[offset:offset+tlv_length - 2]  # till "K6", 10 bytes
                        full_tlv_data_parameters = data[offset:offset+tlv_length]
                        offset = offset + tlv_length
                    elif tlv_type == 4:  # Software Version
                        tlv_data_version = data[offset:offset+tlv_length]
                        offset = offset + tlv_length
                    elif tlv_type == 0x00f5:  # Peer Topology ID List
                        # does Peer Topology ID List trigger inclusion of Parameters TLV into the MD5 process?
                        tlv_data_peer = data[offset:offset+6] \
                            + "\x00"  # only 6 bytes with \x00 appended seems to be used
                        offset = offset + tlv_length
                        have_extra_salt = 1
                        extra_salt = tlv_data_parameters.encode("hex")
                    elif tlv_type == 0x0003:  # Sequence TLV
                        # does Sequence / Next multicast sequence TLV trigger the inclusion of Parameters TLV, Type
                        # 0x0004 TLV (Software Version) and Peer Topology TLV? this stuff keeps getting weirder!
                        offset = offset + tlv_length
                        extra_salt = (full_tlv_data_parameters + tlv_data_version + tlv_data_peer).encode("hex")
                        have_extra_salt = 1
                    elif tlv_type == 0x00f2:  # Internal Route(MTR)
                        extra_salt = data[offset:offset+22] \
                            + "\x00".encode("hex")  # only 22 bytes seem to be used
                        offset = offset + tlv_length
                        have_extra_salt = 1
                    elif tlv_type == 0x0602:  # Internal Route (seen with "Update" with Flags == 0)
                        # there can be multiple such TLVs!
                        internal_routes = internal_routes + data[offset:offset + tlv_length]
                        offset = offset + tlv_length
                        have_extra_salt = 1
                    else:
                        break
                except:
                    break

            # strangely, the last 20 bytes of internal_routes are chopped in MAC calculation!
            if internal_routes:
                internal_routes = internal_routes[:-20].encode("hex")
                extra_salt = extra_salt + internal_routes

            if not extra_salt:
                extra_salt = "no-extra-salt"

            # HMAC-SHA-256 seems to use all data as salt
            if algo_type == 3:
                salt = data[0:2] + "\x00\x00\x00\x00" + data[6:]  # zero-ize checksum
                salt = salt.replace(h.decode("hex"), "\x00" * hash_length)  # zero-ize the digest

            print("%s:$eigrp$%d$%s$%d$%s$1$%s$%s" % (index, algo_type, salt.encode("hex"), have_extra_salt,
                                                                  extra_salt, destination, h))

    f.close()


# https://github.com/nidem/kerberoast (Apache License, Author is "nidem")
def pcap_parser_tgsrep(fname):
    MESSAGETYPEOFFSETUDP = 17
    MESSAGETYPEOFFSETTCP = 21

    TGS_REP = chr(13)

    kploads = []
    packets = rdpcap(fname)
    unfinished = {}
    index = 0
    for p in packets:
        index = index + 1
        # UDP
        if p.haslayer(UDP) and p.sport == 88 and p[UDP].load[MESSAGETYPEOFFSETUDP] == TGS_REP:
            kploads.append(p[UDP].load)

        # TCP
        elif p.haslayer(TCP) and p.sport == 88 and p[TCP].flags & 23 == 16:  # ACK Only, ignore push (8), urg (32), and ECE (64+128)
            # assumes that each TCP packet contains the full payload

            if len(p[TCP].load) > MESSAGETYPEOFFSETTCP and p[TCP].load[MESSAGETYPEOFFSETTCP] == TGS_REP:
                # found start of new TGS-REP
                size = struct.unpack(">I", p[TCP].load[:4])[0]
                if size + 4 == len(p[TCP].load):
                    kploads.append(p[TCP].load[4:size+4])  # strip the size field
                else:
                    # print 'ERROR: Size is incorrect: %i vs %i' % (size, len(p[TCP].load))
                    unfinished[(p[IP].src, p[IP].dst, p[TCP].dport)] = (p[TCP].load[4:size+4], size)
            elif unfinished.has_key((p[IP].src, p[IP].dst, p[TCP].dport)):
                ticketdata, size = unfinished.pop((p[IP].src, p[IP].dst, p[TCP].dport))
                ticketdata += p[TCP].load
                # print "cont: %i %i" % (len(ticketdata), size)
                if len(ticketdata) == size:
                    kploads.append(ticketdata)
                elif len(ticketdata) < size:
                    unfinished[(p[IP].src, p[IP].dst, p[TCP].dport)] = (ticketdata, size)
                else:
                    # OH NO! Oversized!
                    print('Too much data received! Source: %s Dest: %s DPort %i' % (p[IP].src, p[IP].dst, p[TCP].dport), file=sys.stderr)

    for p in kploads:
        print("%s:$tgsrep$%s" % (index, p.encode("hex")))


def pcap_parser_ah(fname):
    """
    Extract Authentication Header (AH) hashes from packets.

    VRRP v2 only supports IPv4 addresses. VRRP v3 protocol does not support
    authentication. Use "Keepalived for Linux" for debugging this function.

    https://fossies.org/linux/scapy/scapy/layers/ipsec.py mentions various HMAC
    schemes which are possible in the Authentication Header (AH).
    """

    pcap = rdpcap(fname)

    for pkt in pcap:
        if pkt.haslayer(AH) and pkt.haslayer(IP):
            pkt = pkt['IP']
            # zero mutable fields
            pkt.tos = 0
            pkt.flags = 0
            pkt.chksum = 0
            # store icv; zero icv in original packet
            icv = pkt['AH'].icv
            pkt['AH'].icv = bytearray(len(icv))
            # print net-ah hash
            print("$net-ah$0$%s$%s" % (hexlify(bytes(pkt)).decode('ascii'), hexlify(icv).decode('ascii')))


def pcap_parser_rndc(fname):
    """
    Extract BIND RNDC hashes from .pcap files.

    Based on rndc.py.in from bind-9.11.2.tar.gz tarball.
    """

    f = open(fname, "rb")
    pcap = dpkt.pcap.Reader(f)
    index = 0

    for _, buf in pcap:
        index = index + 1
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ip = eth.data

            if eth.type == dpkt.ethernet.ETH_TYPE_IP and ip.p != dpkt.ip.IP_PROTO_TCP:
                continue
            if eth.type == dpkt.ethernet.ETH_TYPE_IP6 and ip.nxt != dpkt.ip.IP_PROTO_TCP:
                continue

            tcp = ip.data
            data = tcp.data

            if tcp.dport != 953 and tcp.sport != 953:  # is this RNDC traffic?
                continue

            if len(data) < 48:
                continue

            # sanity check the payload
            offset = data.find("hmd5")
            kind = 1
            if offset == -1:
                offset = data.find("hsha")
                kind = 2
            if offset == -1:
                continue

            if kind == 1:
                hash_offset = offset + len("hmd5") + 5
                h = data[hash_offset:hash_offset + 22]
                if len(h) % 4:
                    h += '=' * (4 - len(h) % 4)
                h = base64.decodestring(h)
                data_offset = hash_offset + 22
                salt = data[data_offset:]
            elif kind == 2:
                hash_type_offset = offset + len("hmd5") + 5
                hash_type = ord(data[hash_type_offset:hash_type_offset + 1])
                hash_offset = offset + len("hsha") + 6
                h = data[hash_offset:hash_offset + 88]
                if len(h) % 4:
                    h += '=' * (4 - len(h) % 4)
                h = base64.decodestring(h)
                data_offset = hash_offset + 88
                salt = data[data_offset:]
                if hash_type == 161:  # SHA-1
                    kind = 2
                elif hash_type == 162:  # SHA-224
                    kind = 3
                elif hash_type == 163:  # SHA-256
                    kind = 4
                elif hash_type == 164:  # SHA-384
                    kind = 5
                elif hash_type == 165:  # SHA-512
                    kind = 6

            print("%s:$rsvp$%s$%s$%s" % (index, kind, salt.encode("hex"), h.encode("hex")))


    f.close()


def pcap_parser_tsig(fname):
    """
    Extract BIND TSIG hashes from .pcap files.
    """
    import dns
    import dns.message
    import dns.tsigkeyring

    mapping = {}

    keyring = dns.tsigkeyring.from_text({
        'update-key' : 'MTIzNDU2Nzg='
    })

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

            if udp.dport != 53 and udp.sport != 53:  # is this DNS traffic?
                continue

            is_response = True
            if udp.dport == 53:
                is_response = False

            if len(data) < 48:
                continue

            p = dns.message.from_wire(data, keyring=keyring, pout=False)
            if not is_response and hasattr(p, "mac"):
                mapping[p.id] = p.mac
            if is_response and hasattr(p, "mac"):
                request_mac = mapping.get(p.id, None)
                if request_mac:
                    p = dns.message.from_wire(data, keyring=keyring, request_mac=request_mac, pout=True)
            else:
                p = dns.message.from_wire(data, keyring=keyring, pout=True)

    f.close()


def pcap_parser_http_authorization(fname):
    """
    Parse the Authorization header of HTTP packets.
    Supports Digest Auth and prints hashes in $response$ format.
    Also outputs decoded Basic Auth credentials on stderr.
    """

    pcap = rdpcap(fname)

    for pkt in pcap:
        if not HTTPRequest in pkt:
            continue
        auth_header = pkt["HTTPRequest"].Authorization
        if not auth_header:
            continue

        if auth_header.startswith(b"Basic "):
            # directly print decoded Basic Auth credentials to stderr, no cracking necessary
            basic_auth = base64.b64decode(auth_header[6:]).decode("UTF-8")
            sys.stderr.write("FOUND HTTP BASIC AUTH: %s\n" % basic_auth)

        if auth_header.startswith(b"Digest "):
            try:
                from urllib.request import parse_http_list, parse_keqv_list
            except ImportError:
                # Python 2
                from urllib2 import parse_http_list, parse_keqv_list
            items = parse_http_list(auth_header[7:].decode("UTF-8"))
            opts = parse_keqv_list(items)
            print("%s:$response$%s$%s$%s$%s$%s$%s$%s$%s$%s" %
                    (opts['username'], opts["response"], opts['username'], opts["realm"],
                        pkt["HTTPRequest"].Method.decode('ascii'), opts["uri"],
                        opts["nonce"], opts["nc"], opts["cnonce"], opts["qop"]))

def pcap_parser_snmpv3(fname):
    """
    Parse SNMPv3 packets to extract authentication and privacy information.
    Supports SNMPv3 with authentication (authNoPriv) and authentication
    with privacy (authPriv). See:
    https://tools.ietf.org/html/rfc3414
    https://www.0x0ff.info/2013/snmpv3-authentification/
    Note: it sets authProto to 0 which makes JtR try both
          MD5 and SHA-1 for authentication. If you know the
          authProto, you can change it to 1 (MD5) or 2 (SHA-1).
          net-snmp supports MD5|SHA1|SHA224|SHA256|SHA384|SHA512
          but currently only MD5 and SHA1 are supported in JtR.
    """
    import re
    import dpkt
    import binascii

    with open(fname, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)

        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.udp.UDP):
                    continue
                udp = ip.data
                if udp.dport != 161:
                    continue

                data = bytearray(udp.data)

                # Find username (only supports printable ASCII usernames)
                matches = re.findall(rb'\x04[\x01-\x20]([ -~]{3,32})', data)
                if not matches:
                    continue
                username = matches[0].decode('ascii', 'ignore')

                # Extract engineID
                engid_index = data.find(b'\x04\x0b')
                if engid_index == -1 or len(data) < engid_index + 13:
                    continue
                engine_id = data[engid_index+2:engid_index+13]

                # Extract authParameters
                auth_index = data.find(b'\x04\x0c')
                if auth_index == -1 or len(data) < auth_index + 14:
                    continue

                auth_digest = data[auth_index+2:auth_index+14]
                data[auth_index+2:auth_index+14] = b'\x00' * 12

                # Extract privParameters (optional)
                priv_index = data.find(b'\x04\x08')
                priv_params = b''
                if priv_index != -1 and len(data) >= priv_index + 10:
                    priv_params = data[priv_index+2:priv_index+10]

                # Build output
                snmpv3_pdu_hex = binascii.hexlify(data).decode('ascii')
                engine_id_hex = binascii.hexlify(engine_id).decode('ascii')
                auth_digest_hex = binascii.hexlify(auth_digest).decode('ascii')
                auth_proto_id = 0  # Let JtR try both MD5 and SHA1

                if priv_params:
                    priv_proto_id = 4
                    priv_hex = binascii.hexlify(priv_params).decode('ascii')
                    print('$SNMPv3$%d$%d$%s$%s$%s$%s' % (
                        auth_proto_id, priv_proto_id,
                        snmpv3_pdu_hex, engine_id_hex,
                        auth_digest_hex, priv_hex))
                else:
                    priv_proto_id = 3
                    print('$SNMPv3$%d$%d$%s$%s$%s' % (
                        auth_proto_id, priv_proto_id,
                        snmpv3_pdu_hex, engine_id_hex,
                        auth_digest_hex))

            except Exception:
                pass  # Skip malformed packets silently


############################################################
# original main, but now calls multiple 2john routines, all
# cut from the original independent convert programs.
############################################################
if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.pcap files]\n" % sys.argv[0])
        sys.exit(1)

    # advertise what is not handled
    sys.stderr.write("Note: This program does not have the functionality of wpapcap2john, SIPdump, eapmd5tojohn, and vncpcap2john programs which are included with JtR Jumbo.\n\n")

    for i in range(1, len(sys.argv)):
        try:
            pcap_parser_ah(sys.argv[i])
        except:
            pass
        try:
            pcap_parser_bfd(sys.argv[i])
        except:
            pass
        try:
            pcap_parser_vtp(sys.argv[i])
        except:
            # sys.stderr.write("vtp could not handle input\n")
            pass
        try:
            pcap_parser_vrrp(sys.argv[i])
        except:
            pass
        try:
            pcap_parser_tcpmd5(sys.argv[i])
        except:
            pass
        try:
            pcap_parser_rsvp(sys.argv[i])
        except:
            pass
        try:
            pcap_parser_ntp(sys.argv[i])
        except:
            pass
        try:
            pcap_parser_isis(sys.argv[i])
        except:
            pass
        try:
            pcap_parser_hsrp(sys.argv[i])
        except:
            pass
        try:
            pcap_parser_hsrp_v2(sys.argv[i])
        except:
            pass
        try:
            pcap_parser_glbp(sys.argv[i])
        except:
            pass
        pcap_parser_gadu(sys.argv[i])
        try:
            pcap_parser_eigrp(sys.argv[i])
        except:
            pass
        pcap_parser_tgsrep(sys.argv[i])
        try:
            pcap_parser_tacacs_plus(sys.argv[i])
        except:
            pass
        try:
            pcap_parser_wlccp(sys.argv[i])
        except:
            pass
        try:
            pcap_parser_rndc(sys.argv[i])
        except:
            pass
        try:
            pcap_parser_tsig(sys.argv[i])
        except:
            pass
        pcap_parser_http_authorization(sys.argv[i])
        try:
            pcap_parser_s7(sys.argv[i])
        except:
            # sys.stderr.write("DEBUG: s7 parser could not handle input\n")
            pass
        try:
            pcap_parser_snmpv3(sys.argv[i])
        except:
            pass
