#!/usr/bin/env python

# Cracker for HSRP v2 MD5 authentication.
#
# http://www.rfc-editor.org/rfc/rfc1828.txt
# https://www.ietf.org/rfc/rfc2281.txt
# http://www.gotohack.org/2011/01/scapy-hsrp-md5-auth-dissecter-to.html
# "i86bi-linux-l3-ipbase-12.4.bin" is fun ;)
#
# Written by Dhiru Kholia <dhiru at openwall.com> in September 2014.
#
# This is dedicated to Darya. You insipre me.

import dpkt
import sys

"""

UDP payload (HSRP message) format (https://www.ietf.org/rfc/rfc2281.txt)

                          1                   2                   3

   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Version     |   Op Code     |     State     |   Hellotime   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Holdtime    |   Priority    |     Group     |   Reserved    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Authentication  Data                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Authentication  Data                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Virtual IP Address                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# from scapy sources
if len(hsrp-payload) > 28:
    MD5 authentication is being used

class HSRPmd5(Packet):
    name = "HSRP MD5 Authentication"
    fields_desc = [
        ByteEnumField("type", 4, {4: "MD5 authentication"}),
        ByteField("len", None),
        ByteEnumField("algo", 0, {1: "MD5"}),
        ByteField("padding", 0x00),
        XShortField("flags", 0x00),
        IPField("sourceip", None),
        XIntField("keyid", 0x00),  # 14 bytes here
        StrFixedLenField("authdigest", "\00" * 16, 16)]

"""


def pcap_parser(fname):

    f = open(fname, "rb")
    pcap = dpkt.pcap.Reader(f)

    for _, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data

            if ip.v != 4:  # IPv6 is a fad
                continue

            if ip.p != dpkt.ip.IP_PROTO_UDP:
                continue

            udp = ip.data
            hsrp = udp.data

            if udp.dport != 1985:  # is this HSRP traffic?
                continue

            if ord(hsrp[0]) != 0:  # HSRP version
                continue

            if len(hsrp) <= 28:  # doesn't use MD5 authentication
                continue

            if len(hsrp) != 50:  # 20 bytes HSRP + 30 bytes for the MD5 authentication payload
                continue

            auth_type = ord(hsrp[20])
            if auth_type != 4:
                continue

            h = hsrp[-16:].encode("hex")  # MD5 hash
            # 20 bytes (HSRP) + 14 (till "keyid") + zero padding (XXX, double-check this) to make 50 bytes!
            salt = hsrp.encode("hex")[:68] + ("\x00" * (50 - 20 - 14)).encode("hex")
            sys.stdout.write("$hsrp$%s$%s\n" % (salt, h))

    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.pcap files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        pcap_parser(sys.argv[i])
