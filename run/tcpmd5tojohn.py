#!/usr/bin/env python

# Cracker for "TCP MD5 Signatures", http://www.ietf.org/rfc/rfc2385.txt
# Written by Dhiru Kholia <dhiru at openwall.com> in October 2013

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
                salt = salt + raw_tcp_data[header_length:header_length +
                        data_length]
                # print len(salt)

                sys.stdout.write("$tcpmd5$%s$%s\n" % (salt.encode("hex"),
                        opt_data.encode("hex")))

    f.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [.pcap files]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        pcap_parser(sys.argv[i])
