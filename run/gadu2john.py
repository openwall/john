#!/usr/bin/env python
"""
This software is Copyright (c) 2013 Lukas Odzioba <ukasz at openwall dot net>
and it is hereby released to the general public under the following terms:

Redistribution and use in source and binary forms, with or without
modification, are permitted.

output format:
gadu-gadu number:$dynamic_24$sha1(pass.salt)$HEX$salt$

We could use user status description and client language in GECOS field, but
this is not currently supported.

"GG32" "hash function" used by ancient clients is not supported.

Tested on:

ekg: 10.1.0.11070
kadu 0.12.3
pidgin 2.110.6

"""

import sys
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

try:
    from scapy.all import TCP, rdpcap
except ImportError:
    sys.stderr.write("Please install scapy, " \
            "http://www.secdev.org/projects/scapy\n")
    sys.exit(-1)

def endian(s):
    ret = ""
    for i in range(0, len(s), 2):
        ret += s[i + 1] + s[i]
    return ret

def process_hash(uid, nonce, sha1):
    if len(nonce) == 0:
        return
    uid = int(endian(uid[::-1]), 16)
    print "%s:$dynamic_24$%s$HEX$%s" % (uid, sha1, nonce)

def process_file(pcapfile):
    try:
        packets = rdpcap(pcapfile)
    except:  # XXX be specific
        sys.stderr.write("%s is not a .pcap file\n" % pcapfile)
        return

    ports = [8074]
    nonce = ""
    for pkt in packets:
        if TCP in pkt and (pkt[TCP].dport in ports or pkt[TCP].sport in ports):
            payload = str(pkt[TCP].payload).encode('hex')
            if payload[:8] == '01000000':  # GG_WELCOME
                nonce = payload[16:]
            if payload[:8] == '31000000':  # GG_LOGIN
                hashtype = payload[28:30]
                if hashtype == "02":
                    uid = payload[16:24]
                    sha1 = payload[30:70]
                    process_hash(uid, nonce, sha1)

if __name__ == '__main__':
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <.pcap files>\n" % sys.argv[0])
        sys.exit(-1)

    for j in range(1, len(sys.argv)):
        process_file(sys.argv[j])
