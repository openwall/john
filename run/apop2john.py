#!/usr/bin/env python

# This software is Copyright (c) 2021 Mark Silinio <mark.silinio-at-gmail.com>,
# and it is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Extract and format POP3 APOP challenge/responses for password cracking with JtR
# Usage: ./apop2john.py <pcap files>
#
# This script depends on Scapy (https://scapy.net)
# To install: pip install --user scapy

try:
    from scapy.all import *
except ImportError:
    print("scapy is missing, run 'pip install --user scapy' to install it!")
    exit(1)

from binascii import hexlify
from sys import argv
import os
import re

if len(argv) < 2:
    print('Usage: ./apop2john.py <pcap files>')
    exit(1)

filenames = argv[1:]

for filename in filenames:

    capture_file = rdpcap(filename)

    apop_salt = {}
    apop_hash = {}
    apop_user = {}

    for packet in capture_file:

        if not TCP in packet or (packet.sport != 110 and packet.dport != 110):
           continue

        pkt = bytes(packet[TCP].payload)

        if packet.sport == 110 and re.search(b'\+OK\ .*\ \<.+\>', pkt):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            res = re.search(b'\+OK\ .*\ (\<.+\>)', pkt)
            apop_salt[(src_ip, dst_ip)] = res.group(1).strip()
        elif packet.dport == 110 and re.search(b'APOP\ .+\ (.+)', pkt):
            src_ip = packet[IP].dst
            dst_ip = packet[IP].src
            res = re.search(b'APOP\ (.+)\ (.+)', pkt)
            apop_user[(src_ip, dst_ip)] = res.group(1).strip()
            apop_hash[(src_ip, dst_ip)] = res.group(2).strip()

    for ips_s, salt in apop_salt.items():
        for ips_h, ahash in apop_hash.items():
            for ips_u, user in apop_user.items():
                if (ips_s == ips_h == ips_u):
                    print('{user}:$dynamic_1017${hash}$HEX${salt}'.format(
                        user=user.decode('utf-8'),
                        hash=ahash.decode('utf-8'),
                        salt=hexlify(salt).decode('utf-8')
                    ))
