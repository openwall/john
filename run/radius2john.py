#!/usr/bin/python3

# This software is Copyright (c) 2019 Maxime GOYETTE <maxgoyette0-at-gmail.com>,
# and it is hereby released to the general public under the following terms:
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Utility to bruteforce RADIUS shared-secret
# Usage: ./radius2john.py <pcap files>
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

if len(argv) < 2:
    print('Usage: ./radius2john.py <pcap files>')
    exit(1)

filenames = argv[1:]

for filename in filenames:

    capture_file = rdpcap(filename)

    accounting_request_packets = {}
    accounting_response_packets = {}

    for packet in capture_file:

        if Radius in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst

            if packet[Radius].code == 4 and not (src_ip, dst_ip) in accounting_request_packets:
                accounting_request_packets[(src_ip, dst_ip)] = packet
            elif packet[Radius].code == 5 and not (dst_ip, src_ip) in accounting_response_packets:
                accounting_response_packets[(dst_ip, src_ip)] = packet

    for ips, packet in accounting_response_packets.items():
        if ips in accounting_request_packets:
            code = hex(packet[Radius].code)[2:].zfill(2)
            identifier = hex(packet[Radius].id)[2:].zfill(2)
            length = hex(packet[Radius].len)[2:].zfill(4)
            authenticator = hexlify(accounting_request_packets[ips][Radius].authenticator).decode('utf-8')

            salt = code + identifier + length + authenticator

            hash_content = hexlify(packet[Radius].authenticator).decode('utf-8')
            hash_type = 1009 if len(salt) <= 16 else 1017

            file_path = os.path.abspath(filename)

            print('{ip}({file_path}):$dynamic_{type}${hash}$HEX${salt}'.format(
                file_path=file_path,
                ip=ips[1],
                type=hash_type,
                hash=hash_content,
                salt=salt
            ))
