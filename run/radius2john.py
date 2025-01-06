#!/usr/bin/env python3

# This software is Copyright (c) 2024, k4amos <k4amos at proton.me>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

# This script is essentially a python version of radius2john.pl written by Didier ARENZANA.
# The previous version of radius2john.py was written by Maxime GOYETTE <maxgoyette0-at-gmail.com>

# ---

# Utility to bruteforce RADIUS shared-secret
# Usage: ./radius2john.py <pcap files>
#
# This script depends on Scapy (https://scapy.net)
# To install: pip install --user scapy

# ---

# Application of two  methods described in https://www.untruth.org/~josh/security/radius/radius-auth.html :
# "3.3 User-Password Attribute Based Shared Secret Attack"
# "3.1 Response Authenticator Based Shared Secret Attack"

# For attack 3.3 :
# We try authentications using a known password, and sniff the radius packets to a pcap file.
# This script reads access-request in the pcap file, and dumps the md5(RA+secret) and RA, in a john-friendly format.

# For attack 3.1:
# We don't need to try authentications. Just sniff the radius packets in a pcap file.
# This script reads the pcap file, matches radius responses with the corresponding all_requests,
# and dumps md5 and salt as needed.

import binascii
import sys
import argparse

try:
    import scapy.all as scapy
except ImportError:
    print(
        "Scapy seems to be missing, run 'pip install --user scapy' to install it",
        file=sys.stderr
    )
    sys.exit(1)


def read_file(args, filename):
    packets = scapy.rdpcap(filename)
    for packet in packets:
        process_packet(args, packet)


def process_packet(args, packet):
    if packet.haslayer(scapy.IP) and packet.haslayer(scapy.UDP):
        ip_layer = packet[scapy.IP]
        udp_layer = packet[scapy.UDP]

        if udp_layer.dport in [1812, 1813] or udp_layer.sport in [1812, 1813]:
            process_radius(args, ip_layer, bytes(udp_layer.payload))


def process_radius(args, ip, udpdata):
    radius_packet = scapy.Radius(udpdata)

    if radius_packet.code in [1, 4]:  # Access-Request, Accounting-Request

        if args['password'] is not None:

            user_name, user_hash = None, None

            for attr in radius_packet.attributes:
                if attr.name == "User-Name":
                    user_name = attr.value.decode("utf-8")

                if attr.name == "User-Password":
                    user_hash = attr.value

            if user_hash is not None:
                if args['login'] is None or user_name == args['login']:
                    dump_access_request(
                        args, ip.src, radius_packet.authenticator, user_hash
                    )

        all_requests[f"{ip.src}-{radius_packet.id}"] = radius_packet.authenticator

    elif radius_packet.code in [2, 11, 3, 5]:  # Access-Accept, Access-Challenge, Access-Reject, Accounting-Response
        key = f"{ip.dst}-{radius_packet.id}"
        if key in all_requests:
            dump_response(args, ip.dst, all_requests[key], radius_packet.authenticator, udpdata)


def dump_response(args, ip, req_ra, ra, udpdata):  # 3.1 attack
    if args["single"] and ip in dumped_ips:
        return

    salt = bytearray(udpdata)
    salt[4:20] = req_ra  # Replace Response Authenticator with the Request Authenticator

    response_type = "1009" if len(salt) <= 16 else "1017"
    print(
        f"{ip}:$dynamic_{response_type}${binascii.hexlify(ra).decode()}$HEX${binascii.hexlify(salt).decode('utf-8')}"
    )

    dumped_ips[ip] = "reply"


def dump_access_request(args, ip, ra, hashed):  # 3.3 attack
    if args["single"] and ip in dumped_ips and dumped_ips[ip] == "request":
        return

    xor_result = bytes(a ^ b for a, b in zip(hashed, args['password'][:16].encode('utf-8').ljust(16, b'\x00')))

    print(
        f"{ip}:$dynamic_1008${binascii.hexlify(xor_result).decode()}$HEX${binascii.hexlify(ra).decode('utf-8')}"
    )

    dumped_ips[ip] = "request"


if __name__ == "__main__":

    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,epilog=
    """
    ### Utility to bruteforce RADIUS shared-secret written by k4amos

    ---

    Application of two  methods described in https://www.untruth.org/~josh/security/radius/radius-auth.html :
    - "3.3 User-Password Attribute Based Shared Secret Attack"
    - "3.1 Response Authenticator Based Shared Secret Attack"

    # For attack 3.3 :
    We try authentications using a known password, and sniff the radius packets to a pcap file.
    This script reads access-request in the pcap file, and dumps the md5(RA+secret) and RA, in a john-friendly format.

    # For attack 3.1:
    We don't need to try authentications. Just sniff the radius packets in a pcap file.
    This script reads the pcap file, matches radius responses with the corresponding all_requests,
    and dumps md5 and salt as needed.
    """)

    parser.add_argument('file', type=str, nargs='+', help='Input PCAP files')
    parser.add_argument('--single', help='To get only one hash per client IP', action='store_true', default=False)
    parser.add_argument('-l', '--login', type=str, help='User login used for the 3.3 attack')
    parser.add_argument('-p', '--password', type=str, help='User password used for the 3.3 attack')

    parsed_args = parser.parse_args()
    args = vars(parsed_args)

    if args["login"] is not None and args["password"] is None:
        # Attack 3.3 can work without login verification (if there is only one client, there is no point), but cannot work without a password
        parser.error("You must specify the password used by the client for the '3.3 User-Password Attribute Based Shared Secret Attack'")

    all_requests = {}
    dumped_ips = {}

    for filename in args['file']:
        read_file(args, filename)
