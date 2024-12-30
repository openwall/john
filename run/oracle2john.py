#!/usr/bin/env python3

# This software is Copyright (c) 2024, k4amos <k4amos at proton.me>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

# ---

# Utility to obtain a hash of ORACLE authentication (o5logon) that can be cracked with John
# This code does not support Oracle authentication with the key derivation function PBKDF2
#
# Usage: ./oracle2john.py <pcap files>
#
# This script depends on Scapy (https://scapy.net)
# To install: pip install --user scapy

import sys
import argparse
import re

try:
    import scapy.all as scapy
except ImportError:
    print(
        "\033[91m[Error] Scapy seems to be missing, run 'pip install --user scapy' to install it\033[0m",
        file=sys.stderr,
    )
    sys.exit(1)


def read_file(args, filename):
    """
    Reads a PCAP file and extracts relevant Oracle authentication data (o5logon).
    """
    auth_data = {
        "server_auth_sesskey": None,
        "auth_vfr_data": None,
        "auth_password": None,
        "client_auth_sesskey": None,
    }

    packets = scapy.rdpcap(filename)
    for packet in packets:
        auth_data = process_packet(args, packet, auth_data)

    if None not in list(auth_data.values()):
        # Format of the hash : $o5logon$ <server's AUTH_SESSKEY> * <AUTH_VFR_DATA> * <AUTH_PASSWORD> * <client's AUTH_SESSKEY>

        print(
            f'$o5logon${auth_data["server_auth_sesskey"]}*{auth_data["auth_vfr_data"]}*{auth_data["auth_password"]}*{auth_data["client_auth_sesskey"]}'
        )

    else:
        # Format of the hash : $o5logon$ <server's AUTH_SESSKEY> * <AUTH_VFR_DATA>
        # This format can be cracked only if your Oracle version is affected by CVE-2012-3137

        print(
            f'$o5logon${auth_data["server_auth_sesskey"]}*{auth_data["auth_vfr_data"]}'
        )


def select_hexa(raw_string):
    """
    Extracts the first valid hexadecimal string from the raw data.
    """
    match_hexa = re.search(
        "([A-Fa-f0-9]+)", raw_string.decode("ascii", errors="ignore").replace(" ", "")
    )
    if match_hexa:
        return match_hexa.group(1)
    return None


def process_packet(args, packet, auth_data):
    """
    Processes a packet and updates the auth_data dictionary with the extracted values.
    """
    raw_data = bytes(packet)

    server_auth_sesskey_match = re.search(
        rb"AUTH_SESSKEY([\s\S]+?)AUTH_VFR_DATA", raw_data
    )
    if server_auth_sesskey_match:
        auth_data["server_auth_sesskey"] = select_hexa(
            server_auth_sesskey_match.group(1)
        )

    auth_vfr_data_match = re.search(
        rb"AUTH_VFR_DATA([\s\S]+?)(AUTH_GLOBALLY_UNIQUE_DBID|$)", raw_data
    )
    if auth_vfr_data_match:
        auth_data["auth_vfr_data"] = select_hexa(auth_vfr_data_match.group(1))

    auth_password_match = re.search(rb"AUTH_PASSWORD([\s\S]+?)AUTH_RTT", raw_data)
    if auth_password_match:
        auth_data["auth_password"] = select_hexa(auth_password_match.group(1))

    client_auth_sesskey_match = re.search(
        rb"AUTH_SESSKEY([\s\S]+?)AUTH_PASSWORD", raw_data
    )
    if client_auth_sesskey_match:
        auth_data["client_auth_sesskey"] = select_hexa(
            client_auth_sesskey_match.group(1)
        )

    return auth_data


if __name__ == "__main__":

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
    ### Utility to obtain a hash of ORACLE authentication (o5logon) that can be cracked with John
        This code does not support Oracle authentication with the key derivation function PBKDF2
        Written by k4amos

    Usage: ./oracle2john.py <pcap files>
    """,
    )

    parser.add_argument("file", type=str, nargs="+")

    parsed_args = parser.parse_args()
    args = vars(parsed_args)

    for filename in args["file"]:
        read_file(args, filename)
