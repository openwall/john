#!/usr/bin/env python3
# Converts Gitea name + salt + passwd + algo into John pbkdf2-sha256 format
# Dynamically handles iterations, trims to 32 bytes for John

"""
Converts Gitea (name, salt, passwd, passwd_hash_algo) into John the Ripper pbkdf2-sha256 format.

Expected input (e.g. from SQLite dump):
    <username>:<hashed salt>:<hashed password>:<password algorithm>

Output:
    username:$pbkdf2-sha256$<iterations>$<base64 salt>$<base64 hash>

Usage example:
    sqlite3 gitea.db 'SELECT name, salt, passwd, passwd_hash_algo FROM user;' | ./gitea2john.py > john.hashes

    echo 'isaac:73616c74313233:599abd158ef01da5e7282425bd05652119b4699cac7f0f13a4b325773f50bbfa8ceeaf96926f68add8bd544390e6abce421e:pbkdf2$50000$50' | ./gitea2john.py > john.hashes

    john --format=pbkdf2-hmac-sha256 john.hashes --wordlist=rockyou-10.txt
"""

import base64
import sys

PBKDF2_KEY_BYTES = 32  # John expects 32-byte derived key

def hex_to_b64(hex_str):
    return base64.b64encode(bytes.fromhex(hex_str)).decode('utf-8')

def parse_algo(algo_str):
    # Expected format: pbkdf2$50000$50
    try:
        parts = algo_str.strip().split('$')
        if parts[0] != 'pbkdf2':
            raise ValueError("Unsupported algo")
        iterations = parts[1]
        return iterations
    except Exception:
        return None

def convert_line(line):
    line = line.strip().replace('|', ':')
    parts = line.split(':')
    if len(parts) != 4:
        print(f"[-] Malformed line: {line}", file=sys.stderr)
        return None

    username, salt_hex, hash_hex, algo = parts

    iterations = parse_algo(algo)
    if not iterations:
        print(f"[-] Unsupported or invalid algo: {algo}", file=sys.stderr)
        return None

    try:
        salt_b64 = hex_to_b64(salt_hex)
        hash_bytes = bytes.fromhex(hash_hex)
        hash_b64 = base64.b64encode(hash_bytes[:PBKDF2_KEY_BYTES]).decode('utf-8')
    except ValueError:
        print(f"[-] Invalid hex in line: {line}", file=sys.stderr)
        return None

    return f"{username}:$pbkdf2-sha256${iterations}${salt_b64}${hash_b64}"

def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print(__doc__)
        return

    for line in sys.stdin:
        result = convert_line(line)
        if result:
            print(result)

if __name__ == "__main__":
    main()
