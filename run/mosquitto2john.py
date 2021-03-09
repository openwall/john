#!/usr/bin/python3

# This software is Copyright (c) 2021, Blackfell <github at blackfell.net>
# and it is hereby released to the general public under the following terms:

# Redistribution and use in source and binary forms, with or without
# modification, are permitted.

import re, argparse

from hashlib import pbkdf2_hmac, sha512
from base64 import b64encode, b64decode
from sys import exit, argv, stderr, stdout
from binascii import hexlify
from textwrap import dedent

def format_hmac(user, hash_data, hashcat):
    """Take hash data and return a valid hashcat hash for the
    PBKDF2-HMAC-SHA512 hash mode (12100) if hashcat is set to True
    else it will return a valid john format hash for the 
    JtR pbkdf2-hmac-sha512 hash format"""

    hcat_fmt_str = "sha512:{}:{}:{}"
    john_fmt_str = "{}:$pbkdf2-hmac-sha512${}.{}.{}"
    junk, morejunk, iterations, salt, digest = hash_data.split("$")
    
    if hashcat:
        #Everything just goes in base64 in this mode - nice & easy
        return hcat_fmt_str.format(iterations, salt, digest)

    # John format needs Hex conversions
    hex_digest = hexlify(b64decode(digest)).decode().upper()
    hex_salt = hexlify(b64decode(salt)).decode().upper()
    
    return john_fmt_str.format(user, iterations, hex_salt, hex_digest)

def format_sha512(user, hash_data, hashcat):
    """Take hash data and return a valid hashcat hash for the
    salted SHA512 hash mode (1710) if hashcat is set True
    else it will take a hash and return a valid john hash for the
    dynamic_82 John mode - sha512($password.$salt) """

    hcat_fmt_str = "{}:{}"
    john_fmt_str = "{}:$dynamic_82${}$HEX${}"
    junk, morejunk, salt, digest = hash_data.split("$")

    # Convert hash and salt to hex - needed for both formats now
    hex_digest = hexlify(b64decode(digest)).decode().upper()
    hex_salt = hexlify(b64decode(salt)).decode().upper()
    
    if hashcat:
        return hcat_fmt_str.format(hex_digest, hex_salt)
    
    return john_fmt_str.format(user, hex_digest, hex_salt)

def extract_hash(line, hmac_list, sha512_list, regex, hashcat):
    """Do basic parsing on a given passwd file line, if valid hash found
    format it accordingly for its type and once properly formatted,
    append to the corresponding hash list. Hash identification is managed 
    by a pretty basic regex passed from calling function."""

    # If there are no hashes on this line - return
    line = line.strip()
    if not line: return
    m = regex.match(line)
    if not m: return

    # We know mosquitto_passwd doesn't permit colons in the user field
    # but this isn't enforced in code, so quick check for that
    if m.group().count(":") > 1:
        stderr.write(
                "Invalid input. Try removing ':' from username:\n {}\n"
                .format(m.group()))
        return
    
    # Everything else in the hash is an int, $ or b64, so we can split on :
    user, hash_data = m.group().split(":")

    # Get any HMACs and put them in the HMAC list
    if hash_data.count("$") == 4:
        hmac_list.append(format_hmac(user, hash_data, hashcat))

    # Get any plain SHA512s and put them in the sha512 list
    elif hash_data.count("$") == 3:
        sha512_list.append(format_sha512(user, hash_data, hashcat))

    # Maybe there's a bad match some how?
    else:
        stderr.write("Error parsing hash - bad format:\n{}".format(
                hash_string))


def process_file(hashfile, hashcat):
    """Take a mosquitto_passwd file and convert to John/Hashcat compatible 
    format.Can handle both SHA512 and PBKDF2_HMAC_SHA512 output formats.
    Uses raw hex or base64 for hash and salt because 'bad' bytes are possible.

    Some versions of mosquitto_passwd can use mixed hash types, so we
    manage the two possible variants in simple lists, up until writing
    them out. 

    See https://github.com/eclipse/mosquitto/search?q=pw_sha512_pbkdf2 for
    info on HMAC format Hashes. An equivalent search can be made for SHA512.
    
    Hashes have been assumed to always be of the format:
        username:$[HASHNO][$ITER(HMAC ONLY)]$SALT$HASH
    Where salt and hash are always B64 encoded and usernames can be .+
    Any usernames with a colon are out of spec, but possible, so we handle
    them by alerting the user and advising manual management.
    """

    hmac_list = []
    sha512_list = []

    # This is probably close enough-ish to being a good regex for the job
    # Suggestions welcome 
    regex = re.compile(
            r".+:\$[6-7](\$[0-9]+)*\$[a-zA-Z0-9+/=]+\$[a-zA-Z0-9+/=]{80,90}")

    # Read matching hashes from the file, populate the hmac and sha512 lists
    with open(hashfile, 'r') as h:
        for line in h:
            # Extract any hash and format them while we're at it
            extract_hash(line, hmac_list, sha512_list, regex, hashcat)

    # Write to stdout if we have any hashes
    if len(sha512_list) > 0 or len(hmac_list) > 0:
        for h in sha512_list:
            stdout.write(h + "\n")
        for h in hmac_list:
            stdout.write(h + "\n")

    # The other case is that we found nothing
    else:
        stderr.write(
                "No hashes found. Is this a valid mosquitto_passwd file?\n")

def get_args():
    parser = argparse.ArgumentParser(
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=dedent('''\
                    Find more Information:
                        See doc/README-mosquitto.md for info/troubleshooting.
                        '''))
    parser.add_argument("-hc", "--hashcat", action = "store_true", \
            help = "Convert hashes to hashcat friendly formats.")
    parser.add_argument("passwd_file", nargs='*', \
            help = "Path to the source mosquitto_passwd file(s).")

    return parser.parse_args()

if __name__ == "__main__":
    
    #Get user options
    args = get_args()

    for passwd_file in args.passwd_file:
        # Quick check that our file is real before we crack on
        try:
            with open(passwd_file, 'r') as f:
                pass
        except:
            stderr.write("'{}' is not a readable file.\n".format(
                passwd_file))
            exit(1)
        # Do the conversion stuff
        process_file(passwd_file, args.hashcat)
