#!/usr/bin/env python

"""
This Python script is designed to parse and extract user credentials data from
an IBM AIX /etc/security/passwd file. The credentials consist of the username
and the corresponding password hashes.

The parser handles different password hash types including DES, MD5, SMD5,
SHA256, and SHA512, with automatic recognition based on the hash length. In
addition to the normal operation, the script provides an option to list all
users, even those with locked or unset passwords.

Features:
- Automatic password hash type identification.
- Option to display all users, regardless of account status.
- Error handling for file opening exceptions.

Usage:
The script can be used from the command line with the following options:

    python aix2john.py -f [filepath] : To specify a file path for processing.
    The default is /etc/security/passwd.
    
    python aix2john.py -a : To include all users, including those with locked
    or unset passwords.

The script prints the username, the password hash, and the password hash type
for each user in a formatted way.

Example /etc/security/passwd file:

        guest:
        password = *

        paul:
        password = YFf0/OmVZz6tQ
        lastupdate = 1026394230
        flags =

        jonas:
        password = 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
        lastupdate = 1026394230
        flags =

Compatibility:
The script is compatible with both Python 2 and Python 3 environments.

Security and Compliance:
This script handles sensitive data and should be used with appropriate caution.
Ensure your usage of this script complies with all relevant laws and
regulations, and refrain from using it for unauthorized access to password
data.
"""

from __future__ import print_function
import argparse
import sys
import logging
import io
import re

# Configure logging
logging.basicConfig(level=logging.ERROR, format="%(levelname)s: %(message)s")

# Define password types and associated lengths
PASSWORD_TYPES = {
    "des": 13,
    "md5": 32,
    "smd5": 46,
    "sha256": 64,
    "sha512": 128
}
PASSWORD_UNDEFINED = "Account is locked or no password is set"
PASSWORD_UNKNOWN = "Password hash type unknown"

USERNAME_REGEX = re.compile(r"(.*):")
PASSWORD_REGEX = re.compile(r"password = (.*)")


def get_password_type(password):
    """
    Returns the password hash type based on its length or an appropriate
    status.
    """
    if password is None or password == "*":
        return PASSWORD_UNDEFINED
    for pt, length in PASSWORD_TYPES.items():
        if len(password) == length:
            return pt
    return PASSWORD_UNKNOWN


def process_line(line):
    """Processes a line from the input file."""
    line = line.strip()
    if not line:
        return None, None

    # Parsing username and password from line
    username_match = USERNAME_REGEX.match(line)
    password_match = PASSWORD_REGEX.match(line)

    username = username_match.group(1) if username_match else None
    password = password_match.group(1) if password_match else None

    # Check the length of the username
    if username and len(username) > 256:
        raise ValueError(
            "Username exceeds the IBM AIX max_logname limit of 256 characters."
        )

    return username, password


def process_password(username, password, print_all):
    """
    Processes password hashes and prints user data if applicable.
    """
    password_type = get_password_type(password)
    if password_type != PASSWORD_UNDEFINED or print_all:
        print("{}:{}:{}".format(username, password, password_type))
        return None, None
    return username, password


def process_file(file, print_all):
    """Processes an opened file line by line."""
    username, password = None, None
    for line in file:
        new_username, new_password = process_line(line)

        username = new_username if new_username else username
        password = new_password if new_password else password

        if username and password:
            username, password = process_password(
                username, password, print_all)


def main():
    """
    Main function, handles argument parsing and file processing.
    """
    parser = argparse.ArgumentParser(
        description="This script parses a password file and returns users' "
                    "password hashes and their types. Use with caution as "
                    "handling passwords might expose sensitive information."
    )
    parser.add_argument(
        "-f",
        "--file",
        type=argparse.FileType("r"),
        default="/etc/security/passwd",
        help="Specify a file path. Default is /etc/security/passwd.",
    )
    parser.add_argument(
        "-a",
        "--all",
        action="store_true",
        help="Show all users, including those with locked or unset passwords."
    )
    args = parser.parse_args()

    try:
        process_file(args.file, args.all)
    except IOError as e:
        logging.error("Could not open file. Error message: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
