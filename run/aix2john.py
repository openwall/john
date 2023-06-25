#!/usr/bin/env python

"""
This script is designed to extract and display password hash information from an AIX /etc/security/passwd file. The
output is sent to stdout and can be used for auditing or analysis purposes. This script supports different password
hash types (smd5, ssha, and des), recognizing them automatically.

Usage:
	python aix2john.py -s -f /path/to/passwd

Arguments:
	-s : Use this option if "lpa_options = std_hash=true" is activated in the system configuration.
	-f : Specify the AIX shadow file filename to read (usually /etc/security/passwd)

Example /etc/security/passwd file:
	root:
			password = mrXXXXXXXXXX
			lastupdate = 1343960660
			flags =
	admin:
			password = oiXXXXXXXXXX
			lastupdate = 1339748349
			flags =

The script parses the file line by line, identifies the username and corresponding password hashes, and then prints
them to stdout in a formatted way. For 'smd5' password type, the printed format varies based on the 'is_standard' flag.

Note: Some of the functionality offered by this script may overlap with the unshadow program.

Compatible with both Python 2 and Python 3.

Please remember that the usage of this script should comply with all relevant laws and regulations, and it should not
be used for unauthorized access to password data.
"""

from __future__ import print_function
import argparse
import re
import sys
import logging

# Regular expression to parse and validate the username
USERNAME_RE = re.compile(r"^\s*(\w+)\s*:\s*$")
# Prefix for password line
PASSWORD_PREFIX = "password = "
# Mapping of password types to their expected lengths
PASSWORD_TYPES = {"smd5": 37, "ssha": 0, "des": 0}


def print_password(username, password, password_type, is_standard):
	"""Prints password line based on password type."""
	if password_type == "smd5":
		sys.stdout.write(
			"%s:$1$%s\n" % (username, password[6:])
			if is_standard
			else "%s:%s\n" % (username, password)
		)
	elif password_type == "ssha":
		tc, salt, h = password.split("$")
		sys.stdout.write("%s:%s$%s$%s\n" % (username, tc, salt, h))
	elif password_type == "des" and password != "*":
		sys.stdout.write("%s:%s\n" % (username, password))
	sys.stdout.flush()


def parse_line(line, username, is_standard):
	"""Parses a line from the password file."""
	match = USERNAME_RE.match(line)
	if match:
		return match.group(1)

	if line.strip().startswith(PASSWORD_PREFIX):
		password = line.partition("=")[2].strip()
		password_type = next(
			(pt for pt in PASSWORD_TYPES if password.startswith(pt)), None
		)
		if password_type and len(password) == PASSWORD_TYPES.get(password_type, 0):
			print_password(username, password, password_type, is_standard)


def process_file(filename, is_standard):
	"""Processes the password file."""
	username = "?"

	try:
		with open(filename, "r") as fd:
			for line in fd:
				result = parse_line(line, username, is_standard)
				if result is not None:
					username = result
	except IOError as e:
		logging.error(f"Failed to open file %s: %s" % (filename, str(e)))
		sys.exit(1)


def main():
	"""Main function to parse command line arguments and process the file."""
	parser = argparse.ArgumentParser()
	parser.add_argument(
		"-s",
		action="store_true",
		dest="is_standard",
		help='Use this option if "lpa_options = std_hash=true" is activated',
	)
	parser.add_argument(
		"-f",
		dest="filename",
		required=True,
		help="Specify the AIX shadow file filename to read (usually /etc/security/passwd)",
	)

	args = parser.parse_args()

	process_file(args.filename, args.is_standard)


if __name__ == "__main__":
	main()
