#!/usr/bin/env python

"""
This script is designed to extract and display password hash information from an AIX /etc/security/passwd file. The
output is sent to stdout and can be used for auditing or analysis. This script supports different password
hash types (des, md5, smd5, sha256, and sha512), recognizing them automatically.

Usage:
	python aix2john.py

Arguments:
	-f : Specify a file path. The default is /etc/security/passwd.
 	-a : Show all users, including those with locked or unset passwords.

Example /etc/security/passwd file with different hashes:
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

The script parses the file line by line, identifies the username and corresponding password hashes, and then prints
them to stdout in a formatted way.

Note: Some of the functionality offered by this script may overlap with the unshadow program.

Compatible with both Python 2 and Python 3.

Please remember that the usage of this script should comply with all relevant laws and regulations, and it should not
be used for unauthorized access to password data.
"""

from __future__ import print_function
import argparse
import sys
import logging
import io
import re

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(levelname)s: %(message)s')

# Define password types and associated lengths
PASSWORD_TYPES = {'des': 13, 'md5': 32, 'smd5': 46, 'sha256': 64, 'sha512': 128}
PASSWORD_UNDEFINED = 'Account is locked or no password is set'
PASSWORD_UNKNOWN = 'Password type unknown'

USERNAME_REGEX = re.compile(r"(.*):")
PASSWORD_REGEX = re.compile(r"password = (.*)")

def get_password_type(password):
	"""Returns the password type based on its length or an appropriate status."""
	if password is None or password == '*':
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

	return username, password

def process_password(username, password, print_all):
	"""Processes password and prints user data if applicable."""
	password_type = get_password_type(password)
	if password_type != PASSWORD_UNDEFINED or print_all:
		print('{}:{}:{}'.format(username, password, password_type))
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
			username, password = process_password(username, password, print_all)

def main():
	"""Main function, handles argument parsing and file processing."""
	parser = argparse.ArgumentParser(
		description="Parses a password file and returns users' password hash and their types. Use with caution.")
	parser.add_argument('-f', '--file', type=argparse.FileType('r'), default='/etc/security/passwd', 
		     help='Specify a file path. Default is /etc/security/passwd.')
	parser.add_argument('-a', '--all', action='store_true', 
		     help='Show all users, including those with locked or unset passwords.')
	args = parser.parse_args()

	try:
		process_file(args.file, args.all)
	except IOError as e:
		logging.error("Could not open file. Error message: %s", e)
		sys.exit(1)

if __name__ == '__main__':
	main()
