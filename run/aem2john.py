#!/usr/bin/env python

"""
This script is designed to transform Adobe Experience Manager (AEM) hash formats into the hash format used by the John
the Ripper (JtR) password-cracking tool. It primarily serves as a conversion utility, enabling testing AEM hashes with
tools that can handle JtR's hash format.

The script reads the original AEM hashes from input files, where each hash is expected to be either in the SHA-256 or
SHA-512 format and may optionally be prefixed with a username separated by a colon. The script determines its algorithm
for each hash, extracts the relevant components (salt, iterations, and the hash itself), and reassembles these
components into the JtR format. 

The JtR hash format is then printed to the standard output. In case of any unrecognized or malformed hashes in the
input, the script logs a warning and skips to the next hash. 

Usage:
    python aem2john.py <file1> [<file2> ...]

Each argument should be a file path pointing to a text file containing AEM hashes, one per line.

The script is compatible with both Python 2 and Python 3.

Originally authored by Dhiru Kholia <kholia at kth.se> in 2018 and released to the general public under a permissive
license allowing free redistribution and modification.

For more details about the original AEM hash generation algorithm, see the "generateHash" method in PasswordUtil.java
from the Apache Jackrabbit Oak project: https://github.com/apache/jackrabbit-oak.
"""

# Use the print function for Python 2 and 3 compatibility
from __future__ import print_function

import sys
import logging
from argparse import ArgumentParser

# Map algorithm tags to their respective algorithm numbers
ALGO_TAGS = {
	"{SHA-256}": 3,  # SHA-256
	"{SHA-512}": 4  # SHA-512
}

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Python 2 and 3 compatibility for file paths
if sys.version_info.major == 2:
	Path = str
else:
	from pathlib import Path


def split_user_and_hash(line):
	"""Split username and hash from the line."""
	if ':' in line:
		return line.split(':', 1)
	return '', line


def extract_algo_and_hash(line):
	"""Extract algorithm number and hash from the line."""
	for tag, algo in ALGO_TAGS.items():
		if tag in line:
			return algo, line[len(tag):]
	return None, line


def split_hash_parts(line):
	"""Split hash into salt, iterations, and actual hash."""
	parts = line.split('-')
	if len(parts) != 3:
		return None
	return tuple(parts)


def process_line(line):
	"""Process a single line from the input file."""
	line = line.rstrip()
	user, hash_with_algo = split_user_and_hash(line)
	algo, hash_without_algo = extract_algo_and_hash(hash_with_algo)

	if algo is None:
		logging.warning(f"Unknown hash format in line: {line[:8]}")
		return None

	hash_parts = split_hash_parts(hash_without_algo)
	if hash_parts is None:
		logging.warning(f"Invalid hash format in line: {line[:8]}")
		return None

	salt, iterations, hash_value = hash_parts

	return f"{user}:$sspr${algo}${iterations}${salt}${hash_value}"


def process_file(filename):
	"""Process the given input file."""
	try:
		with open(filename, "r") as f:
			for line in f:
				result = process_line(line)
				if result is not None:
					print(result)
	except IOError as e:
		logging.error(f"Error reading file {filename}: {str(e)}")
		sys.exit(1)


def main():
	parser = ArgumentParser(description="Process Adobe AEM hashes.")
	parser.add_argument("files", metavar="F", type=Path, nargs='+', help="Files with Adobe AEM hashes")
	args = parser.parse_args()

	for filename in args.files:
		process_file(filename)


if __name__ == "__main__":
	main()
