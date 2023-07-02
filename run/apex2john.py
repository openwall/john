#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
A script for processing Oracle APEX password hashes in a specific format.

Each line in the file should have three comma-separated values: username,
apexhash, and sgid. Each of these values are stripped of leading and trailing
white space. The script will write to stdout in the format
"$dynamic_1$<apexhash><sgid><username>".

Lines that do not adhere to this format will be skipped, and an error message
indicating the line number and content will be written to stderr.

Usage:
    python apex2john.py file1 [file2 ...]

This script can take one or more file paths as command-line arguments.
If a file is not found, an error message will be written to stderr.

This script is compatible with both Python 2 and Python 3.
"""

from __future__ import print_function

import csv
import os
import sys
from argparse import ArgumentParser


class HashFileProcessor:
    """
    Class for processing hash files. It includes methods for reading the file,
    validating the content, and printing the formatted output.
    """

    def __init__(self, filepath):
        """
        Initialize HashFileProcessor with the file path.
        """
        self.filepath = filepath

    def read_file(self):
        """
        This method reads a file and yields its lines
        """
        try:
            with open(self.filepath, 'r') as file:
                reader = csv.reader(file, delimiter=',')
                for line in reader:
                    yield line
        except IOError as e:
            sys.stderr.write(
                "Failed to read file {}: {}\n".format(self.filepath, e))
            return

    def process_file(self):
        """
        Processes a file line by line.
        
        Prints an error message and skips lines that don't pass validation,
        and prints the formatted output for valid lines.
        """
        for i, line in enumerate(self.read_file() or [], start=1):
            if self.validate_line(line):
                try:
                    username, apexhash, sgid = map(str.strip, line)
                    print(self.format_line(username, apexhash, sgid), end='')
                except ValueError as e:
                    sys.stderr.write(
                        "Failed to process line {} ('{}'): {}\n"
                        .format(i, ','.join(line), e))
            else:
                sys.stderr.write(
                    "Invalid line format at line {}: {}\n"
                    .format(i, ','.join(line)))

    @staticmethod
    def validate_line(line):
        """
        Validates the line structure.
        """
        if len(line) != 3:
            return False
        username, apexhash, sgid = map(str.strip, line)
        return all([username, apexhash, sgid])

    @staticmethod
    def format_line(username, apexhash, sgid):
        """
        This method prints the line in the required format.
        """
        return "$dynamic_1${}${}\n".format(apexhash, sgid + username)


def parse_args():
    """
    Handles command line arguments.
    """
    parser = ArgumentParser(description="A script to process hash files.")
    parser.add_argument(
        'files',
        metavar='F',
        type=str,
        nargs='+',
        help="One or more files to be processed."
    )
    return parser.parse_args()


def main():
    """
    The main driver function.
    """
    args = parse_args()
    for filepath in args.files:
        if not os.path.isfile(filepath):
            sys.stderr.write("File not found: {}\n".format(filepath))
            continue
        processor = HashFileProcessor(filepath)
        processor.process_file()


if __name__ == "__main__":
    main()
