#!/usr/bin/python3

# This software is Copyright (c) 2018, Dhiru Kholia <kholia at kth.se> and it
# is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# All credit goes to "Android backup extractor" project by Nikolay Elenkov for
# making this work possible.
#
# Tested with Android 4.4.4, Android 6.0 and Android 8.0 running on Genymotion.
#
# Android backups can be created with the following command,
#
# adb backup -f freeotp-backup.ab -apk org.fedorahosted.freeotp  # valid for freeotp app

import os
import sys

PY3 = sys.version_info[0] == 3

if not PY3:
    reload(sys)
    sys.setdefaultencoding('utf8')

# https://github.com/nelenkov/android-backup-extractor
BACKUP_MANIFEST_VERSION = 1
BACKUP_FILE_HEADER_MAGIC = b"ANDROID BACKUP\n"
BACKUP_FILE_V1 = 1
BACKUP_FILE_V2 = 2
BACKUP_FILE_V3 = 3
BACKUP_FILE_V4 = 4
BACKUP_FILE_V5 = 5
ENCRYPTION_MECHANISM = b"AES/CBC/PKCS5Padding"
PBKDF2_HASH_ROUNDS = 10000
PBKDF2_KEY_SIZE = 256  # bits
MASTER_KEY_SIZE = 256  # bits
PBKDF2_SALT_SIZE = 512  # bits
ENCRYPTION_ALGORITHM_NAME = b"AES-256"


def process_file(filename):
    """
    Parser for Android Backup .ab files
    """
    with open(filename, "rb") as f:
        magic = f.readline()

        # Untested hack for "Xiaomi-MIUI backup"
        while magic != BACKUP_FILE_HEADER_MAGIC and magic:
            magic = f.readline()
        if magic != BACKUP_FILE_HEADER_MAGIC:
            sys.stderr.write("[!] Magic missing from file, is this an Android Backup?\n")
            return

        try:
            version = int(f.readline())
        except ValueError:
            return
        if version < BACKUP_FILE_V1 or version > BACKUP_FILE_V5:
            sys.stderr.write("[!] Unsupported backup version, is this an Android Backup?\n")
            return

        try:
            is_compressed = int(f.readline())
        except ValueError:
            sys.stderr.write("[!] Error reading compression flag, is this an Android Backup?\n")
            return

        encryption_algorithm = f.readline().strip()

        if encryption_algorithm != ENCRYPTION_ALGORITHM_NAME:
            sys.stderr.write(
                "[!] Unsupported encryption algorithm (%s) found, is this an Android Backup?\n" % encryption_algorithm)
            return

        user_salt = f.readline().strip().lower()

        ck_salt = f.readline().strip().lower()

        try:
            rounds = int(f.readline())
        except ValueError:
            sys.stderr.write("[!] Error reading rounds value, is this an Android Backup?\n")
            return

        user_iv = f.readline().strip().lower()
        masterkey_blob = f.readline().strip().lower()

        if PY3:
            user_salt = str(user_salt, 'ascii')
            ck_salt = str(ck_salt, 'ascii')
            user_iv = str(user_iv, 'ascii')
            masterkey_blob = str(masterkey_blob, 'ascii')

        cipher = 0  # AES-256
        sys.stdout.write("%s:$ab$%d*%d*%d*%s*%s*%s*%s\n" %
                         (os.path.basename(filename), version, cipher, rounds, user_salt, ck_salt, user_iv,
                          masterkey_blob))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [Android Backup .ab file(s)]\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
