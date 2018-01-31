#!/usr/bin/env python

# This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>
# and it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# Special thanks goes to @Chick3nman for coming up with the output hash format.
#
# References,
#
# https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition
#
# https://github.com/ethereum/go-ethereum/wiki/Passphrase-protected-key-store-spec,
# v1 wallets are not supported (yet)

import os
import sys
import traceback

try:
    import json
    assert json
except ImportError:
    try:
        sys.path.append(".")
        import simplejson as json
    except ImportError:
        sys.stderr.write("Please install json / simplejson module which is currently not installed.\n")
        sys.exit(-1)


def process_presale_wallet(filename, data):
    try:
        bkp = data["bkp"]
    except KeyError:
        sys.stdout.write("%s: presale wallet is missing 'bkp' field, this is unsupported!\n" % filename)
        return

    try:
        encseed = data["encseed"]
        ethaddr = data["ethaddr"]
    except KeyError:
        sys.stdout.write("%s: presale wallet is missing necessary fields!\n" % filename)
        return

    # 16 bytes of bkp should be enough
    sys.stdout.write("%s:$ethereum$w*%s*%s*%s\n" %
                     (os.path.basename(filename), encseed, ethaddr, bkp[:32]))


def process_file(filename):
    try:
        f = open(filename, "rb")
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    data = f.read().decode("utf-8")

    sys.stderr.write("WARNING: Upon successful password recovery, this hash format may expose your PRIVATE KEY. Do not share extracted hashes with any untrusted parties!\n")

    try:
        data = json.loads(data)
        try:
            crypto = data["crypto"]
        except KeyError:
            try:
                crypto = data["Crypto"]
            except:  # hack for presale wallet
                process_presale_wallet(filename, data)
                return
        cipher = crypto["cipher"]
        if cipher != "aes-128-ctr":
            sys.stdout.write("%s: unexpected cipher '%s' found\n" % (filename, cipher))
            return -2
        kdf = crypto["kdf"]
        ciphertext = crypto["ciphertext"]
        mac = crypto["mac"]
        if kdf == "scrypt":
            kdfparams = crypto["kdfparams"]
            n = kdfparams["n"]
            r = kdfparams["r"]
            p = kdfparams["p"]
            salt = kdfparams["salt"]
            sys.stdout.write("%s:$ethereum$s*%s*%s*%s*%s*%s*%s\n" %
                             (os.path.basename(filename), n, r, p, salt,
                              ciphertext, mac))
        elif kdf == "pbkdf2":
            kdfparams = crypto["kdfparams"]
            n = kdfparams["c"]
            prf = kdfparams["prf"]
            if prf != 'hmac-sha256':
                sys.stdout.write("%s: unexpected prf '%s' found\n" % (filename, prf))
                return
            salt = kdfparams["salt"]
            sys.stdout.write("%s:$ethereum$p*%s*%s*%s*%s\n" %
                             (os.path.basename(filename), n, salt,
                              ciphertext, mac))
        else:
            assert 0
    except:
        sys.stdout.write("%s: json parsing failed\n" % filename)
        traceback.print_exc()
        return -1

    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [Ethereum Wallet files (Geth/Mist/MyEtherWallet)]\n" % sys.argv[0])
        sys.exit(-1)

    for j in range(1, len(sys.argv)):
        process_file(sys.argv[j])
