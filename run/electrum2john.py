#!/usr/bin/env python

# This software is Copyright (c) 2017, Dhiru Kholia <dhiru.kholia at gmail.com>
# and it is hereby released under GPL v2 license.
#
# Major parts are borrowed from the "btcrecover" program which is,
# Copyright (C) 2014-2016 Christopher Gurnee and under GPL v2.
#
# See https://github.com/gurnec/btcrecover for details.
#
# References,
#
# https://github.com/gurnec/btcrecover/blob/master/btcrecover/btcrpass.py
# https://github.com/spesmilo/electrum (see 1.9.8 version)

import os
import sys
# import traceback
import base64
import binascii
import itertools
import optparse

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


def process_electrum28_wallets(bname, data, options):
    version = 4  # hack
    MIN_LEN = 37 + 32 + 32  # header + ciphertext + trailer
    if len(data) < MIN_LEN * 4 / 3:
        sys.stderr.write("%s: Electrum 2.8+ wallet is too small to parse!\n" % bname)
        return
    data = base64.b64decode(data)
    ephemeral_pubkey = data[4:37]  # compressed representation
    # ciphertext = data[37:-32]
    mac = data[-32:]
    all_but_mac = data[:-32]
    if len(all_but_mac) > 16384 or options.truncate:
        sys.stderr.write("Forcing generation of truncated hash, this is not tested well!\n")
        all_but_mac = data[37:][:1024]   # skip over the 4-byte magic & 33-byte pubkey
        version = 5  # hack
    ephemeral_pubkey = binascii.hexlify(ephemeral_pubkey).decode("ascii")
    mac = binascii.hexlify(mac).decode("ascii")
    all_but_mac = binascii.hexlify(all_but_mac).decode("ascii")
    sys.stdout.write("%s:$electrum$%d*%s*%s*%s\n" % (bname, version, ephemeral_pubkey, all_but_mac, mac))


def process_file(filename, options):
    bname = os.path.basename(filename)
    try:
        f = open(filename, "rb")
        data = f.read()
    except IOError:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return

    # detect Electrum 2.7+ encrypted wallets
    try:
        if base64.b64decode(data).startswith('BIE1'):
            # sys.stderr.write("%s: Encrypted Electrum 2.8+ wallets are not supported yet!\n" % bname)
            process_electrum28_wallets(bname, data, options)
            return
    except:
        # traceback.print_exc()
        pass

    try:
        data = data.decode("utf-8")
    except:
        e = sys.exc_info()[1]
        sys.stderr.write("%s\n" % str(e))
        return -13

    version = None
    try:
        wallet = json.loads(data)
    except:
        try:
            from ast import literal_eval  # hack for Electrum 1.x wallets
            wallet = literal_eval(data)
            version = 1
        except:
            sys.stderr.write("%s: Unable to parse the wallet file!\n" % bname)
            # traceback.print_exc()
            return

    # This check applies for both Electrum 2.x and 1.x
    if "use_encryption" in wallet and wallet.get("use_encryption") == False:
        sys.stderr.write("%s: Electrum wallet is not encrypted!\n" % bname)
        return

    # Is this an upgraded wallet, from 1.x to 2.y (y<7)?
    if "wallet_type" in wallet and wallet["wallet_type"] == "old":
        sys.stderr.write("%s: Upgraded wallet found!\n" % bname)
        version = 1  # hack

    if version == 1:
        try:
            seed_version = wallet["seed_version"]
            seed_data = base64.b64decode(wallet["seed"])
            if len(seed_data) != 64:
                sys.stderr.write("%s: Weird seed length value '%d' found!\n" % (bname, len(seed_data)))
                return
            if seed_version == 4:
                iv = seed_data[:16]
                encrypted_data = seed_data[16:32]
                iv = binascii.hexlify(iv).decode("ascii")
                encrypted_data = binascii.hexlify(encrypted_data).decode("ascii")
                sys.stdout.write("%s:$electrum$1*%s*%s\n" % (bname, iv, encrypted_data))
                return
            else:
                sys.stderr.write("%s: Unknown seed_version value '%d' found!\n" % (bname, seed_version))
                return
        except:
            sys.stderr.write("%s: Problem in parsing seed value!\n" % (bname, seed_version))
            return

    # not version 1 wallet
    wallet_type = wallet.get("wallet_type")
    if not wallet_type:
        sys.stderr.write("%s: Unrecognized wallet format!\n" % (bname))
        return
    if wallet.get("seed_version") not in (11, 12, 13) and wallet_type != "imported":  # all 2.x versions as of Oct 2016
        sys.stderr.write("%s: Unsupported Electrum2 seed version '%d' found!\n" % (bname, wallet.get("seed_version")))
        return
    xprv = None
    version = 2  # hack
    while True:  # "loops" exactly once; only here so we've something to break out of
        # Electrum 2.7+ standard wallets have a keystore
        keystore = wallet.get("keystore")
        if keystore:
            keystore_type = keystore.get("type", "(not found)")

            # Wallets originally created by an Electrum 2.x version
            if keystore_type == "bip32":
                xprv = keystore.get("xprv")
                if xprv:
                    break

            # Former Electrum 1.x wallet after conversion to Electrum 2.7+ standard-wallet format
            elif keystore_type == "old":
                seed_data = keystore.get("seed")
                if seed_data:
                    # Construct and return a WalletElectrum1 object
                    seed_data = base64.b64decode(seed_data)
                    if len(seed_data) != 64:
                        raise RuntimeError("Electrum1 encrypted seed plus iv is not 64 bytes long")
                    iv = seed_data[:16]  # only need the 16-byte IV plus
                    encrypted_data = seed_data[16:32]  # the first 16-byte encrypted block of the seed
                    version = 1  # hack
                    break

            # Imported loose private keys
            elif keystore_type == "imported":
                for privkey in keystore["keypairs"].values():
                    if privkey:
                        privkey = base64.b64decode(privkey)
                        if len(privkey) != 80:
                            raise RuntimeError("Electrum2 private key plus iv is not 80 bytes long")
                        iv = privkey[-32:-16]  # only need the 16-byte IV plus
                        encrypted_data = privkey[-16:]  # the last 16-byte encrypted block of the key
                        version = 3  # dirty hack!
                        break
                if version == 3:  # another dirty hack, break out of outer loop
                    break
            else:
                sys.stderr.write("%s: found unsupported keystore type!\n" % (bname))

        # Electrum 2.7+ multisig or 2fa wallet
        for i in itertools.count(1):
            x = wallet.get("x{}/".format(i))
            if not x:
                break
            x_type = x.get("type", "(not found)")
            if x_type == "bip32":
                xprv = x.get("xprv")
                if xprv:
                    break
            else:
                sys.stderr.write("%s: found unsupported keystore type!\n" % (bname))
        if xprv:
            break

        # Electrum 2.0 - 2.6.4 wallet with imported loose private keys
        if wallet_type == "imported":
            for imported in wallet["accounts"]["/x"]["imported"].values():
                privkey = imported[1] if len(imported) >= 2 else None
                if privkey:
                    privkey = base64.b64decode(privkey)
                    if len(privkey) != 80:
                        raise RuntimeError("Electrum2 private key plus iv is not 80 bytes long")
                    iv = privkey[-32:-16]  # only need the 16-byte IV plus
                    encrypted_data = privkey[-16:]  # the last 16-byte encrypted block of the key
                    version = 3  # dirty hack
                    break
            if version == 3:  # another dirty hack, break out of outer loop
                break

        # Electrum 2.0 - 2.6.4 wallet (of any other wallet type)
        else:
            mpks = wallet.get("master_private_keys")
            if mpks:
                xprv = mpks.values()[0]
                break

        raise RuntimeError("No master private keys or seeds found in Electrum2 wallet")

    if xprv:
        xprv_data = base64.b64decode(xprv)
        if len(xprv_data) != 128:
            raise RuntimeError("Unexpected Electrum2 encrypted master private key length")
        iv = xprv_data[:16]  # only need the 16-byte IV plus
        encrypted_data = xprv_data[16:32]  # the first 16-byte encrypted block of a master privkey

    iv = binascii.hexlify(iv).decode("ascii")
    encrypted_data = binascii.hexlify(encrypted_data).decode("ascii")

    sys.stdout.write("%s:$electrum$%d*%s*%s\n" % (bname, version, iv, encrypted_data))
    f.close()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [Ethereum Wallet files (default_wallet)]\n" % sys.argv[0])
        sys.exit(-1)

    parser = optparse.OptionParser()
    parser.add_option('-t', action="store_true", dest="truncate", help="force generation of truncated hashes")
    options, remainder = parser.parse_args()

    for j in range(0, len(remainder)):
        process_file(remainder[j], options)
