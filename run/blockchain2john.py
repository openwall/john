#!/usr/bin/env python

import sys
import base64
import binascii
import argparse
import json
import traceback

if __name__ == '__main__':

    parser = argparse.ArgumentParser(
        prog=sys.argv[0],
        usage="%(prog)s [blockchain wallet files]")

    parser.add_argument('--json', action='store_true', default=False,
                        dest='json', help='is the wallet using v2 format?')
    parser.add_argument('--base64', action='store_true', default=False,
                        dest='base64', help='does the wallet contain only a base64 string?')

    args, unknown = parser.parse_known_args()

    if len(sys.argv) < 2:
        parser.print_help()
        sys.exit(-1)

    for filename in unknown:
        with open(filename, "rb") as f:
            data = f.read()
            # try to detect the wallet format version, https://blockchain.info/wallet/wallet-format
            if b"guid" in data and args.json:  # v1
                sys.stderr.write("My Wallet Version 1 seems to be used, remove --json option!\n")
                continue
            if b"pbkdf2_iterations" in data and not args.json:  # v2/v3
                sys.stderr.write("My Wallet Version 2 or 3 seems to be used, adding --json option is required!\n")
                continue

            if args.json:
                # hack for version 2.0 and 3.0 wallets
                try:
                    decoded_data = json.loads(data.decode("utf-8"))
                    if "version" in decoded_data and (str(decoded_data["version"]) == "2" or str(decoded_data["version"]) == "3"):
                        payload = base64.b64decode(decoded_data["payload"])
                        iterations = decoded_data["pbkdf2_iterations"]
                        print("%s:$blockchain$v2$%s$%s$%s" % (
                            filename, iterations, len(payload),
                            binascii.hexlify(payload).decode(("ascii"))))
                except:
                    traceback.print_exc()
                    pass

            if args.base64:
                # handle blockchain version 1 wallet format files which contain
                # only a base64 encoded string
                try:
                    ddata = base64.decodestring(data)
                    print("%s:$blockchain$%s$%s" % (
                        filename, len(ddata),
                        binascii.hexlify(ddata).decode("ascii")))
                except:
                    pass

            if not (args.json or args.base64):  # version 1 wallet format
                print("%s:$blockchain$%s$%s" % (
                    filename, len(data),
                    binascii.hexlify(data).decode("ascii")))
