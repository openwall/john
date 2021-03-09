#!/usr/bin/python3

# Based on the Kerberoast script from Tim Medin to extract the Kerberos tickets
# from a kirbi file (https://github.com/nidem/kerberoast).

# Modification to parse them into the JtR-format by Michael Kramer (SySS GmbH)
# Copyright [2015] [Tim Medin, Michael Kramer]
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License

from pyasn1.codec.ber import decoder
import sys

if __name__ == '__main__':
    m = "exported mimikatz kerberos tickets / extracttgsrepfrompcap.py output"

    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <%s>\n" % (sys.argv[0], m))
        sys.exit(-1)

    for f in sys.argv[1:]:
        with open(f, 'rb') as fd:
            data = fd.read()
            if data[0] == '\x76':  # process .kirbi
                # rem dump
                etype = str(decoder.decode(data)[0][2][0][3][0])
                if etype != "23":
                    sys.stderr.write("Unsupported etype %s seen! Please report this to us.\n" % etype)
                et = str(decoder.decode(data)[0][2][0][3][2])
                sys.stdout.write("$krb5tgs$unknown:$krb5tgs$%s$" % etype + et[:16].encode("hex") +
                                 "$" + et[16:].encode("hex") + "\n")
            elif data[:2] == '6d':  # extracttgsrepfrompcap.py output
                for ticket in data.strip().split('\n'):
                    etype = str(decoder.decode(ticket.decode('hex'))[0][4][3][0])
                    if etype != "23":
                        sys.stderr.write("Unsupported etype %s found. Such hashes can't be cracked it seems.\n" % etype)
                    et = str(decoder.decode(ticket.decode('hex'))[0][4][3][2])
                    sys.stdout.write("$krb5tgs$unknown:$krb5tgs$%s$" % etype + et[:16].encode("hex") +
                                     "$" + et[16:].encode("hex") + "\n")
