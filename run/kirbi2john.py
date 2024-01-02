#!/usr/bin/env python3

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


def extract_ticket_from_kirbi(filename):
    with open(filename, 'rb') as fd:
        data = fd.read()
        return extract_ticket(data)

def extract_ticket(data):
    if data[0] == 0x76:
        # ram dump
        #enctickets.append(((decoder.decode(data)[0][2][0][3][2]).asOctets(), i, f))
        return (decoder.decode(data)[0][2][0][3][2]).asOctets()
    elif data[:2] == b'6d':
        # honestly, i completely forgot. I think this is from a pcap -Tim
        #enctickets.append(((decoder.decode(ticket.decode('hex'))[0][4][3][2]).asOctets(), i, f))
        return (decoder.decode(ticket.decode('hex'))[0][4][3][2]).asOctets()

if __name__ == '__main__':
    import argparse
    import sys

    parser = argparse.ArgumentParser(description='Read Mimikatz kerberos ticket then modify it and save it in crack_file')
    parser.add_argument('-o', dest='crack_file', metavar='crack_file', type=argparse.FileType('w'), default=sys.stdout, nargs='?',
                    help='File to save crackable output to (default is stdout')
    parser.add_argument('files', nargs='+', metavar='file.kirbi', type=str,
                    help='File name to crack.\n Files are exported with mimikatz or from extracttgsrepfrompcap.py')

    args = parser.parse_args()

    enctickets = []

    for filename in args.files:
        et = extract_ticket_from_kirbi(filename)
        if et:
            enctickets.append((et,filename))

    #out=open("crack_file","wb")
    for et in enctickets:
        filename = et[1].split('/')[-1].split('\\')[-1].replace('.kirbi','')

        out = '$krb5tgs$23$*' + filename + '*$' + et[0][:16].hex() + '$' +et[0][16:].hex() + '\n'

        args.crack_file.writelines(out)
    sys.stderr.write('tickets written: ' + str(len(enctickets)) + '\n')
