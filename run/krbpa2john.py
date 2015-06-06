#!/usr/bin/env python2

# http://anonsvn.wireshark.org/wireshark/trunk/doc/README.xml-output
# tshark -r AD-capture-2.pcapng -T pdml  > data.pdml
#
# tshark -2 -r test.pcap -R "tcp.dstport==88 or udp.dstport==88" -T pdml >> data.pdml
# ./run/krbpa2john.py data.pdml

import sys
try:
    from lxml import etree
except ImportError:
    sys.stderr.write("This program needs lxml libraries to run!\n")
    sys.exit(1)
import binascii

def process_file(f):

    xmlData = etree.parse(f)

    messages = [e for e in xmlData.xpath('/pdml/packet/proto[@name="kerberos"]')]
    encrypted_timestamp = None
    etype = None
    user = ''
    salt = ''
    realm = None

    for msg in messages:
        if msg.attrib['showname'] == "Kerberos AS-REQ":
            # locate encrypted timestamp
            r = msg.xpath('field[@name="kerberos.padata"]//field[@name="kerberos.PA_ENC_TIMESTAMP.encrypted"]')
            if not r:
                continue
            if isinstance(r, list):
                r  = r[0]
            encrypted_timestamp = r.attrib["value"]

            # locate etype
            r = msg.xpath('field[@name="kerberos.padata"]//field[@name="kerberos.etype"]')
            if not r:
                continue
            if isinstance(r, list):
                r  = r[0]
            etype = r.attrib["show"]

            # locate realm
            r = msg.xpath('field[@name="kerberos.kdc_req_body"]//field[@name="kerberos.realm"]')
            if not r:
                continue
            if isinstance(r, list):
                r  = r[0]
            realm = r.attrib["show"]

            # locate cname
            r = msg.xpath('field[@name="kerberos.kdc_req_body"]//field[@name="kerberos.name_string"]')
            if r:
                if isinstance(r, list):
                    r  = r[0]
                user = r.attrib["show"]

            # locate salt
            r = msg.xpath('field[@name="kerberos.kdc_req_body"]//field[@name="kerberos.etype_info2.salt"]')
            if r:
                if isinstance(r, list):
                    r  = r[0]
                salt = r.attrib["show"]

            if user == "":
                user = binascii.unhexlify(salt)

            sys.stdout.write("%s:$krb5pa$%s$%s$%s$%s$%s\n" % (user,
                etype, user, realm, binascii.unhexlify(salt),
                encrypted_timestamp))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: %s <.pdml files>\n" % sys.argv[0])
        sys.stdout.write("\ntshark -r sample.pcap -T pdml > sample.pdml; %s sample.pdml\n" % sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
