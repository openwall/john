#!/usr/bin/env python2

# http://anonsvn.wireshark.org/wireshark/trunk/doc/README.xml-output
# tshark -r AD-capture-2.pcapng -T pdml  > ~/data.pdml
# krbng2john data.pdml

import sys
try:
    from lxml import etree
except ImportError:
    print >> sys.stderr, "This program needs lxml libraries to run!"
    sys.exit(1)
import binascii

def process_file(f):

    xmlData = etree.parse(f)

    messages = [e for e in xmlData.xpath('/pdml/packet/proto[@name="kerberos"]')]

    state = None
    encrypted_timestamp = None
    server = None
    etype = None
    got_etype = False


    for msg in messages:
        if msg.attrib['showname'] == "Kerberos AS-REQ":
            if not state:
                state = "AS-REQ"
            elif state == "KRB-ERROR":
                state = "AS-REQ2"
                # actual request with encrypted timestamp
                fields = msg.xpath(".//field")
                for field in fields:
                    if 'name' in field.attrib:
                        if field.attrib['name'] == 'kerberos.PA_ENC_TIMESTAMP.encrypted':
                            encrypted_timestamp = field.attrib['value']
                        if field.attrib['name'] == 'kerberos.etype' and not got_etype:
                            got_etype = True
                            etype = field.attrib['show']

        if msg.attrib['showname'] == "Kerberos KRB-ERROR":
            if state == "AS-REQ" or state == "AS-REQ2":
                state = "KRB-ERROR"
            else:
                pass
                # print "Unkwown state! Please report this on john-users mailing list"
            # note down the salt
            fields = msg.xpath(".//field")
            for field in fields:
                if 'name' in field.attrib:
                    if field.attrib['name'] == 'kerberos.etype_info2.salt':
                        salt = field.attrib["value"]
                        server = "AD"
                    if field.attrib['name'] == 'kerberos.realm':
                        realm = field.attrib['show']
                        server = "plain"
                    if field.attrib['name'] == 'kerberos.cname':
                        user = field.attrib['showname'][25:]

        if msg.attrib['showname'] == "Kerberos AS-REP" or state == "AS-REQ2":
            # we might not have AS-REP packets
            if state == "AS-REQ2":
                if server == "AD":
                    print "%s:$krb5pa$%s$1$%s$%s" % (binascii.unhexlify(salt), etype, binascii.unhexlify(salt), encrypted_timestamp)
                else:
                    print "%s:$krb5pa$%s$0$%s$%s$%s" % (user, etype, user, realm, encrypted_timestamp)
                # reset state
                state = None
                got_etype = False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: %s <pdml file(s)>" % sys.argv[0]
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
