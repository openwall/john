#!/usr/bin/env python2

# http://anonsvn.wireshark.org/wireshark/trunk/doc/README.xml-output
#
# For extracting "AS-REQ (krb-as-req)" hashes,
# tshark -r AD-capture-2.pcapng -T pdml  > data.pdml
# tshark -2 -r test.pcap -R "tcp.dstport==88 or udp.dstport==88" -T pdml >> data.pdml
# ./run/krbpa2john.py data.pdml
#
# For extracting "TGS-REP (krb-tgs-rep)" hashes,
# tshark -2 -r test.pcap -R "tcp.srcport==88 or udp.srcport==88" -T pdml >> data.pdml
# ./run/krbpa2john.py data.pdml
#
# Tested on Ubuntu 14.04.2 LTS (Trusty Tahr)
#
# $ tshark -v
# TShark 1.10.6 (v1.10.6 from master-1.10)

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
    PA_DATA_ENC_TIMESTAMP = None
    etype = None
    user = ''
    salt = ''
    realm = None

    for msg in messages:  # msg is of type "proto"
        r = msg.xpath('.//field[@name="kerberos.msg_type"]') or msg.xpath('.//field[@name="kerberos.msg.type"]')
        if not r:
            continue
        if isinstance(r, list):
            r  = r[0]
        message_type = r.attrib["show"]

        # "kerberos.etype_info2.salt" value (salt) needs to be extracted
        # from a different packet when etype is 17 or 18!
        # if salt is empty, realm.user is used instead (in krb5pa-sha1_fmt_plug.c)
        if message_type == "30":  # KRB-ERROR
            r = msg.xpath('.//field[@name="kerberos.etype_info2.salt"]') or msg.xpath('.//field[@name="kerberos.salt"]') or msg.xpath('.//field[@name="kerberos.etype_info.salt"]')
            if r:
                if isinstance(r, list):
                    # some of the entries might have "value" missing!
                    for item in r:
                        if "value" in item.attrib:
                            try:
                                salt = binascii.unhexlify(item.attrib["value"])
                                break
                            except:
                                continue

        if message_type == "10":  # Kerberos AS-REQ
            # locate encrypted timestamp
            r = msg.xpath('.//field[@name="kerberos.padata"]//field[@name="kerberos.PA_ENC_TIMESTAMP.encrypted"]') or msg.xpath('.//field[@name="kerberos.padata"]//field[@name="kerberos.cipher"]')
            if not r:
                continue
            if isinstance(r, list):
                r  = r[0]
            PA_DATA_ENC_TIMESTAMP = r.attrib["value"]

            # locate etype
            r = msg.xpath('.//field[@name="kerberos.padata"]//field[@name="kerberos.etype"]')
            if not r:
                continue
            if isinstance(r, list):
                r  = r[0]
            etype = r.attrib["show"]

            # locate realm
            r = msg.xpath('.//field[@name="kerberos.kdc_req_body"]//field[@name="kerberos.realm"]') or msg.xpath('.//field[@name="kerberos.req_body_element"]//field[@name="kerberos.realm"]')
            if not r:
                continue
            if isinstance(r, list):
                r  = r[0]
            realm = r.attrib["show"]

            # locate cname
            r = msg.xpath('.//field[@name="kerberos.req_body_element"]//field[@name="kerberos.KerberosString"]') or msg.xpath('.//field[@name="kerberos.kdc_req_body"]//field[@name="kerberos.name_string"]')
            if r:
                if isinstance(r, list):
                    r  = r[0]
                user = r.attrib["show"]

            if user == "":
                user = binascii.unhexlify(salt)

            # user, realm and salt are unused when etype is 23 ;)
            checksum = PA_DATA_ENC_TIMESTAMP[0:32]
            enc_timestamp = PA_DATA_ENC_TIMESTAMP[32:]
            if etype == "23":  # user:$krb5pa$etype$user$realm$salt$HexTimestampHexChecksum
                sys.stdout.write("%s:$krb5pa$%s$%s$%s$%s$%s%s\n" % (user,
                            etype, user, realm, salt,
                            enc_timestamp,
                            checksum))
            else:
                if not salt:
                    sys.stderr.write("[-] Hash might be broken, etype != 23 and salt not found!\n")
                sys.stdout.write("%s:$krb5pa$%s$%s$%s$%s$%s\n" % (user,
                            etype, user, realm, salt,
                            PA_DATA_ENC_TIMESTAMP))

    for msg in messages:  # WIP!
        if msg.attrib['showname'] == "Kerberos TGS-REP":  # kerberos.msg.type == 13
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
