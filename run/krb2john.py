#!/usr/bin/env python2

# This file was named krbpa2john.py previously.
#
# http://anonsvn.wireshark.org/wireshark/trunk/doc/README.xml-output
#
# For extracting "AS-REQ (krb-as-req)" hashes,
# tshark -r AD-capture-2.pcapng -T pdml > data.pdml
# tshark -2 -r test.pcap -R "tcp.dstport==88 or udp.dstport==88" -T pdml >> data.pdml
# ./run/krb2john.py data.pdml
#
# For extracting "TGS-REP (krb-tgs-rep)" hashes,
# tshark -2 -r test.pcap -R "tcp.srcport==88 or udp.srcport==88" -T pdml >> data.pdml
# ./run/krb2john.py data.pdml
#
# Tested on Ubuntu 14.04.2 LTS (Trusty Tahr), and Fedora 25.
#
# $ tshark -v
# TShark 1.10.6 (v1.10.6 from master-1.10)
#
# August 2017 update -> Extracts AS-REP hashes too. Crack such hashes with
# krb5asrep format.
#
# October 2017 update -> Extracts TGS-REP hashes too. Crack such hashes with
# krb5tgs format.
#
# This software is Copyright (c) 2012, Dhiru Kholia <dhiru at openwall.com> and
# it is hereby released to the general public under the following terms:
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.


import sys
try:
    from lxml import etree
except ImportError:
    sys.stderr.write("This program needs lxml libraries to run. Please install the python-lxml package.\n")
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
            r = r[0]
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
                r = r[0]
            PA_DATA_ENC_TIMESTAMP = r.attrib["value"]

            # locate etype
            r = msg.xpath('.//field[@name="kerberos.padata"]//field[@name="kerberos.etype"]')
            if not r:
                continue
            if isinstance(r, list):
                r = r[0]
            etype = r.attrib["show"]

            # locate realm
            r = msg.xpath('.//field[@name="kerberos.kdc_req_body"]//field[@name="kerberos.realm"]') or msg.xpath('.//field[@name="kerberos.req_body_element"]//field[@name="kerberos.realm"]')
            if not r:
                continue
            if isinstance(r, list):
                r = r[0]
            realm = r.attrib["show"]

            # locate cname
            r = msg.xpath('.//field[@name="kerberos.req_body_element"]//field[@name="kerberos.KerberosString"]') or msg.xpath('.//field[@name="kerberos.kdc_req_body"]//field[@name="kerberos.name_string"]') or msg.xpath('.//field[@name="kerberos.req_body_element"]//field[@name="kerberos.CNameString"]')
            if r:
                if isinstance(r, list):
                    r = r[0]
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

    for msg in messages:  # extract hashes from TGS-REP messages
        r = msg.xpath('.//field[@name="kerberos.msg_type"]') or msg.xpath('.//field[@name="kerberos.msg.type"]')
        if not r:
            continue
        if isinstance(r, list):
            r = r[0]
        message_type = r.attrib["show"]
        if message_type == "13":  # Kerberos TGS_REP
            spnps = msg.xpath('.//field[@name="kerberos.SNameString"]')  # is this robust enough?
            spn = "Unknown"
            if isinstance(spnps, list):
                out = []
                for spnp in spnps:
                    out.append(spnp.attrib["show"])
                spn = "/".join(out)
            # locate the hash
            rs = msg.xpath('.//field[@name="kerberos.enc_part_element"]')
            if not rs:
                continue
            if isinstance(rs, list):
                idx = 0
                multiple_entries = False
                if len(rs) >= 2:  # this is typically 2
                    multiple_entries = True
                for r in rs:
                    if multiple_entries and idx != 0:  # only generate hash for the first "kerberos.enc_part_element", is this always correct?
                        idx = idx + 1
                        continue
                    idx = idx + 1
                    v = r.xpath('.//field[@name="kerberos.etype"]')
                    if isinstance(v, list):
                        v = v[0]
                    etype = v.attrib["show"]
                    v = r.xpath('.//field[@name="kerberos.cipher"]')
                    if isinstance(v, list):
                        v = v[0]
                    data = v.attrib["value"]
                    if etype != "23":
                        sys.stderr.write("Currently unsupported etype %s found!\n" % etype)
                    else:
                        sys.stdout.write("%s:$krb5tgs$%s$%s$%s\n" % (spn, etype, data[:32], data[32:]))

    for msg in messages:  # extract hashes from AS-REP messages
        r = msg.xpath('.//field[@name="kerberos.msg_type"]') or msg.xpath('.//field[@name="kerberos.msg.type"]')
        if not r:
            continue
        if isinstance(r, list):
            r = r[0]
        message_type = r.attrib["show"]

        if message_type == "11":  # Kerberos AS-REP
            s = msg.xpath('.//field[@name="kerberos.salt"]')  # is this valid for M$ AD too?
            # locate the hash
            rs = msg.xpath('.//field[@name="kerberos.enc_part_element"]')
            if not rs:
                continue
            if isinstance(rs, list):
                idx = 0
                multiple_entries = False
                if len(rs) >= 2:  # this is typically 2
                    multiple_entries = True
                for r in rs:
                    if multiple_entries and idx == 0:  # skip over the first entry, is this always correct?
                        idx = idx + 1
                        continue
                    idx = idx + 1
                    v = r.xpath('.//field[@name="kerberos.etype"]')
                    if isinstance(v, list):
                        v = v[0]
                    etype = v.attrib["show"]
                    if etype != "23":
                        if s is None:
                            sys.stderr.write("Unable to find kerberos.salt value. Please report this bug to us!\n")
                            continue
                        if isinstance(s, list):
                            if len(s) == 0:
                                sys.stderr.write("Unable to find kerberos.salt value. Please report this bug to us!\n")
                                continue
                            s = s[0]
                            salt = s.attrib["show"]
                    v = r.xpath('.//field[@name="kerberos.cipher"]')
                    if isinstance(v, list):
                        v = v[0]
                    data = v.attrib["value"]
                    if etype != "23":
                        sys.stdout.write("$krb5asrep$%s$%s$%s$%s\n" % (etype, salt, data[0:-24], data[-24:]))
                    else:
                        sys.stdout.write("$krb5asrep$%s$%s$%s\n" % (etype, data[0:32], data[32:]))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stdout.write("Usage: %s <.pdml files>\n" % sys.argv[0])
        sys.stdout.write("\ntshark -r sample.pcap -T pdml > sample.pdml; %s sample.pdml\n" % sys.argv[0])
        sys.exit(1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])
