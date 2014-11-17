#!/usr/bin/env python

"""

s7tojohn.py, parse .pcap files and output JtR compatible hashes.
Extended by Narendra Kangralkar <narendrakangralkar at gmail.com>
and Dhiru Kholia <dhiru at openwall.com>

S7 protocol, is used for communication between Engineering Stations,
SCADA, HMI & PLC and can be protected by password.

Original Authors: Alexander Timorin, Dmitry Sklyarov

http://scadastrangelove.org

__author__      = "Aleksandr Timorin"
__copyright__   = "Copyright 2013, Positive Technologies"
__license__     = "GNU GPL v3"
__version__     = "1.2"
__maintainer__  = "Aleksandr Timorin"
__email__       = "atimorin@gmail.com"
__status__      = "Development"

"""

import os
import logging
l = logging.getLogger("scapy.runtime")
l.setLevel(49)
import sys
from binascii import hexlify
try:
    from scapy.all import rdpcap
except ImportError:
    sys.stderr.write("Please install scapy, "
            "http://www.secdev.org/projects/scapy/\n")
    sys.exit(-1)


def get_challenge_response(cfg_pcap_file):
    found_something = False

    # s7-1500_brute_offline.py code
    #
    # Offline password bruteforse based on challenge-response data, extracted
    # from auth traffic dump file for Siemens S7-1500 PLC's.
    #
    # IMPORTANT:
    #
    # traffic dump should contains only traffic between plc and hmi/pc/etc.
    # filter dump file before parse
    result = {}
    challenge = ''
    response = ''

    for packet in rdpcap(cfg_pcap_file):
        try:
            payload = packet.load.encode('hex')
            # if payload[14:26]=='720200453200' and payload[46:52]=='100214' and abs(packet.len+14 - 138)<=1:
            if payload[14:20]=='720200' and payload[46:52]=='100214' and abs(packet.len+14 - 138)<=1:
                challenge = payload[52:92]
            # elif payload[14:26]=='720200663100' and payload[64:70]=='100214'  and abs(packet.len+14 - 171)<=1:
            elif payload[14:20]=='720200' and payload[64:70]=='100214'  and abs(packet.len+14 - 171)<=1:
                response = payload[70:110]

            if challenge and response:
                result[challenge] = response
                challenge = ''
                response = ''
        except:
            pass

    outcome = 0  # XXX we don't know this currently!
    for c, r in result.items():
        found_something = True  # overkill ;(
        sys.stdout.write("%s:$siemens-s7$%s$%s$%s\n" % (os.path.basename(cfg_pcap_file),
                                                        outcome, c, r))

    # s7-1200_brute_offline.py stuff below
    # try to find challenge packet
    r = rdpcap(cfg_pcap_file)

    lens = map(lambda x: x.len, r)
    pckt_lens = dict([(i, lens[i]) for i in range(0, len(lens))])

    pckt_108 = None  # challenge packet (from server)
    for (pckt_indx, pckt_len) in pckt_lens.items():
        if (pckt_len + 14 == 108 and
                hexlify(r[pckt_indx].load)[14:24] == '7202002732'):
            pckt_108 = pckt_indx
            break

    # try to find response packet
    pckt_141 = 0  # response packet (from client)
    _t1 = dict([(i, lens[i]) for i in pckt_lens.keys()[pckt_108:]])
    for pckt_indx in sorted(_t1.keys()):
        pckt_len = _t1[pckt_indx]
        if (pckt_len + 14 == 141 and
                hexlify(r[pckt_indx].load)[14:24] == '7202004831'):
            pckt_141 = pckt_indx
            break

    # try to find auth result packet
    pckt_84 = 0  # auth answer from plc: pckt_len==84 -> auth ok
    pckt_92 = 0  # auth answer from plc: pckt_len==92 -> auth bad
    for pckt_indx in sorted(_t1.keys()):
        pckt_len = _t1[pckt_indx]
        if (pckt_len + 14 == 84 and
                hexlify(r[pckt_indx].load)[14:24] == '7202000f32'):
            pckt_84 = pckt_indx
            assert(pckt_84)
            break
        if (pckt_len + 14 == 92 and
                hexlify(r[pckt_indx].load)[14:24] == '7202001732'):
            pckt_92 = pckt_indx
            assert(pckt_92)
            break

    # print "found packets indices: pckt_108=%d, pckt_141=%d, pckt_84=%d, pckt_92=%d" % (pckt_108, pckt_141, pckt_84, pckt_92)
    # if pckt_84:
    #    print "auth ok"
    # else:
    #    print "auth bad. for brute we need right auth result. exit"
    #    sys.exit()

    challenge = None
    response = None

    if not pckt_108 and found_something:
        sys.exit(0)

    try:
        raw_challenge = hexlify(r[pckt_108].load)
    except (AttributeError):
        sys.stderr.write("%s : expected data not found!\n" % cfg_pcap_file)
        return
    if raw_challenge[46:52] == '100214' and raw_challenge[92:94] == '00':
        challenge = raw_challenge[52:92]
        # sys.stdout.write("found challenge: %s\n" % challenge)
    else:
        sys.stderr.write("[-] cannot find challenge for %s. exiting...\n"
                % os.path.basename(cfg_pcap_file))
        return

    raw_response = hexlify(r[pckt_141].load)
    if raw_response[64:70] == '100214' and raw_response[110:112] == '00':
        response = raw_response[70:110]
        # sys.stdout.write("found  response: %s\n" % response)
    else:
        sys.stderr.write("[-] cannot find response for %s. exiting...\n"
                % os.path.basename(cfg_pcap_file))
        return

    if pckt_84:
        outcome = 1
    else:
        outcome = 0
    sys.stdout.write("%s:$siemens-s7$%s$%s$%s\n" % (os.path.basename(cfg_pcap_file),
        outcome, challenge, response))


if __name__ == '__main__':

    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <.pcap files>\n" % sys.argv[0])
        sys.exit(-1)

    for j in range(1, len(sys.argv)):
        data = get_challenge_response(sys.argv[j])
