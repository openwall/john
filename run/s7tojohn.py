#!/usr/bin/env python

"""

s7tojohn.py, parse .pcap files and output JtR compatible hashes.
Extended by Narendra Kangralkar <narendrakangralkar at gmail.com>
and Dhiru Kholia <dhiru at openwall.com>

S7 protocol, is used for communication between Engineering Stations,
SCADA, HMI & PLC and can be protected by password.

Original PoC Authors: Alexander Timorin, Dmitry Sklyarov
http://scadastrangelove.org

"""


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
    r = rdpcap(cfg_pcap_file)

    lens = map(lambda x: x.len, r)
    pckt_lens = dict([(i, lens[i]) for i in range(0, len(lens))])

    # try to find challenge packet
    pckt_108 = 0  # challenge packet (from server)
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

    try:
        raw_challenge = hexlify(r[pckt_108].load)
    except (AttributeError):
        sys.stderr.write("%s : expected data not found!\n" % cfg_pcap_file)
        return
    if raw_challenge[46:52] == '100214' and raw_challenge[92:94] == '00':
        challenge = raw_challenge[52:92]
        # sys.stdout.write("found challenge: %s\n" % challenge)
    else:
        sys.stderr.write("cannot find challenge for %s. exiting...\n"
                % cfg_pcap_file)
        return

    raw_response = hexlify(r[pckt_141].load)
    if raw_response[64:70] == '100214' and raw_response[110:112] == '00':
        response = raw_response[70:110]
        # sys.stdout.write("found  response: %s\n" % response)
    else:
        sys.stderr.write("cannot find response for %s. exiting...\n"
                % cfg_pcap_file)
        return

    if pckt_84:
        outcome = 1
    else:
        outcome = 0
    sys.stdout.write("%s:$siemens-s7$%s$%s$%s\n" % (cfg_pcap_file,
        outcome, challenge, response))


if __name__ == '__main__':

    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <.pcap files>\n" % sys.argv[0])
        sys.exit(-1)

    for j in range(1, len(sys.argv)):
        data = get_challenge_response(sys.argv[j])
