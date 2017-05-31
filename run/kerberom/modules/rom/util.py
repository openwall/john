# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42):
# <jean-christophe.delaunay (at) synacktiv.com> wrote this file.  As long as you
# retain this notice you can do whatever you want with this stuff. If we meet
# some day, and you think this stuff is worth it, you can buy me a beer in
# return.   Fist0urs
# ----------------------------------------------------------------------------

#!/usr/bin/python

# -*- coding: utf-8 -*-

# by Fist0urs

from struct import unpack, pack
from time import time, gmtime, strftime, strptime, localtime
from calendar import timegm


def gt2epoch(gt):
    return timegm(strptime(gt, '%Y%m%d%H%M%SZ'))

def epoch2gt(epoch=None, microseconds=False):
    if epoch is None:
        epoch = time()
    gt = strftime('%Y%m%d%H%M%SZ', gmtime(epoch))
    if microseconds:
        ms = int(epoch * 1000000) % 1000000
        return (gt, ms)
    return gt

def epoch2filetime(epoch=None):
    if epoch is None:
        epoch = time()
    return pack('Q', int((epoch + 11644473600) * 10000000))

def filetime2local(s):
    t = unpack('Q', s)[0]
    if t == 0x7fffffffffffffff:
        return 'NEVER'
    if t == 0:
        return 'NULL'
    secs = t / 10000000 - 11644473600
    digits = t % 10000000
    return "%s.%07d" % (strftime('%Y/%m/%d %H:%M:%S', localtime(secs)), digits)

def bitstring2int(bs):
    return sum(b << i for i, b in enumerate(reversed(bs)))


