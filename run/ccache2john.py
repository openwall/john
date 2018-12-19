#!/usr/bin/env python2

"""
This script extracts crackable hashes from krb5's credential cache files (e.g.
/tmp/krb5cc_1000).

NOTE: This attack technique only works against MS Active Directory servers.

This was tested with CentOS 7.4 client running krb5-1.15.1 software against a
Windows 2012 R2 Active Directory server.

Usage: python ccache2john.py ccache_file

Upstream: https://github.com/rvazarkar/KrbCredExport

Authors: Rohan Vazarkar (main author), Michael Kramer (splitting support), and Dhiru
Kholia (misc. glue)

Resources,

https://lapo.it/asn1js/
https://tools.ietf.org/html/rfc1510#section-5.8.1
https://github.com/CoreSecurity/impacket/tree/master/impacket/krb5
https://www.gnu.org/software/shishi/manual/html_node/The-Credential-Cache-Binary-File-Format.html
https://github.com/wireshark/wireshark/blob/master/epan/dissectors/asn1/kerberos/KerberosV5Spec2.asn
"""

import sys
import time
import struct
import datetime
from pyasn1.codec.ber import decoder


# LB is a single byte representing the length of the rest of the section
# LT is a 3 byte structure consisting of the byte 82 followed by 2 bytes representing the length of the rest of the file

# header {
#   uint16 tag
#   uint16 taglen
#   uint8[taglen] tagdata
# }
class Header:
    def __init__(self):
        self.tag = None
        self.taglen = None
        self.deltatime = DeltaTime()

    def parsefile(self, f):
        self.tag, self.taglen = struct.unpack(">HH", f.read(4))
        self.deltatime.parsefile(f)

    def tostring(self):
        r = ''
        r += struct.pack(">HH", self.tag, self.taglen)
        r += self.deltatime.tostring()
        return r


# deltatime {
#   uint32 time_offset
#   uint32 usec_offset
# }
class DeltaTime:
    def __init__(self):
        self.usec_offset = None
        self.time_offset = None

    def parsefile(self, f):
        self.time_offset, self.usec_offset = struct.unpack(">LL", f.read(8))

    def tostring(self):
        r = ''
        r += struct.pack(">LL", self.time_offset, self.usec_offset)
        return r


# ccacheheader {
#   uint16 version
#   uint16 header_len
#   header[] headers
#   principal primary_principal
# }
class CCacheHeader:
    def __init__(self):
        self.version = None
        self.header_length = None
        self.header = Header()

    def parsefile(self, f):
        self.version, = struct.unpack(">H", f.read(2))
        self.header_length, = struct.unpack(">H", f.read(2))
        # self.header.parsefile(f)  # this is perhaps buggy?
        f.read(self.header_length)

    def tostring(self):
        r = ''
        r += struct.pack(">HH", self.version, self.header_length)
        r += self.header.tostring()
        return r


# times {
#   uint32 authtime
#   uint32 starttime
#   uint32 endtime
#   uint32 renew_till
# }
class KerbTimes:
    def __init__(self):
        self.authtime = None
        self.starttime = None
        self.endtime = None
        self.renew_till = None

    def parsefile(self, f):
        self.authtime, self.starttime, self.endtime, self.renew_till = struct.unpack(">IIII", f.read(16))

    def tostring(self):
        return struct.pack(">IIII", self.authtime, self.starttime, self.endtime, self.renew_till)


# counted_octet {
#   uint32 length
#   uint8[char] data
# }
class CountedOctet:
    def __init__(self):
        self.length = None
        self.data = None

    def parsefile(self, f):
        self.length, = struct.unpack(">L", f.read(4))
        self.data, = struct.unpack(">%ds" % self.length, f.read(self.length))

    def tostring(self):
        r = b''
        r += struct.pack(">L", self.length)
        r += struct.pack(">%ds" % self.length, self.data)
        return r


# keyblock {
#   uint16 keytype
#   uint16 etype
#   uint16 keylen
#   uint8[keylen] key
# }
class Keyblock:
    def __init__(self):
        self.keytype = None
        self.etype = None
        self.keylen = None
        self.key = None

    def parsefile(self, f):
        self.keytype, self.etype, self.keylen = struct.unpack(">HHH", f.read(6))
        self.key, = struct.unpack(">%ds" % self.keylen, f.read(self.keylen))

    def tostring(self):
        r = ''
        r += struct.pack(">HHH", self.keytype, self.etype, self.keylen)
        r += struct.pack(">%ds" % self.keylen, self.key)
        return r


# principal {
#   uint32 name_type
#   uint32 num_components
#   counted_octet realm
#   counted_octet[num_components] components
# }
class Principal:
    def __init__(self):
        self.name_type = None
        self.num_components = None
        self.realm = CountedOctet()
        self.components = []

    def parsefile(self, f):
        self.name_type, self.num_components = struct.unpack(">LL", f.read(8))
        self.realm.parsefile(f)
        for i in range(0, self.num_components):
            component = CountedOctet()
            component.parsefile(f)
            self.components.append(component.data)

    def tostring(self):
        r = ''
        r += struct.pack(">LL", self.name_type, self.num_components)
        r += self.realm.tostring()
        for i in self.components:
            r += struct.pack(">L", len(i))
            r += i
        return r


# address {
#   uint16 address_type
#   counted_octet address
# }
class Address:
    def __init__(self):
        self.address_type = None
        self.address = CountedOctet()

    def parsefile(self, f):
        self.address_type, = struct.unpack(">H", f.read(2))
        self.address.parsefile(f)

    def tostring(self):
        r = ''
        r += struct.pack(">H", self.address_type)
        r += self.address.tostring()
        return r


# authdata {
#   uint16 authtype
#   counted_octet authdata
# }
class AuthData:
    def __init__(self):
        self.authtype = None
        self.authdata = CountedOctet()

    def parsefile(self, f):
        self.authtype, = struct.unpack(">H", f.read(2))
        self.authdata.parsefile(f)

    def tostring(self):
        r = ''
        r += struct.pack(">H", self.authtype)
        r += self.authdata.tostring()
        return r


# credential {
#   principal client
#   principal server
#   keyblock key
#   times timedata
#   uint8 skey
#   uint32 tktFlags (Reverse Byte Order!)
#   uint32 num_address
#   address[num_address] addresses
#   uint32 num_authdata
#   authdata[num_authdata] auths
#   counted_octet ticket_1
#   counted_octet ticket_2 (nothing here in what I've seen)
# }
class Credential:
    def __init__(self):
        self.client = Principal()
        self.server = Principal()
        self.keyblock = Keyblock()
        self.times = KerbTimes()
        self.is_skey = None
        self.tktFlags = None
        self.num_address = None
        self.address = []
        self.num_authdata = None
        self.authdata = []
        self.ticket = CountedOctet()
        self.secondticket = CountedOctet()

    def parsefile(self, f):
        self.client.parsefile(f)
        self.server.parsefile(f)
        self.keyblock.parsefile(f)
        self.times.parsefile(f)
        self.is_skey, = struct.unpack(">B", f.read(1))
        self.tktFlags, = struct.unpack("<I", f.read(4))
        self.num_address, = struct.unpack(">I", f.read(4))
        for i in range(0, self.num_address):
            self.address.append(Address().parsefile(f))
        self.num_authdata, = struct.unpack(">I", f.read(4))
        for i in range(0, self.num_authdata):
            self.authdata.append(AuthData().parsefile(f))
        self.ticket.parsefile(f)
        self.secondticket.parsefile(f)

    def tostring(self):
        r = ''
        r += self.client.tostring()
        r += self.server.tostring()
        r += self.keyblock.tostring()
        r += self.times.tostring()
        r += struct.pack(">B", self.is_skey)
        r += struct.pack("<I", self.tktFlags)
        r += struct.pack(">I", self.num_address)
        for i in self.address:
            r += i.tostring()
        r += struct.pack(">I", self.num_authdata)
        for i in self.authdata:
            r += i.tostring()
        r += self.ticket.tostring()
        r += self.secondticket.tostring()
        return r


# Prepend, shortened for convenience
def p(a, b):
    return b + a


# Returns the length of s as a single byte
def clen(s):
    return chr(len(s))


# key {
#   0xA0 LB
#   0x30 LB
#   0xA0 0x03 0x02 0x01
#   uint8 key_type
#   0xA1 LB
#   0x03 LB
#   keydata
# }
class Key:

    def __init__(self):
        self.key = None
        self.keytype = None

    def parsefile(self, f):
        f.read(8)
        self.keytype, = struct.unpack('>B', f.read(1))
        f.read(3)
        keylen, = struct.unpack('>B', f.read(1))
        self.key, = struct.unpack(">%ds" % keylen, f.read(keylen))

    def tostring(self):
        r = ''
        r += self.key
        r = p(r, clen(r))
        r = p(r, '\x04')
        r = p(r, clen(r))
        r = p(r, '\xA1')
        r = p(r, chr(self.keytype))
        r = p(r, '\xA0\x03\x02\x01')
        r = p(r, clen(r))
        r = p(r, '\x30')
        r = p(r, clen(r))
        r = p(r, '\xA0')
        return r


# This section represents the primary principal realm. Corresponds to the domain name
# prealm {
#   0xA1 LB
#   0x1B LB
#   Primary Principal Realm
# }
class PRealm:

    def __init__(self):
        self.principal_realm = None

    def parsefile(self, f):
        f.read(3)
        length, = struct.unpack(">b", f.read(1))
        self.principal_realm, = struct.unpack(">%ds" % length, f.read(length))

    def tostring(self):
        r = ''
        r += self.principal_realm
        r = p(r, clen(r))
        r = p(r, '\x1B')
        r = p(r, clen(r))
        r = p(r, '\xA1')
        return r


# This section represents the primary principal realm
# pname {
#   0xA2 LB
#   0x30 LB
#   0xA0 0x03 0x02 0x01
#   uint8 name_type
#   0xA1 LB
#   0x30 LB
#   0x1B LB
#   Primary Principal Name
# }
class PName:

    def __init__(self):
        self.principal_components = []
        self.principal_name_type = None

    def parsefile(self, f):
        f.read(8)
        self.principal_name_type, = struct.unpack(">B", f.read(1))
        f.read(3)
        rem_length, = struct.unpack(">B", f.read(1))
        while (rem_length > 0):
            f.read(1)
            l, = struct.unpack(">B", f.read(1))
            component, = struct.unpack("%ds" % l, f.read(l))
            self.principal_components.append(component)
            rem_length -= (2 + l)

    def tostring(self):
        r = ''
        for s in self.principal_components:
            r += '\x1B' + chr(len(s)) + s
        r = p(r, clen(r))
        r = p(r, '\x30')
        r = p(r, clen(r))
        r = p(r, '\xA1')
        r = p(r, chr(self.principal_name_type))
        r = p(r, '\xA0\x03\x02\x01')
        r = p(r, clen(r))
        r = p(r, '\x30')
        r = p(r, clen(r))
        r = p(r, '\xA2')
        return r


# This section details flags for the ticket
# tktflags {
#   0xA3 LB
#   0x03 LB
#   0x00 Always 0, apparently number of unused bytes. tktFlags is always a uint32
#   uint32 Ticket Flags
# }
class TicketFlags:

    def __init__(self):
        self.ticket_flags = None

    def parsefile(self, f):
        f.read(5)
        self.ticket_flags, = struct.unpack("I", f.read(4))

    def tostring(self):
        r = ''
        r += struct.pack("I", self.ticket_flags)
        r = p(r, '\x00')
        r = p(r, clen(r))
        r = p(r, '\x03')
        r = p(r, clen(r))
        r = p(r, '\xA3')
        return r


# These sections contain the ticket timestamps. Note that the timestamps are in a consistent format, so length tags are always the same
# Timestamp format is YYYYmmddHHMMSSZ and must be UTC!
# 0xA5 is starttime, 0xA6 is endtime, 0xA7 is renew_till
# time {
#   uint8 Identifier
#   LB (Always 0x11)
#   0x18 LB (Always 0x0F)
#   start_time
# }
class Time:

    def __init__(self, identifier):
        self.identifier = identifier
        self.time = None

    @staticmethod
    def convert_to_unix(timestr):
        epoch = datetime.datetime(1970, 1, 1)
        t = datetime.datetime.strptime(timestr[:-1], '%Y%m%d%H%M%S')
        td = t - epoch
        return int((td.microseconds + (td.seconds + td.days * 24 * 3600) * 10 ** 6) / 1e6)

    @staticmethod
    def convert_to_kerbtime(unixtime):
        t = datetime.datetime.utcfromtimestamp(unixtime)
        t = ''.join([t.strftime('%Y'), t.strftime('%m'), t.strftime('%d'),
                     t.strftime('%H'), t.strftime('%M'), t.strftime('%S'), 'Z'])
        return t

    def parsefile(self, f):
        self.identifier, = struct.unpack(">B", f.read(1))
        f.read(3)
        strtime, = struct.unpack(">15s", f.read(15))
        self.time = Time.convert_to_unix(strtime)

    def tostring(self):
        r = ''
        r += struct.pack(">15s", Time.convert_to_kerbtime(self.time))
        r = p(r, '\x11\x18\x0F')
        r = p(r, chr(self.identifier))
        return r


# This section represents the server realm (domain)
# srealm {
#   0xA8 LB
#   0x1B LB
#   server_realm (domain name of server)
# }
class SRealm:

    def __init__(self):
        self.server_realm = None

    def parsefile(self, f):
        f.read(3)
        length, = struct.unpack(">B", f.read(1))
        self.server_realm, = struct.unpack(">%ds" % length, f.read(length))

    def tostring(self):
        r = ''
        r += self.server_realm
        r = p(r, clen(r))
        r = p(r, '\x1B')
        r = p(r, clen(r))
        r = p(r, '\xA8')
        return r


# This section represents the server name components
# sname {
#   0xA9 LB
#   0x30 LB
#   0xA0 0x03 0x02 0x01
#   uint8 server_name_type
#   0xA1 LB
#   0x30 LB
#   components[]
# }
#
# components {
#   0x1B
#   uint8 Component Length
#   Component
# }

class SName:

    def __init__(self):
        self.server_components = []
        self.server_name_type = None

    def parsefile(self, f):
        f.read(8)
        self.server_name_type, = struct.unpack(">B", f.read(1))
        f.read(3)
        rem_length, = struct.unpack(">B", f.read(1))
        while rem_length > 0:
            f.read(1)
            l, = struct.unpack(">B", f.read(1))
            component, = struct.unpack(">%ds" % l, f.read(l))
            self.server_components.append(component)
            rem_length -= (2 + l)

    def tostring(self):
        r = ''
        for s in self.server_components:
            r += '\x1B' + chr(len(s)) + s
        r = p(r, clen(r))
        r = p(r, '\x30')
        r = p(r, clen(r))
        r = p(r, '\xA1')
        r = p(r, chr(self.server_name_type))
        r = p(r, '\xA0\x03\x02\x01')
        r = p(r, clen(r))
        r = p(r, '\x30')
        r = p(r, clen(r))
        r = p(r, '\xA9')
        return r


# header {
#   0x7D LT
#   0x30 LT
#   0xA0 LT
#   0x30 LT
#   0x30 LT
# }
class KrbCredInfo:

    def __init__(self):
        self.krbcredinfo = None
        self.key = Key()
        self.prealm = PRealm()
        self.pname = PName()
        self.flags = TicketFlags()
        self.starttime = Time(165)
        self.endtime = Time(166)
        self.renew_till = Time(167)
        self.srealm = SRealm()
        self.sname = SName()

    def parsefile(self, f):
        f.read(20)
        self.key.parsefile(f)
        self.prealm.parsefile(f)
        self.pname.parsefile(f)
        self.flags.parsefile(f)
        self.starttime.parsefile(f)
        self.endtime.parsefile(f)
        self.renew_till.parsefile(f)
        self.srealm.parsefile(f)
        self.sname.parsefile(f)
        self.krbcredinfo = self.key.tostring() + self.prealm.tostring() + self.pname.tostring() + self.flags.tostring() + \
            self.starttime.tostring() + self.endtime.tostring() + \
            self.renew_till.tostring() + self.srealm.tostring() + \
            self.sname.tostring()

    def tostring(self):
        r = self.krbcredinfo
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x30\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x30\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\xA0\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x30\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x7D\x82')
        return r

    def createkrbcrdinfo(self):
        self.krbcredinfo = self.key.tostring() + self.prealm.tostring() + self.pname.tostring() + self.flags.tostring() + \
            self.starttime.tostring() + self.endtime.tostring() + \
            self.renew_till.tostring() + self.srealm.tostring() + \
            self.sname.tostring()


# The encpart serves as a sort of header for the EncKrbCredPart
# encpart {
#   0xA0 0x03 0x02 0x01
#   uint8 etype (Seems to always be 0 in my testing)
#   0xA2 LT
#   0x04 LT
# }
class EncPart:
    def __init__(self):
        self.krbcredinfo = KrbCredInfo()
        self.etype = None

    def parsefile(self, f):
        f.read(4)
        self.etype, = struct.unpack(">B", f.read(1))
        f.read(8)
        self.krbcredinfo.parsefile(f)

    def tostring(self):
        r = self.krbcredinfo.tostring()
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x04\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\xA2\x82')
        r = p(r, chr(self.etype))
        r = p(r, '\xA0\x03\x02\x01')
        return r


# This section represents the tickets section of the overall KrbCred
# tickets {
#   0xA2 0x82
#   uint16 ticket_length + 4
#   0x30 0x82
#   uint16 ticket_length
#   ticket
#   0xA3 LT
#   0x30 LT
# }
class TicketPart:
    def __init__(self):
        self.ticket = None
        self.encpart = EncPart()

    def parsefile(self, f):
        f.read(6)
        ticketlen, = struct.unpack(">H", f.read(2))
        self.ticket, = struct.unpack(">%ds" % ticketlen, f.read(ticketlen))
        f.read(8)
        self.encpart.parsefile(f)

    def tostring(self):
        r = self.encpart.tostring()
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x30\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\xA3\x82')
        r = p(r, self.ticket)
        r = p(r, struct.pack(">H", len(self.ticket)))
        r = p(r, '\x30\x82')
        r = p(r, struct.pack(">H", len(self.ticket) + 4))
        r = p(r, '\xA2\x82')
        return r


# This is the header for the kerberos ticket, and the final section
# header {
#   0x76 LT
#   0x30 LT
#   0xA0 0x03 0x02 0x01
#   uint8 pvno (Protocol Version, always 0x05)
#   0xA1 0x03 0x02 0x01
#   uint8 msg-type (Always 0x16 for krbcred)
# }
class KrbCredHeader:
    def __init__(self):
        self.ticketpart = TicketPart()

    def parsefile(self, f):
        f.read(18)
        self.ticketpart.parsefile(f)

    def tostring(self):
        r = self.ticketpart.tostring()
        r = p(r, '\xA1\x03\x02\x01\x16')
        r = p(r, '\xA0\x03\x02\x01\x05')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x30\x82')
        r = p(r, struct.pack(">H", len(r)))
        r = p(r, '\x76\x82')
        return r


# borrowed from https://stackoverflow.com
def swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]

# src/include/krb5/krb5.h
"""
#define TKT_FLG_FORWARDABLE             0x40000000
#define TKT_FLG_FORWARDED               0x20000000
#define TKT_FLG_PROXIABLE               0x10000000
#define TKT_FLG_PROXY                   0x08000000
#define TKT_FLG_MAY_POSTDATE            0x04000000
#define TKT_FLG_POSTDATED               0x02000000
#define TKT_FLG_INVALID                 0x01000000
#define TKT_FLG_RENEWABLE               0x00800000
#define TKT_FLG_PRE_AUTH                0x00200000
#define TKT_FLG_HW_AUTH                 0x00100000
#define TKT_FLG_TRANSIT_POLICY_CHECKED  0x00080000
#define TKT_FLG_OK_AS_DELEGATE          0x00040000
#define TKT_FLG_ENC_PA_REP              0x00010000
#define TKT_FLG_ANONYMOUS               0x00008000
"""

TKT_FLG_INITIAL = 0x00400000

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: {0} <input credential cache file>".format(sys.argv[0]))
        print("\nExample: {0} /tmp/krb5cc_1000".format(sys.argv[0]))
        sys.exit(0)

    with open(sys.argv[1], 'rb') as f:
        fileid, = struct.unpack(">B", f.read(1))
        if fileid == 0x5:  # Credential Cache (ccache)
            f.seek(0)
            header = CCacheHeader()
            primary_principal = Principal()
            credential = Credential()

            header.parsefile(f)
            primary_principal.parsefile(f)

            i = 0
            sys.stderr.write("WARNING: Not all the hashes generated by this program are crackable. Please select the relevant hashes manually!\n")
            time.sleep(2)

            # Check if you've reached the end of the file. If not get the next credential
            while(f.read(1) != ''):
                f.seek(-1, 1)
                credential.parsefile(f)
                out = []

                KrbCred = KrbCredHeader()
                KrbCred.ticketpart.ticket = credential.ticket.data  # extract hash from here!
                try:
                    # this code is terrible!
                    etype = str(decoder.decode(credential.ticket.data)[0][3][0])
                    data = str(decoder.decode(credential.ticket.data)[0][3][2])
                    if etype != "23":
                        sys.stderr.write("Unsupported etype %s found. Such hashes can't be cracked it seems.\n" % etype)
                        continue
                except:
                    continue

                # print(credential.ticket.data.encode("hex"))
                KrbCred.ticketpart.encpart.etype = credential.keyblock.etype
                krbcredinfo = KrbCred.ticketpart.encpart.krbcredinfo
                krbcredinfo.key.key = credential.keyblock.key
                krbcredinfo.key.keytype = credential.keyblock.keytype
                # print(credential.keyblock.keytype)
                krbcredinfo.prealm.principal_realm = primary_principal.realm.data
                # print(primary_principal.realm.data)
                krbcredinfo.pname.principal_components = primary_principal.components
                # print(primary_principal.components)
                krbcredinfo.pname.principal_name_type = primary_principal.name_type
                krbcredinfo.flags.ticket_flags = credential.tktFlags
                tktFlags = swap32(credential.tktFlags)
                if tktFlags & TKT_FLG_INITIAL:
                    continue
                krbcredinfo.starttime.time = credential.times.starttime
                krbcredinfo.endtime.time = credential.times.endtime
                krbcredinfo.renew_till.time = credential.times.renew_till
                krbcredinfo.srealm.server_realm = credential.server.realm.data
                # print(credential.server.realm.data)
                krbcredinfo.sname.server_components = credential.server.components
                for c in credential.server.components:  # dirty hack
                    if c not in ['krbtgt', 'krb5_ccache_conf_data', 'pa_type']:
                        out.append(c)
                name = b"-".join(out[-2:])
                krbcredinfo.sname.server_name_type = credential.server.name_type
                krbcredinfo.createkrbcrdinfo()
                sys.stdout.write("%s:$krb5tgs$%s$%s$%s\n" % (name, etype, data[:16].encode("hex"), data[16:].encode("hex")))
                """
                # Write seperate files for each ticket found. postfix is just a number for now.
                with open(sys.argv[2] + "_" + str(i), 'wb') as o:
                    o.write(KrbCred.tostring())
                i = i + 1
                """
            sys.exit(0)

        elif fileid == 0x76:  # untested code, don't use!
            f.seek(0)
            KrbCred = KrbCredHeader()
            KrbCred.parsefile(f)

            header = CCacheHeader()
            primary_principal = Principal()
            credential = Credential()

            header.version = 0x504
            header.header_length = 0xC
            header.header.deltatime.time_offset = 4294967295
            header.header.deltatime.usec_offset = 0
            header.header.tag = 0x01
            header.header.taglen = 0x08
            KrbCredInfo_ = KrbCred.ticketpart.encpart.krbcredinfo

            primary_principal.name_type = KrbCredInfo_.pname.principal_name_type
            primary_principal.components = KrbCredInfo_.pname.principal_components
            primary_principal.num_components = len(primary_principal.components)
            primary_principal.realm.data = KrbCredInfo.prealm.principal_realm
            primary_principal.realm.length = len(primary_principal.realm.data)

            credential.client.name_type = KrbCredInfo.pname.principal_name_type
            credential.client.components = KrbCredInfo.pname.principal_components
            credential.client.num_components = len(credential.client.components)
            credential.client.realm.data = KrbCredInfo.prealm.principal_realm
            credential.client.realm.length = len(credential.client.realm.data)

            credential.server.name_type = KrbCredInfo.sname.server_name_type
            credential.server.components = KrbCredInfo.sname.server_components
            credential.server.num_components = len(credential.server.components)
            credential.server.realm.data = KrbCredInfo.srealm.server_realm
            credential.server.realm.length = len(credential.server.realm.data)

            credential.keyblock.etype = KrbCred.ticketpart.encpart.etype
            credential.keyblock.key = KrbCredInfo.key.key
            credential.keyblock.keylen = len(credential.keyblock.key)
            credential.keyblock.keytype = KrbCredInfo.key.keytype

            credential.times.authtime = KrbCredInfo.starttime.time
            credential.times.starttime = KrbCredInfo.starttime.time
            credential.times.endtime = KrbCredInfo.endtime.time
            credential.times.renew_till = KrbCredInfo.renew_till.time

            credential.is_skey = 0

            credential.tktFlags = KrbCredInfo.flags.ticket_flags

            credential.num_address = 0
            credential.address = []

            credential.num_authdata = 0
            credential.authdata = []

            credential.ticket.data = KrbCred.ticketpart.ticket
            credential.ticket.length = len(credential.ticket.data)

            credential.secondticket.length = 0
            credential.secondticket.data = ''

            with open(sys.argv[2], 'wb') as o:
                o.write(header.tostring())
                o.write(primary_principal.tostring())
                o.write(credential.tostring())
                sys.exit(0)
        else:
            print('Unknown File Type!')
            sys.exit(0)
