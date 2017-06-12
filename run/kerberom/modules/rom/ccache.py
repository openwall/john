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

from collections import namedtuple
import struct
from struct import pack, unpack

from util import gt2epoch, bitstring2int
from krb5 import encode, Ticket, NT_PRINCIPAL

CCacheCredential = namedtuple('CCacheCredential', 'client server key time is_skey tktflags addrs authdata ticket second_ticket')
CCacheKeyblock = namedtuple('CCacheKeyblock', 'keytype etype keyvalue')
CCacheTimes = namedtuple('CCacheTimes', 'authtime starttime endtime renew_till')
CCacheAddress = namedtuple('CCacheAddress', 'addrtype addrdata')
CCacheAuthdata = namedtuple('CCacheAuthdata', 'authtype authdata')
CCachePrincipal = namedtuple('CCachePrincipal', 'name_type realm components')

VERSION = 0x0504
DEFAULT_HEADER = '00010008ffffffff00000000'.decode('hex')

class CCache(object):
    def __init__(self, primary_principal, credentials=[], header=DEFAULT_HEADER):
        if not isinstance(primary_principal, CCachePrincipal):
            if isinstance(primary_principal, basestring) and '@' in primary_principal:
                realm, user_name = primary_principal.split('@', 1)
            elif isinstance(primary_principal, tuple) and len(primary_principal) == 2:
                realm, user_name = primary_principal
            else:
                raise ValueError('Bad primary principal format: %r' % primary_principal)
            primary_principal = CCachePrincipal(NT_PRINCIPAL, realm, [user_name])

        self.primary_principal = primary_principal
        self.credentials = credentials
        self.header = header

    @classmethod
    def load(cls, filename):
        fp = open(filename, 'rb')
        version, headerlen = unpack('>HH', fp.read(4))
        if version != VERSION:
            raise ValueError('Unsupported version: 0x%04x' % version)
        header = fp.read(headerlen)
        primary_principal = cls.read_principal(fp)
        credentials = []
        while True:
            try:
                credentials.append(cls.read_credential(fp))
            except struct.error:
                break
        fp.close()
        return cls(primary_principal, credentials, header)

    def save(self, filename):
        fp = open(filename, 'wb')
        fp.write(pack('>HH', VERSION, len(self.header)))
        fp.write(self.header)
        self.write_principal(fp, self.primary_principal)
        for cred in self.credentials:
            self.write_credential(fp, cred)
        fp.close()

    def add_credential(self, newcred):
        for i in range(len(self.credentials)):
            if self.credentials[i].client == newcred.client and \
                    self.credentials[i].server == newcred.server:
                self.credentials[i] = newcred
                return
        self.credentials.append(newcred)

    @classmethod
    def read_string(cls, fp):
        length = unpack('>I', fp.read(4))[0]
        return fp.read(length)

    @classmethod
    def write_string(cls, fp, s):
        fp.write(pack('>I', len(s)))
        fp.write(s)

    @classmethod
    def read_principal(cls, fp):
        name_type, num_components = unpack('>II', fp.read(8))
        realm = cls.read_string(fp)
        components = [cls.read_string(fp) for i in range(num_components)]
        return CCachePrincipal(name_type, realm, components)

    @classmethod
    def write_principal(cls, fp, p):
        fp.write(pack('>II', p.name_type, len(p.components)))
        cls.write_string(fp, p.realm)
        for comp in p.components:
            cls.write_string(fp, comp)

    @classmethod
    def read_keyblock(cls, fp):
        keytype, etype, keylen = unpack('>HHH', fp.read(6))
        keyvalue = fp.read(keylen)
        return CCacheKeyblock(keytype, etype, keyvalue)

    @classmethod
    def write_keyblock(cls, fp, k):
        fp.write(pack('>HHH', k.keytype, k.etype, len(k.keyvalue)))
        fp.write(k.keyvalue)

    @classmethod
    def read_times(cls, fp):
        authtime, starttime, endtime, renew_till = unpack('>IIII', fp.read(16))
        return CCacheTimes(authtime, starttime, endtime, renew_till)

    @classmethod
    def write_times(cls, fp, t):
        fp.write(pack('>IIII', t.authtime, t.starttime, t.endtime, t.renew_till))

    @classmethod
    def read_address(cls, fp):
        addrtype = unpack('>H', fp.read(2))[0]
        addrdata = cls.read_string(fp)
        return CCacheAddress(addrtype, addrdata)

    @classmethod
    def write_address(cls, fp, a):
        fp.write(pack('>H', a.addrtype))
        cls.write_string(fp, a.addrdata)

    @classmethod
    def read_credential(cls, fp):
        client = cls.read_principal(fp)
        server = cls.read_principal(fp)
        key = cls.read_keyblock(fp)
        time = cls.read_times(fp)
        is_skey, tktflags, num_address = unpack('>BII', fp.read(9))
        addrs = [cls.read_address(fp) for i in range(num_address)]
        num_authdata = unpack('>I', fp.read(4))[0]
        authdata = [cls.read_authdata(fp) for i in range(num_authdata)]
        ticket = cls.read_string(fp)
        second_ticket = cls.read_string(fp)
        return CCacheCredential(client, server, key, time, is_skey, tktflags,
                                addrs, authdata, ticket, second_ticket)

    @classmethod
    def write_credential(cls, fp, c):
        cls.write_principal(fp, c.client)
        cls.write_principal(fp, c.server)
        cls.write_keyblock(fp, c.key)
        cls.write_times(fp, c.time)
        fp.write(pack('>BII', c.is_skey, c.tktflags, len(c.addrs)))
        for addr in c.addrs:
            cls.write_address(fp, addr)
        fp.write(pack('>I', len(c.authdata)))
        for authdata in c.authdata:
            cls.write_authdata(fp, authdata)
        cls.write_string(fp, c.ticket)
        cls.write_string(fp, c.second_ticket)

def get_tgt_cred(ccache):
    for credential in ccache.credentials:
        if credential.server.components[0] == 'krbtgt':
            return credential
    raise ValueError('No TGT in CCache!')

def kdc_rep2ccache(kdc_rep, kdc_rep_enc):
    return CCacheCredential(
        client=CCachePrincipal(
            name_type=int(kdc_rep['cname']['name-type']),
            realm=str(kdc_rep['crealm']),
            components=[str(c) for c in kdc_rep['cname']['name-string']]),
        server=CCachePrincipal(
            name_type=int(kdc_rep_enc['sname']['name-type']),
            realm=str(kdc_rep_enc['srealm']),
            components=[str(c) for c in kdc_rep_enc['sname']['name-string']]),
        key=CCacheKeyblock(
            keytype=int(kdc_rep_enc['key']['keytype']),
            etype=0,
            keyvalue=str(kdc_rep_enc['key']['keyvalue'])),
        time=CCacheTimes(
            authtime=gt2epoch(str(kdc_rep_enc['authtime'])),
            starttime=gt2epoch(str(kdc_rep_enc['starttime'])),
            endtime=gt2epoch(str(kdc_rep_enc['endtime'])),
            renew_till=gt2epoch(str(kdc_rep_enc['renew-till']))),
        is_skey=0,
        tktflags=bitstring2int(kdc_rep_enc['flags']),
        addrs=[],
        authdata=[],
        ticket=encode(kdc_rep['ticket'].clone(tagSet=Ticket.tagSet, cloneValueFlag=True)),
        second_ticket='')
