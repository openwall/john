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

from socket import socket

from pyasn1.type.univ import Integer, Sequence, SequenceOf, OctetString, BitString, Boolean
from pyasn1.type.char import GeneralString
from pyasn1.type.useful import GeneralizedTime
from pyasn1.type.tag import Tag, tagClassContext, tagClassApplication, tagFormatSimple
from pyasn1.type.namedtype import NamedTypes, NamedType, OptionalNamedType
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode

from crypto import encrypt, decrypt, checksum, RC4_HMAC, RSA_MD5
from util import epoch2gt
from struct import pack, unpack

NT_UNKNOWN = 0
NT_PRINCIPAL = 1
NT_SRV_INST = 2
NT_SRV_HST = 3
NT_SRV_XHST = 4
NT_UID = 5
NT_X500_PRINCIPAL = 6
NT_SMTP_NAME = 7
NT_ENTERPRISE = 10


AD_IF_RELEVANT = 1
AD_WIN2K_PAC = 128


def _c(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n))

def _v(n, t):
    return t.clone(tagSet=t.tagSet + Tag(tagClassContext, tagFormatSimple, n), cloneValueFlag=True)

def application(n):
    return Sequence.tagSet + Tag(tagClassApplication, tagFormatSimple, n)

class Microseconds(Integer): pass

class KerberosString(GeneralString): pass

class Realm(KerberosString): pass

class PrincipalName(Sequence):
    componentType = NamedTypes(
        NamedType('name-type', _c(0, Integer())),
        NamedType('name-string', _c(1, SequenceOf(componentType=KerberosString()))))

class KerberosTime(GeneralizedTime): pass

class HostAddress(Sequence):
    componentType = NamedTypes(
        NamedType('addr-type', _c(0, Integer())),
        NamedType('address', _c(1, OctetString())))

class HostAddresses(SequenceOf):
    componentType = HostAddress()

class AuthorizationData(SequenceOf):
    componentType = Sequence(componentType=NamedTypes(
            NamedType('ad-type', _c(0, Integer())),
            NamedType('ad-data', _c(1, OctetString()))))

class PAData(Sequence):
    componentType = NamedTypes(
        NamedType('padata-type', _c(1, Integer())),
        NamedType('padata-value', _c(2, OctetString())))

class KerberosFlags(BitString): pass

class EncryptedData(Sequence):
    componentType = NamedTypes(
        NamedType('etype', _c(0, Integer())),
        OptionalNamedType('kvno', _c(1, Integer())),
        NamedType('cipher', _c(2, OctetString())))

class EncryptionKey(Sequence):
    componentType = NamedTypes(
        NamedType('keytype', _c(0, Integer())),
        NamedType('keyvalue', _c(1, OctetString())))

class CheckSum(Sequence):
    componentType = NamedTypes(
        NamedType('cksumtype', _c(0, Integer())),
        NamedType('checksum', _c(1, OctetString())))

class Ticket(Sequence):
    tagSet = application(1)
    componentType = NamedTypes(
        NamedType('tkt-vno', _c(0, Integer())),
        NamedType('realm', _c(1, Realm())),
        NamedType('sname', _c(2, PrincipalName())),
        NamedType('enc-part', _c(3, EncryptedData())))

class APOptions(KerberosFlags): pass

class APReq(Sequence):
    tagSet = application(14)
    componentType = NamedTypes(
        NamedType('pvno', _c(0, Integer())),
        NamedType('msg-type', _c(1, Integer())),
        NamedType('ap-options', _c(2, APOptions())),
        NamedType('ticket', _c(3, Ticket())),
        NamedType('authenticator', _c(4, EncryptedData())))

class Authenticator(Sequence):
    tagSet = application(2)
    componentType = NamedTypes(
        NamedType('authenticator-vno', _c(0, Integer())),
        NamedType('crealm', _c(1, Realm())),
        NamedType('cname', _c(2, PrincipalName())),
        OptionalNamedType('cksum', _c(3, CheckSum())),
        NamedType('cusec', _c(4, Microseconds())),
        NamedType('ctime', _c(5, KerberosTime())),
        OptionalNamedType('subkey', _c(6, EncryptionKey())),
        OptionalNamedType('seq-number', _c(7, Integer())),
        OptionalNamedType('authorization-data', _c(8, AuthorizationData())))

class KDCOptions(KerberosFlags): pass

class KdcReqBody(Sequence):
    componentType = NamedTypes(
        NamedType('kdc-options', _c(0, KDCOptions())),
        OptionalNamedType('cname', _c(1, PrincipalName())),
        NamedType('realm', _c(2, Realm())),
        OptionalNamedType('sname', _c(3, PrincipalName())),
        OptionalNamedType('from', _c(4, KerberosTime())),
        NamedType('till', _c(5, KerberosTime())),
        OptionalNamedType('rtime', _c(6, KerberosTime())),
        NamedType('nonce', _c(7, Integer())),
        NamedType('etype', _c(8, SequenceOf(componentType=Integer()))),
        OptionalNamedType('addresses', _c(9, HostAddresses())),
        OptionalNamedType('enc-authorization-data', _c(10, EncryptedData())),
        OptionalNamedType('additional-tickets', _c(11, SequenceOf(componentType=Ticket()))))

class KdcReq(Sequence):
    componentType = NamedTypes(
        NamedType('pvno', _c(1, Integer())),
        NamedType('msg-type', _c(2, Integer())),
        NamedType('padata', _c(3, SequenceOf(componentType=PAData()))),
        NamedType('req-body', _c(4, KdcReqBody())))

class TicketFlags(KerberosFlags): pass

class AsReq(KdcReq):
    tagSet = application(10)

class TgsReq(KdcReq):
    tagSet = application(12)

class KdcRep(Sequence):
    componentType = NamedTypes(
        NamedType('pvno', _c(0, Integer())),
        NamedType('msg-type', _c(1, Integer())),
        OptionalNamedType('padata', _c(2, SequenceOf(componentType=PAData()))),
        NamedType('crealm', _c(3, Realm())),
        NamedType('cname', _c(4, PrincipalName())),
        NamedType('ticket', _c(5, Ticket())),
        NamedType('enc-part', _c(6, EncryptedData())))

class AsRep(KdcRep):
    tagSet = application(11)

class TgsRep(KdcRep):
    tagSet = application(13)

class LastReq(SequenceOf):
    componentType = Sequence(componentType=NamedTypes(
            NamedType('lr-type', _c(0, Integer())),
            NamedType('lr-value', _c(1, KerberosTime()))))

class PaEncTimestamp(EncryptedData): pass

class PaEncTsEnc(Sequence):
    componentType = NamedTypes(
        NamedType('patimestamp', _c(0, KerberosTime())),
        NamedType('pausec', _c(1, Microseconds())))

class EncKDCRepPart(Sequence):
    componentType = NamedTypes(
        NamedType('key', _c(0, EncryptionKey())),
        NamedType('last-req', _c(1, LastReq())),
        NamedType('nonce', _c(2, Integer())),
        OptionalNamedType('key-expiration', _c(3, KerberosTime())),
        NamedType('flags', _c(4, TicketFlags())),
        NamedType('authtime', _c(5, KerberosTime())),
        OptionalNamedType('starttime', _c(6, KerberosTime())),
        NamedType('endtime', _c(7, KerberosTime())),
        OptionalNamedType('renew-till', _c(8, KerberosTime())),
        NamedType('srealm', _c(9, Realm())),
        NamedType('sname', _c(10, PrincipalName())),
        OptionalNamedType('caddr', _c(11, HostAddresses())))

class EncASRepPart(EncKDCRepPart):
    tagSet = application(25)

class EncTGSRepPart(EncKDCRepPart):
    tagSet = application(26)

class TransitedEncoding(Sequence):
    componentType = NamedTypes(
        NamedType('tr-type', _c(0, Integer())),
        NamedType('contents', _c(1, OctetString())))

class EncTicketPart(Sequence):
    tagSet = application(3)
    componentType = NamedTypes(
        NamedType('flags', _c(0, TicketFlags())),
        NamedType('key', _c(1, EncryptionKey())),
        NamedType('crealm', _c(2, Realm())),
        NamedType('cname', _c(3, PrincipalName())),
        NamedType('transited', _c(4, TransitedEncoding())),
        NamedType('authtime', _c(5, KerberosTime())),
        OptionalNamedType('starttime', _c(6, KerberosTime())),
        NamedType('endtime', _c(7, KerberosTime())),
        OptionalNamedType('renew-till', _c(8, KerberosTime())),
        OptionalNamedType('caddr', _c(9, HostAddresses())),
        OptionalNamedType('authorization-data', _c(10, AuthorizationData())))

class KerbPaPacRequest(Sequence):
    componentType = NamedTypes(
        NamedType('include-pac', _c(0, Boolean())))

def build_req_body(realm, service, host, nonce, cname=None, authorization_data=None, etype=RC4_HMAC):
    req_body = KdcReqBody()

    # (Forwardable, Proxiable, Renewable, Canonicalize)
    req_body['kdc-options'] = "'01010000100000000000000000000000'B"

    if cname is not None:
        req_body['cname'] = None
        req_body['cname']
        req_body['cname']['name-type'] = NT_SRV_INST
        req_body['cname']['name-string'] = None
        req_body['cname']['name-string'][0] = cname

    req_body['realm'] = realm

    req_body['sname'] = None
    req_body['sname']['name-type'] = NT_SRV_INST
    req_body['sname']['name-string'] = None
    req_body['sname']['name-string'][0] = service
    req_body['sname']['name-string'][1] = realm
    if (host != ''):
        req_body['sname']['name-string'][1] = host
    #else:
    #    req_body['sname']['name-string'][1] = host
    #    req_body['sname']['name-string'][2] = realm

    req_body['from'] = '19700101000000Z'
    req_body['till'] = '19700101000000Z'
    req_body['rtime'] = '19700101000000Z'
    req_body['nonce'] = nonce

    req_body['etype'] = None
    req_body['etype'][0] = etype

    if authorization_data is not None:
        req_body['enc-authorization-data'] = None
        req_body['enc-authorization-data']['etype'] = authorization_data[0]
        req_body['enc-authorization-data']['cipher'] = authorization_data[1]

    return req_body

def build_authenticator(realm, name, chksum, subkey, current_time, authorization_data=None):
    auth = Authenticator()

    auth['authenticator-vno'] = 5

    auth['crealm'] = realm

    auth['cname'] = None
    auth['cname']['name-type'] = NT_PRINCIPAL
    auth['cname']['name-string'] = None
    auth['cname']['name-string'][0] = name

    auth['cksum'] = None
    auth['cksum']['cksumtype'] = chksum[0]
    auth['cksum']['checksum'] = chksum[1]

    gt, ms = epoch2gt(current_time, microseconds=True)
    auth['cusec'] = ms
    auth['ctime'] = gt

    auth['subkey'] = None
    auth['subkey']['keytype'] = subkey[0]
    auth['subkey']['keyvalue'] = subkey[1]

    if authorization_data is not None:
        auth['authorization-data'] = _v(8, authorization_data)

    return auth

def build_ap_req(ticket, key, msg_type, authenticator):
    enc_auth = encrypt(key[0], key[1], msg_type, encode(authenticator))

    ap_req = APReq()
    ap_req['pvno'] = 5
    ap_req['msg-type'] = 14
    ap_req['ap-options'] = "'00000000000000000000000000000000'B"
    ap_req['ticket'] = _v(3, ticket)

    ap_req['authenticator'] = None
    ap_req['authenticator']['etype'] = key[0]
    ap_req['authenticator']['cipher'] = enc_auth

    return ap_req

def build_tgs_req(target_realm, target_service, target_host,
                  user_realm, user_name, tgt, session_key, subkey,
                  nonce, current_time, authorization_data=None, pac_request=None):

    if authorization_data is not None:
        ad1 = AuthorizationData()
        ad1[0] = None
        ad1[0]['ad-type'] = authorization_data[0]
        ad1[0]['ad-data'] = authorization_data[1]
        ad = AuthorizationData()
        ad[0] = None
        ad[0]['ad-type'] = AD_IF_RELEVANT
        ad[0]['ad-data'] = encode(ad1)
        enc_ad = (subkey[0], encrypt(subkey[0], subkey[1], 5, encode(ad)))
    else:
        ad = None
        enc_ad = None

    req_body = build_req_body(target_realm, target_service, target_host, nonce, authorization_data=enc_ad)
    chksum = (RSA_MD5, checksum(RSA_MD5, encode(req_body)))

    authenticator = build_authenticator(user_realm, user_name, chksum, subkey, current_time)#, ad)
    ap_req = build_ap_req(tgt, session_key, 7, authenticator)

    tgs_req = TgsReq()
    tgs_req['pvno'] = 5
    tgs_req['msg-type'] = 12

    tgs_req['padata'] = None
    tgs_req['padata'][0] = None
    tgs_req['padata'][0]['padata-type'] = 1
    tgs_req['padata'][0]['padata-value'] = encode(ap_req)

    if pac_request is not None:
        pa_pac_request = KerbPaPacRequest()
        pa_pac_request['include-pac'] = pac_request
        tgs_req['padata'][1] = None
        tgs_req['padata'][1]['padata-type'] = 128
        tgs_req['padata'][1]['padata-value'] = encode(pa_pac_request)

    tgs_req['req-body'] = _v(4, req_body)

    return tgs_req

def build_pa_enc_timestamp(current_time, key):
    gt, ms = epoch2gt(current_time, microseconds=True)
    pa_ts_enc = PaEncTsEnc()
    pa_ts_enc['patimestamp'] = gt
    pa_ts_enc['pausec'] = ms

    pa_ts = PaEncTimestamp()
    pa_ts['etype'] = key[0]
    pa_ts['cipher'] = encrypt(key[0], key[1], 1, encode(pa_ts_enc))

    return pa_ts

def build_as_req(target_realm, user_name, key, current_time, nonce, pac_request=None):
    req_body = build_req_body(target_realm, 'krbtgt', '', nonce, cname=user_name)
    pa_ts = build_pa_enc_timestamp(current_time, key)

    as_req = AsReq()

    as_req['pvno'] = 5
    as_req['msg-type'] = 10

    as_req['padata'] = None
    as_req['padata'][0] = None
    as_req['padata'][0]['padata-type'] = 2
    as_req['padata'][0]['padata-value'] = encode(pa_ts)

    if pac_request is not None:
        pa_pac_request = KerbPaPacRequest()
        pa_pac_request['include-pac'] = pac_request
        as_req['padata'][1] = None
        as_req['padata'][1]['padata-type'] = 128
        as_req['padata'][1]['padata-value'] = encode(pa_pac_request)

    as_req['req-body'] = _v(4, req_body)

    return as_req

def send_req(req, kdc, port=88):
    data = encode(req)
    data = pack('>I', len(data)) + data
    sock = socket()
    sock.connect((kdc, port))
    sock.send(data)
    return sock

def recv_rep(sock):
    data = ''
    datalen = None
    while True:
        rep = sock.recv(8192)
        if not rep:
            sock.close()
            raise IOError('Connection error')
        data += rep
        if len(rep) >= 4:
            if datalen is None:
                datalen = unpack('>I', rep[:4])[0]
            if len(data) >= 4 + datalen:
                sock.close()
                return data[4:4 + datalen]

def _decrypt_rep(data, key, spec, enc_spec, msg_type):
    rep = decode(data, asn1Spec=spec)[0]
    rep_enc = str(rep['enc-part']['cipher'])
    #print rep_enc
    rep_enc = decrypt(key[0], key[1], msg_type, rep_enc)

    # MAGIC
    if rep_enc[:20] == '31337313373133731337':
        return rep_enc[20:22], None

    rep_enc = decode(rep_enc, asn1Spec=enc_spec)[0]

    return rep, rep_enc

def decrypt_tgs_rep(data, key):
    return _decrypt_rep(data, key, TgsRep(), EncTGSRepPart(), 9) # assume subkey

def _extract_data(data, spec):
    rep = decode(data, asn1Spec=spec)[0]

    return rep

#used in implicit authentication
def extract_tgs_data(data):
    return _extract_data(data, Ticket())

def decrypt_as_rep(data, key):
    return _decrypt_rep(data, key, AsRep(), EncASRepPart(), 8)

def decrypt_ticket_enc_part(ticket, key):
    ticket_enc = str(ticket['enc-part']['cipher'])
    ticket_enc = decrypt(key[0], key[1], 2, ticket_enc)
    return decode(ticket_enc, asn1Spec=EncTicketPart())[0]

def iter_authorization_data(ad):
    if ad is None:
        return
    for block in ad:
        yield block
        if block['ad-type'] == AD_IF_RELEVANT:
            for subblock in iter_authorization_data(decode(str(block['ad-data']), asn1Spec=AuthorizationData())[0]):
                yield subblock
