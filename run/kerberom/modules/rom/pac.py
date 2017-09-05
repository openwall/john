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

from struct import pack, unpack, unpack_from

from crypto import checksum, RSA_MD5
from util import filetime2local, epoch2filetime

PAC_LOGON_INFO = 1
PAC_SERVER_CHECKSUM = 6
PAC_PRIVSVR_CHECKSUM = 7
PAC_CLIENT_INFO = 10

PAC_TYPE_NAME = {PAC_LOGON_INFO: 'Logon information',
                 PAC_SERVER_CHECKSUM: 'Server checksum',
                 PAC_PRIVSVR_CHECKSUM: 'KDC checksum',
                 PAC_CLIENT_INFO: 'Client info'}

SE_GROUP_MANDATORY = 1
SE_GROUP_ENABLED_BY_DEFAULT = 2
SE_GROUP_ENABLED = 4
SE_GROUP_ALL = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED

USER_NORMAL_ACCOUNT = 0x00000010
USER_DONT_EXPIRE_PASSWORD = 0x00000200

def _build_unicode_string(buf, eid, s):
    buf.append('')
    buf[-1] += pack('QI', len(s), len(s))
    buf[-1] += s.encode('utf-16le')
    return pack('HHI', len(s) * 2, len(s) * 2, eid)

def _build_groups(buf, eid, groups):
    buf.append('')
    buf[-1] += pack('I', len(groups))
    for gr, attr in groups:
        buf[-1] += pack('II', gr, attr)
    return pack('I', eid)

def _build_sid(buf, eid, s):
    l = s.split('-')
    assert l[0] == 'S'
    l = [int(c) for c in l[1:]]
    buf.append('')
    buf[-1] += pack('IBB', len(l) - 2, l[0], len(l) - 2)
    buf[-1] += pack('>IH', l[1] >> 16, l[1] & 0xffff)
    for c in l[2:]:
        buf[-1] += pack('I', c)
    return pack('I', eid)

def _build_pac_logon_info(domain_sid, domain_name, user_id, user_name, logon_time):
    buf = []
    buf.append('')

    # ElementId
    buf[0] += pack('I', 0x20000)
    # LogonTime
    buf[0] += logon_time
    # LogoffTime
    buf[0] += pack('Q', 0x7fffffffffffffff)
    # KickOffTime
    buf[0] += pack('Q', 0x7fffffffffffffff)
    # PasswordLastSet
    buf[0] += pack('Q', 0)
    # PasswordCanChange
    buf[0] += pack('Q', 0)
    # PasswordMustChange
    buf[0] += pack('Q', 0x7fffffffffffffff)
    # EffectiveName
    buf[0] += _build_unicode_string(buf, 0x20004, user_name)
    # FullName
    buf[0] += _build_unicode_string(buf, 0x20008, '')
    # LogonScript
    buf[0] += _build_unicode_string(buf, 0x2000c, '')
    # ProfilePath
    buf[0] += _build_unicode_string(buf, 0x20010, '')
    # HomeDirectory
    buf[0] += _build_unicode_string(buf, 0x20014, '')
    # HomeDirectoryDrive
    buf[0] += _build_unicode_string(buf, 0x20018, '')
    # LogonCount
    buf[0] += pack('H', 0)
    # BadPasswordCount
    buf[0] += pack('H', 0)
    # UserId
    buf[0] += pack('I', user_id)
    # PrimaryGroupId
    buf[0] += pack('I', 513)
    # GroupCount
    buf[0] += pack('I', 5)
    # GroupIds[0]
    buf[0] += _build_groups(buf, 0x2001c, [(513, SE_GROUP_ALL),
                                           (512, SE_GROUP_ALL),
                                           (520, SE_GROUP_ALL),
                                           (518, SE_GROUP_ALL),
                                           (519, SE_GROUP_ALL)])
    # UserFlags
    buf[0] += pack('I', 0)
    # UserSessionKey
    buf[0] += pack('QQ', 0, 0)
    # LogonServer
    buf[0] += _build_unicode_string(buf, 0x20020, '')
    # LogonDomainName
    buf[0] += _build_unicode_string(buf, 0x20024, domain_name)
    # LogonDomainId
    buf[0] += _build_sid(buf, 0x20028, domain_sid)
    # Reserved1
    buf[0] += pack('Q', 0)
    # UserAccountControl
    buf[0] += pack('I', USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD)
    # SubAuthStatus
    buf[0] += pack('I', 0)
    # LastSuccessFulILogon
    buf[0] += pack('Q', 0)
    # LastFailedILogon
    buf[0] += pack('Q', 0)
    # FailedILogonCount
    buf[0] += pack('I', 0)
    # Reserved3
    buf[0] += pack('I', 0)
    # SidCount
    buf[0] += pack('I', 0)
    # ExtraSids
    buf[0] += pack('I', 0)
    # ResourceGroupDomainSid
    buf[0] += pack('I', 0)
    # ResourceGroupCount
    buf[0] += pack('I', 0)
    # ResourceGroupIds
    buf[0] += pack('I', 0)

    flattened = ''
    for s in buf:
        flattened += s
        flattened += chr(0) * ((len(s) + 3) / 4 * 4 - len(s))

    header = '01100800cccccccc'.decode('hex') # typeHeader
    header += pack('II', len(flattened), 0) # privateHeader

    return header + flattened

def _build_pac_client_info(user_name, logon_time):
    buf = ''

    # ClientId
    buf += logon_time
    # NameLength
    buf += pack('H', len(user_name) * 2)
    # Name
    buf += user_name.encode('utf-16le')

    return buf

def build_pac(user_realm, user_name, user_sid, logon_time, server_key=(RSA_MD5, None), kdc_key=(RSA_MD5, None)):
    logon_time = epoch2filetime(logon_time)
    domain_sid, user_id = user_sid.rsplit('-', 1)
    user_id = int(user_id)

    elements = []
    elements.append((PAC_LOGON_INFO, _build_pac_logon_info(domain_sid, user_realm, user_id, user_name, logon_time)))
    elements.append((PAC_CLIENT_INFO, _build_pac_client_info(user_name, logon_time)))
    elements.append((PAC_SERVER_CHECKSUM, pack('I', server_key[0]) + chr(0)*16))
    elements.append((PAC_PRIVSVR_CHECKSUM, pack('I', kdc_key[0]) + chr(0)*16))

    buf = ''
    # cBuffers
    buf += pack('I', len(elements))
    # Version
    buf += pack('I', 0)

    offset = 8 + len(elements) * 16
    for ultype, data in elements:
        # Buffers[i].ulType
        buf += pack('I', ultype)
        # Buffers[i].cbBufferSize
        buf += pack('I', len(data))
        # Buffers[0].Offset
        buf += pack('Q', offset)
        offset = (offset + len(data) + 7) / 8 * 8

    for ultype, data in elements:
        if ultype == PAC_SERVER_CHECKSUM:
            ch_offset1 = len(buf) + 4
        elif ultype == PAC_PRIVSVR_CHECKSUM:
            ch_offset2 = len(buf) + 4
        buf += data
        buf += chr(0) * ((len(data) + 7) / 8 * 8 - len(data))

    chksum1 = checksum(server_key[0], buf, server_key[1])
    chksum2 = checksum(kdc_key[0], chksum1, kdc_key[1])
    buf = buf[:ch_offset1] + chksum1 + buf[ch_offset1+len(chksum1):ch_offset2] + chksum2 + buf[ch_offset2+len(chksum2):]

    return buf

# very dirty...
def pretty_print_pac(pac):

    def ppstr(prefix, pac, k, k2):
        le, sz, ptr = unpack_from('HHI', pac, k)
        k += 8
        if ptr != 0:
            reserved, elements = unpack_from('QI', pac, k2)
            k2 += 12
            s = pac[k2:k2+le].decode('utf-16le')
            k2 += le
            print '%s[0x%08x] %s' % (prefix, ptr, s)
            k2 = (k2 + 3) / 4 * 4
        else:
            print prefix + '<NULL>'
        return k, k2

    def ppgrparr(prefix, pac, k, k2):
        ptr = unpack_from('I', pac, k)[0]
        k += 4
        if ptr != 0:
            le = unpack_from('I', pac, k2)[0]
            k2 += 4
            print '%s[0x%08x]' % (prefix, ptr)
            for i in range(le):
                print '        %d (Attributes: 0x%08x)' % unpack_from('II', pac, k2)
                k2 +=  8
        else:
            print prefix + '<NULL>'
        return k, k2

    def ppsid(prefix, pac, k, k2):
        ptr = unpack_from('I', pac, k)[0]
        k += 4
        if ptr != 0:
            elements, rev, sac = unpack_from('IBB', pac, k2)
            k2 += 6
            ia1, ia2 = unpack_from('>IH', pac, k2)
            k2 += 6
            ia = (ia1 << 16) | ia2
            sa = unpack_from('I' * sac, pac, k2)
            k2 += 4 * sac
            print '%s[0x%08x] S-%d-%d-%s' % (prefix, ptr, rev, ia, '-'.join(str(c) for c in sa))
        else:
            print prefix + '<NULL>'

        return k, k2

    i = 0
    print 'PACTYPE:'
    cbuffers = unpack_from('I', pac, i)[0]
    i += 4
    print '  cBuffers: %d' % cbuffers
    print '  Version: %d' % unpack_from('I', pac, i)
    i += 4
    bufs = []
    for j in range(cbuffers):
        ultype, bufsz, offset = unpack_from('IIQ', pac, i)
        i += 16
        print '  Buffers[%d]:' % j
        print '    ulType: %d (%s)' % (
            ultype, PAC_TYPE_NAME.get(ultype, 'UNKNOWN'))
        print '    cbBufferSize: %d' % bufsz
        print '    Offset: %d' % offset

        if ultype == PAC_LOGON_INFO:
            k = offset
            k2 = offset + 236
            print '      RPCHeader:'
            print '        Version: %d' % unpack_from('B', pac, k)
            k += 1
            print '        Endianness: %d' % unpack_from('B', pac, k)
            k += 1
            print '        CommonHeaderLength: %d' % unpack_from('H', pac, k)
            k += 2
            print '        Filler: 0x%08x' % unpack_from('I', pac, k)
            k += 4
            print '        ObjectBufferLength: %d' % unpack_from('I', pac, k)
            k += 4
            print '        Filler: 0x%08x' % unpack_from('I', pac, k)
            k += 4
            print '        ElementId: 0x%08x' % unpack_from('I', pac, k)
            k += 4
            print '      LogonTime: %s' % filetime2local(pac[k:k+8])
            k += 8
            print '      LogoffTime: %s' % filetime2local(pac[k:k+8])
            k += 8
            print '      KickOffTime: %s' % filetime2local(pac[k:k+8])
            k += 8
            print '      PasswordLastSet: %s' % filetime2local(pac[k:k+8])
            k += 8
            print '      PasswordCanChange: %s' % filetime2local(pac[k:k+8])
            k += 8
            print '      PasswordMustChange: %s' % filetime2local(pac[k:k+8])
            k += 8
            k, k2 = ppstr('      EffectiveName: ', pac, k, k2)
            k, k2 = ppstr('      FullName: ', pac, k, k2)
            k, k2 = ppstr('      LogonScript: ', pac, k, k2)
            k, k2 = ppstr('      ProfilePath: ', pac, k, k2)
            k, k2 = ppstr('      HomeDirectory: ', pac, k, k2)
            k, k2 = ppstr('      HomeDirectoryDrive: ', pac, k, k2)
            print '      LogonCount: %d' % unpack_from('H', pac, k)
            k += 2
            print '      BadPasswordCount: %d' % unpack_from('H', pac, k)
            k += 2
            print '      UserId: %d' % unpack_from('I', pac, k)
            k += 4
            print '      PrimaryGroupId: %d' % unpack_from('I', pac, k)
            k += 4
            print '      GroupCount: %d' % unpack_from('I', pac, k)
            k += 4
            k, k2 = ppgrparr('      GroupId: ', pac , k, k2)
            print '      UserFlags: 0x%08x' % unpack_from('I', pac, k)
            k += 4
            print '      UserSessionKey: 0x%016x 0x%016x' % unpack_from('QQ', pac, k)
            k += 16
            k, k2 = ppstr('      LogonServer: ', pac, k, k2)
            k, k2 = ppstr('      LogonDomainName: ', pac, k, k2)
            k, k2 = ppsid('      LogonDomainId: ', pac, k, k2)
            print '      Reserved1: %s' % filetime2local(pac[k:k+8])
            k += 8
            print '      UserAccountControl: 0x%08x' % unpack_from('I', pac, k)
            k += 4
            print '      SubAuthStatus: 0x%08x' % unpack_from('I', pac, k)
            k += 4
            print '      LastSuccessfulILogon: %s' % filetime2local(pac[k:k+8])
            k += 8
            print '      LastFailedILogon: %s' % filetime2local(pac[k:k+8])
            k += 8
            print '      FailedILogonCount: %d' % unpack_from('I', pac, k)
            k += 4
            print '      Reserved3: 0x%08x' % unpack_from('I', pac, k)
            k += 4
            print '      SidCount: %d' % unpack_from('I', pac, k)
            k += 4
            print '      ExtraSids: 0x%08x' % unpack_from('I', pac, k)
            k += 4
            k, k2 = ppsid('      ResourceGroupDomainSid: ', pac, k, k2)
            print '      ResourceGroupCount: %d' % unpack_from('I', pac, k)
            k += 4
            k, k2 = ppgrparr('      ResourceGroupIds: ', pac , k, k2)

        elif ultype == PAC_CLIENT_INFO:
            k = offset
            print '      ClientId: %s' % filetime2local(pac[k:k+8])
            k += 8
            name_len = unpack_from('H', pac, k)[0]
            k += 2
            print '      Name: %s' % pac[k:k + name_len].decode('utf-16le')

        elif ultype in (PAC_SERVER_CHECKSUM, PAC_PRIVSVR_CHECKSUM):
            print '     SignatureType: 0x%08x' % unpack_from('I', pac, offset)
            print '     Signature: %s' % pac[offset+4:offset+bufsz].encode('hex')
