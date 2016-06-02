Kerberom
========

Kerberom is a tool aimed to retrieve ARC4-HMAC'ed encrypted Tickets Granting Service (TGS) of accounts having a Service Principal Name (SPN) within
an Active Directory.

These tickets are stored in a format supported by John The Ripper bleeding-jumbo (https://github.com/magnumripper/JohnTheRipper)
and hashcat (https://github.com/hashcat/oclHashcat).

Cracking these tickets gives you the associated accounts' password within the Active Directory.

**You do not need any third-party tools that are OS dependents (like mimikatz or PowerShell) and do not need privileged rights to use kerberom**


Author
------
- Fist0urs, eddy (dot) maaalou (at) gmail (dot) com

Greetings
---------
- meskal
- The amazing impacket (https://github.com/CoreSecurity/impacket)

kerberom.py
-----------

Prerequisites :
- A domain account (eventually its SID if NTLM authentication is disabled upon Kerberos)
- The address of the Domain Controler (can be a FQDN or IP address)
- The FQDN of the domain
- (Eventually a list of SPN with format "samaccountname$spn", field "samaccountname" can be "unknown")

Tickets can be retrieved using NTLM authentication but also Kerberos (this one needs you to provide the account SID as you will have to use it to make up your PAC)
and providing password or hash (format "LM:NT") of the account used.

Install
-------
kerberom is a standalone script, all you need is ldap3 (https://github.com/cannatag/ldap3), argparse and pyasn1 modules.


Usage
-----
```
usage: kerberom.py [-h] -u USERNAME -d DOMAINCONTROLERADDR [-o OUTPUTFILE]
                   [-iK INPUT_TGT_FILE] [-p PASSWORD | --hash HASH] [-v]
                   [--delta DELTA] [-k USER_SID | -i INPUTFILE_SPN]

Script to retrieve all accounts having an SPN and retrieving their TGS in
rc4-hmac encrypted blob in John The Ripper 'krb5tgs' format and hashcat's one,
by Fist0urs

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAME, --username USERNAME
                        format must be userName@DomainFQDN. eg:
                        fistouille@infra.kerberos.com
  -d DOMAINCONTROLERADDR, --domainControlerAddr DOMAINCONTROLERADDR
                        domain Controler FQDN. Can be an IP but ldap retrieval
                        through kerberos method will not work (-k)
  -o OUTPUTFILE, --outputfile OUTPUTFILE
                        outputfile where to store results
  -iK INPUT_TGT_FILE, --input_TGT_File INPUT_TGT_FILE
                        user's provided file containing TGT. Parsing is
                        determined by extension (.ccache for Linux , Windows
                        is yet to be implemented)
  -p PASSWORD, --password PASSWORD
                        clear password submitted. Cannot be used with '--hash'
  --hash HASH           user's hash key. Format is "LM:NT". Cannot be used
                        with '-p'
  -v, --verbose         increase verbosity level
  --delta DELTA         set time delta in Kerberos tickets. Useful when DC is
                        not on the same timezone. Format is
                        "(+/-)hours:minutes:seconds", eg. --delta="+00:05:00"
                        or --delta="-02:00:00"
  -k USER_SID, --user_sid USER_SID
                        force ldap SPN retrieval through kerberos, sid is
                        mandatory. Cannot be used with '-i'
  -i INPUTFILE_SPN, --inputfile_spn INPUTFILE_SPN
                        retrieve TGS associated with SPN in user's provided
                        file. Format must be 'samaccountname$spn' on each
                        line, 'samaccountname' can be 'unknown'
```

