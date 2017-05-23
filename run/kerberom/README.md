Kerberom
========

Kerberom is a tool aimed to retrieve ARC4-HMAC'ed encrypted Tickets Granting Service (TGS) of accounts having a Service Principal Name (SPN) within
an Active Directory.

These tickets are stored in a format supported by John The Ripper bleeding-jumbo (https://github.com/magnumripper/JohnTheRipper)
and hashcat (https://github.com/hashcat/hashcat).

Cracking these tickets gives you the associated accounts' password within the Active Directory.

**You do not need any third-party tools that are OS dependents (like mimikatz or PowerShell) and do not need privileged rights to use kerberom**

Author
------
- Jean-Christophe Delaunay, jean-christophe.delaunay (at) synacktiv.com

Greetings
---------
- meskal
- The amazing impacket (https://github.com/CoreSecurity/impacket)
- Sylvain Monne, sylvain (dot) monne (at) solucom (dot) fr

kerberom.py
-----------

Prerequisites in explicit authentication:
- A domain account (eventually its SID if NTLM authentication is disabled upon Kerberos) and its credentials
- The address of the Domain Controler (can be a FQDN or IP address)
- The FQDN of the domain
- (Eventually a list of SPN with format "samaccountname$spn", field "samaccountname" can be "unknown")

Tickets can be retrieved using NTLM authentication but also Kerberos (this one needs you to provide the account SID as you will have to use it to make up your PAC)
and providing password or hash (format "LM:NT") of the account used.

Prerequisites in implicit authentication (Windows only):
- Being in a user logged-on context
- The address of the Domain Controler (can be a FQDN or IP address)
- The FQDN of the domain
- (Eventually a list of SPN with format "samaccountname$spn", field "samaccountname" can be "unknown")

Install
-------
kerberom is a standalone script/binary

Compilation (Windows only):
--------------------------
HOW-TO is provided in bin/BUILD.md

The binary is generated using PyInstaller and a new AES256 encryption key is generated each time the binary is compiled. This is only to break anti-viruses' signature engine based on kerberom source code.

Known-bug
---------
Depending on your pyasn1 version, you may encounter parsing errors using explicit authentication.

Usage
-----
```
usage: kerberom.py [-h] [--implicit IMPLICIT] [-u USERNAME]
                   [-d DOMAINCONTROLERADDR] [-o OUTPUTFILE]
                   [-iK INPUT_TGT_FILE] [-p PASSWORD | --hash HASH] [-v]
                   [--delta DELTA] [-k USER_SID | -i INPUTFILE_SPN]

Tool to retrieve all accounts having an SPN and their TGS in arc4-hmac
encrypted blob. Output is ready-to-crack for John The Ripper 'krb5tgs' and
hashcat 13100 formats, by jean-christophe.delaunay <at> synacktiv.com

optional arguments:
  -h, --help            show this help message and exit
  --implicit IMPLICIT   use Windows implicit authentication mechanism. Format
                        is (FQDN/IP)_DomainController[:port]@FQDN_Domain. eg:
                        192.168.13.13:389@infra.kerberos.com
  -u USERNAME, --username USERNAME
                        format must be userName@DomainFQDN. eg:
                        fistouille@infra.kerberos.com
  -d DOMAINCONTROLERADDR, --domainControlerAddr DOMAINCONTROLERADDR
                        domain Controler FQDN. Can be an IP but ldap retrieval
                        through kerberos method will not work (-k)
  -o OUTPUTFILE, --outputfile OUTPUTFILE
                        outputfile where to store results and extracted
                        accounts having an SPN (to be used with '-i'
                        afterward)
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
