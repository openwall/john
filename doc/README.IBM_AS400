How to get & crack AS/400 hashes?

Assuming you have been granted access to an AS/400 server with *ALLOBJ and *SECADM privileges,
you will be able to download and crack the password hashes that are stored on the system to
assess password strength. Depending on the current setting of the QPWDLVL system value,
password hashes are stored in different formats on the AS/400:

QPWDLVL 0:
IBM DES hashes (supported by JtR with our 'as400-des' format plugin)
LM hashes (supported by default by JtR)
SHA1 uppercase hashes (supported by JtR with our 'as400-ssha1' format plugin)

QPWDLVL 1:
IBM DES hashes (supported by JtR with our 'as400-des' plugin)
SHA1 uppercase hashes (supported by JtR with our 'as400-ssha1' plugin)

QPWDLVL 2:
IBM DES hashes* (supported by JtR with our 'as400-des' plugin)
LM hashes** (supported by default by JtR)
SHA1 uppercase hashes*** (supported by JtR with our 'as400-ssha1' plugin)
SHA1 mixed case hashes (supported by JtR with our 'as400-ssha1' plugin)

QPWDLVL 3:
SHA1 uppercase hashes*** (supported by JtR with our 'as400-ssha1' plugin)
SHA1 mixed case hashes (supported by JtR with our 'as400-ssha1' plugin)

* Only if QPWDMAXLEN <=10
** Only if QPWDMAXLEN <=14
** Depending on password policy configuration

In this tutorial we describe how to extract and assess the strength of all these types
of hashes. Obviously, if LM hashes are available, you should go for these as these can be cracked very
efficiently by JtR or by using other programs and a rainbow table.
If LM hashes are not available, our 'as400-des' and 'as400-ssha1' plugins have you covered.

PREREQUISITES
In order to be able to grab and crack the hashes, you will need:
- the latest version of IBMiScanner (part of hack400tool), available on https://github.com/hackthelegacy/hack400tool
- the latest john the ripper jumbo release including our 'as400-des' and 'as400-ssha1' plugins.

LM hashes:
- Open IBMiScanner tool
- Provide at minimum: Username, Password, IP address/DNS name
- Click "Connect"
- From the list of available scans, select option 26: 'SECURITY: Get John the Ripper hashes (LM hash)'
- In the output directory, a file named 'lmhashes.txt' will be created.
- Copy the file to your John the Ripper 'run' directory
- Run john the ripper: john --format=LM {filename}
Enjoy the passwords :)

DES hashes:
- Open IBMiScanner tool
- Provide at minimum: Username, Password, IP address/DNS name
- Click "Connect"
- From the list of available scans, select option 29: 'SECURITY: Get John the Ripper hashes (DES)'
- In the output directory a file named 'DES-hashes.txt' will be created.
- Copy the file to your John the Ripper 'run' directory
- Run john the ripper: john --format=as400-des {filename}
Enjoy the passwords :)

SHA-1 hashes:
(Please note that this method is generic for both mixed and upper case)
- Open IBMiScanner tool
- Provide at minimum: Username, Password, IP address/DNS name
- Click "Connect"
- From the list of available scans, select option 27: 'SECURITY: Get John the Ripper hashes (SHA-1 hash uppercase)' for uppercase hashes.
- For mixed case hashes, you can choose for option 28: 'SECURITY: Get John the Ripper hashes SHA-1 hash mixed case)' respectively.
- In the output directory, a file named 'SHA-uc-hashes.txt' for uppercase hashes or 'SHA-mc-hashes.txt' for mixed case hashes will be created.
- Copy the file to your John the Ripper 'run' directory
- Run john the ripper: john --format=as400-ssha1 {filename}
Enjoy the passwords :)
Note: In case you used an older version of the IBMiscanner tool that outputs hashes in the format userid:hash, you can
use the ibmiscanner2john.py script to convert the file into a format that can be processed by JtR

http://hackthelegacy.org for more information and tooling.

The 'as400-ssha1' plugin was developed by Bart Kulach (@bartholozz) and Rob Schoemaker (@5up3rUs3r) with support of JimF (aka jfoug).
The 'as400-des' plugin was developed by Bart Kulach (@bartholozz) and Rob Schoemaker (@5up3rUs3r) with support of Dhiru Kholia.
The IBMiscanner tool is developed and maintained by Bart Kulach (@bartholozz).
