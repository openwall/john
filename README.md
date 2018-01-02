## *John the Ripper* [![Build Status](https://travis-ci.org/magnumripper/JohnTheRipper.svg?branch=bleeding-jumbo)](https://travis-ci.org/magnumripper/JohnTheRipper) [![Circle CI](https://circleci.com/gh/magnumripper/JohnTheRipper/tree/bleeding-jumbo.svg?style=shield)](https://circleci.com/gh/magnumripper/JohnTheRipper/tree/bleeding-jumbo) [![Downloads](https://img.shields.io/badge/Download-Windows%20Build-green.svg)](http://daily-builds.appspot.com/latest) [![License](https://img.shields.io/badge/License-GPL%20v2%2B-blue.svg)](https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/doc/LICENSE)

This is a community-enhanced, "jumbo" version of John the Ripper.
It has a lot of code, documentation, and data contributed by the
user community.  This is not "official" John the Ripper code.  It is
very easy for new code to be added to jumbo: the quality requirements
are low.  This means that you get a lot of functionality that is not
"mature" enough or is otherwise inappropriate for the official JtR,
which in turn also means that bugs in this code are to be expected.

If you have any comments on this release or on JtR in general, please
join the john-users mailing list and post in there.

Licensing info:
http://openwall.info/wiki/john/licensing

How to contribute more code:
http://openwall.info/wiki/how-to-make-patches

---

	John the Ripper password cracker.

John the Ripper is a fast password cracker, currently available for
many flavors of Unix (11 are officially supported, not counting
different architectures), Windows, DOS, BeOS, and OpenVMS (the latter
requires a contributed patch).  Its primary purpose is to detect weak
Unix passwords.  Besides several crypt(3) password hash types most
commonly found on various Unix flavors, supported out of the box are
Kerberos/AFS and Windows LM hashes, as well as DES-based tripcodes, plus
many more hashes and ciphers in "community enhanced" -jumbo versions
and/or with other contributed patches.


	How to install.

See INSTALL for information on installing John on your system.


	How to use.

To run John, you need to supply it with some password files and
optionally specify a cracking mode, like this, using the default order
of modes and assuming that "passwd" is a copy of your password file:

	john passwd

or, to restrict it to the wordlist mode only, but permitting the use
of word mangling rules:

	john --wordlist=password.lst --rules passwd

Cracked passwords will be printed to the terminal and saved in the
file called $JOHN/john.pot (in the documentation and in the
configuration file for John, "$JOHN" refers to John's "home
directory"; which directory it really is depends on how you installed
John).  The $JOHN/john.pot file is also used to not load password
hashes that you already cracked when you run John the next time.

To retrieve the cracked passwords, run:

	john --show passwd

While cracking, you can press any key for status, or 'q' or Ctrl-C to
abort the session saving its state to a file ($JOHN/john.rec by
default).  If you press Ctrl-C for a second time before John had a
chance to complete handling of your first Ctrl-C, John will abort
immediately without saving.  By default, the state is also saved every
10 minutes to permit for recovery in case of a crash.

To continue an interrupted session, run:

	john --restore

These are just the most essential things you can do with John.  For
a complete list of command line options and for more complicated usage
examples you should refer to OPTIONS and EXAMPLES, respectively.

Please note that "binary" (pre-compiled) distributions of John may
include alternate executables instead of just "john".  You may need to
choose the executable that fits your system best, e.g. "john-omp" to
take advantage of multiple CPUs and/or CPU cores.


	Features and performance.

John the Ripper is designed to be both feature-rich and fast.  It
combines several cracking modes in one program and is fully
configurable for your particular needs (you can even define a custom
cracking mode using the built-in compiler supporting a subset of C).
Also, John is available for several different platforms which enables
you to use the same cracker everywhere (you can even continue a
cracking session which you started on another platform).

Out of the box, John supports (and autodetects) the following Unix
crypt(3) hash types: traditional DES-based, "bigcrypt", BSDI extended
DES-based, FreeBSD MD5-based (also used on Linux and in Cisco IOS), and
OpenBSD Blowfish-based (now also used on some Linux distributions and
supported by recent versions of Solaris).  Also supported out of the box
are Kerberos/AFS and Windows LM (DES-based) hashes, as well as DES-based
tripcodes.

When running on Linux distributions with glibc 2.7+, John 1.7.6+
additionally supports (and autodetects) SHA-crypt hashes (which are
actually used by recent versions of Fedora and Ubuntu), with optional
OpenMP parallelization (requires GCC 4.2+, needs to be explicitly
enabled at compile-time by uncommenting the proper OMPFLAGS line near
the beginning of the Makefile).

Similarly, when running on recent versions of Solaris, John 1.7.6+
supports and autodetects SHA-crypt and SunMD5 hashes, also with
optional OpenMP parallelization (requires GCC 4.2+ or recent Sun Studio,
needs to be explicitly enabled at compile-time by uncommenting the
proper OMPFLAGS line near the beginning of the Makefile and at runtime
by setting the OMP_NUM_THREADS environment variable to the desired
number of threads).

John the Ripper Pro adds support for Windows NTLM (MD4-based) and Mac
OS X 10.4+ salted SHA-1 hashes.

"Community enhanced" -jumbo versions add support for many more password
hash types, including Windows NTLM (MD4-based), Mac OS X 10.4-10.6
salted SHA-1 hashes, Mac OS X 10.7 salted SHA-512 hashes, raw MD5 and
SHA-1, arbitrary MD5-based "web application" password hash types, hashes
used by SQL database servers (MySQL, MS SQL, Oracle) and by some LDAP
servers, several hash types used on OpenVMS, password hashes of the
Eggdrop IRC bot, and lots of other hash types, as well as many
non-hashes such as OpenSSH private keys, S/Key skeykeys files, Kerberos
TGTs, PDF files, ZIP (classic PKZIP and WinZip/AES) and RAR archives.

Unlike older crackers, John normally does not use a crypt(3)-style
routine.  Instead, it has its own highly optimized modules for different
hash types and processor architectures.  Some of the algorithms used,
such as bitslice DES, couldn't have been implemented within the crypt(3)
API; they require a more powerful interface such as the one used in
John.  Additionally, there are assembly language routines for several
processor architectures, most importantly for x86-64 and x86 with SSE2.


        Graphical User Interface (GUI).

There is an official GUI for John the Ripper: Johnny.

Despite the fact that Johnny is oriented onto core john, all basic
functionality is supposed to work in all versions, even Jumbo. So,
password could be loaded from file and cracked with different
options.

Johnny is a separate program, therefore, you need to have John the
Ripper installed in order to use it.

You could find more info about releases and Johnny on the wiki:

  http://openwall.info/wiki/john/johnny


	Documentation.

The rest of documentation is located in separate files, listed here in
the recommended order of reading:

* INSTALL - installation instructions
* OPTIONS - command line options and additional utilities
* MODES - cracking modes: what they are
* CONFIG (*) - how to customize
* RULES (*) - wordlist rules syntax
* EXTERNAL (*) - defining an external mode
* EXAMPLES - usage examples - strongly recommended
* FAQ - guess
* CHANGES (*) - history of changes
* CONTACT (*) - how to contact the author or otherwise obtain support
* CREDITS (*) - credits
* BUGS - list of known bugs
* README.bash-completion - how to enable bash completion for JtR
* DYNAMIC - how to use dynamic format in JtR
* DYNAMIC COMPILER FORMATS - List of known hash formats built using the dynamic compiler
* DYNAMIC_SCRIPTING - how to build/optimise a format that uses dynamic
* HACKING - list of all possible hacks in John
* LICENSE - copyrights and licensing terms
* COPYING - GNU GPL version 2, as referenced by LICENSE above

The rest of documents in alphabetical:

* AddressSanitizer-HOWTO - Building JtR with AddressSanitizer (or ASan)
* Auditing-Openfire - Openfire hashes audit process
* AxCrypt-Auditing-HOWTO - auditing AxCrypt secrets
* DYNAMIC_EXPRESSIONS - 'self-describing' Dynamic format.
* dynamic_history - upto date history on dynamic_fmt.c file
* ENCODINGS - Encoding in the current John
* EXTERNAL - how to define external mode and available external mode functions
* HDAA_README - for HTTP Digest access authentication
* INSTALL-UBUNTU - Only for Ubuntu (Please read INSTALL for general installation information)
* john-1.7.9-jumbo-7-licensing-stats.txt - license status for john-1.7.9-jumbo-7
* Kerberos-Auditing-HOWTO - how to audit Kerberos hashes
* libFuzzer-HOWTO - how to build libfuzzer
* MARKOV - basic information/usage for the Markov mode
* MASK - Information on mask mode and examples
* NETNTLM_README - LM/NTLM Challenge / Response Authentication
* OFFICE - JtR on Office 2003 / 2007 / 2010 / 2013 files
* pass_gen.Manifest - pass_gen.pl version history
* pcap2john.readme - all the prior copyright headers from the independent XXX2john.py PCAP conversion utilities
* PRINCE - JtR prince mode crash course
* README.7z2john - 7z2 credit in JtR
* README.apex - dumping Oracle APEX...
* README.Apple_DMG - cracking DMG in JtR
* README.bitcoin - cracking bitcoin wallet files with JtR
* README.BitLocker - cracking bitlocker in JtR
* README.coding-style(*) - accepted coding style for contributors
* README.cprepair - reading broken files
* README-CUDA - JtR CUDA updates/status
* README-DISTROS - building a CPU-fallback chain (with OpenMP fallback too) for distros
* README.Ethereum - cracking etherum wallet in JtR
* README.FileVault2 - cracking password protected FileVault 2 encrypted volumes in JtR
* README.format-epi - how to dump EPiServer password hashes
* README.FreeBSD(*) - building JtR-jumbo on FreeBSD
* README.gpg - PGP Zip / OpenPGP / GnuPG private cracking in JtR
* README.IBM_AS400 - How to get & crack AS/400 hashes
* README.IOS 7 - cracking IOS 7 restrictions PIN code
* README.keychain - Cracking Apple's Mac OS Keychain files
* README.keyring - cracking GNOME Keyring files
* README.keystore - cracking KeyStore files
* README-krb5-18-23 - kdb5_util in JtR
* README.kwallet - cracking KWallet files
* README.librexgen - howto perform regex expression work within JtR
* README.LotusNotes - IBM Lotus Domino hash extractor
* README.LUKS - Cracking LUKS passphrases
* README-MIC - how to build JtR for MIC
* README.MinGW - Fedora >= 22 cross-compiling instructions
* README.mozilla - cracking Mozilla Firefox, Thunderbird and SeaMonkey master passwords
* README.mpi - using MPI in JtR
* README-OPENCL - how to use opencl in JtR
* README-PDF - PDF cracking in JtR
* README-PST - PST cracking in JtR
* README.pwsafe - cracking Password Safe 3.x and Password Gorilla databases with john
* README.ssh - Cracking password protected ssh private keys
* README-ZIP - ZIP cracking in JtR
* README-ZTEX - using ZTEX with JtR
* Regen-Lost-Salts - regen-lost-salt in JtR
* RULES-hashcat - wordlist rules with hashcat extension
* SecureMode-tutorial - using JtR's SecureMode feature
* SIPcrack-LICENSE - the SIPcrack license


(*) most users can safely skip these.

Happy reading!
