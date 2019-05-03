[![Build Status](https://travis-ci.com/magnumripper/JohnTheRipper.svg?branch=bleeding-jumbo)](https://travis-ci.com/magnumripper/JohnTheRipper)
[![Circle CI](https://circleci.com/gh/magnumripper/JohnTheRipper/tree/bleeding-jumbo.svg?style=shield)](https://circleci.com/gh/magnumripper/JohnTheRipper/tree/bleeding-jumbo)
[![Downloads](https://img.shields.io/badge/Download-Windows%20Build-blue.svg)](https://rebrand.ly/JtRWin64)
[![License](https://img.shields.io/badge/License-GPL%20v2%2B-blue.svg)](https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/doc/LICENSE)
[![LoC](https://tokei.rs/b1/github/magnumripper/JohnTheRipper?category=code)](https://github.com/magnumripper/JohnTheRipper/tree/bleeding-jumbo)
[![Contributors](https://img.shields.io/github/contributors/magnumripper/JohnTheRipper.svg?label=Contributors)](https://github.com/magnumripper/JohnTheRipper/graphs/contributors)
[![Search hit](https://img.shields.io/github/search/magnumripper/JohnTheRipper/goto.svg?label=GitHub%20Hits)](https://github.com/search?utf8=%E2%9C%93&q=john%20the%20ripper&type=)

John the Ripper
====================

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

For contributions to John the Ripper Jumbo, please use a
[pull requested (PR) on GitHub](https://github.com/magnumripper/JohnTheRipper/blob/bleeding-jumbo/CONTRIBUTING.md).

---

	John the Ripper password cracker.

John the Ripper is a fast password cracker, currently available for
many flavors of Unix, macOS, Windows, DOS, BeOS, and OpenVMS (the latter
requires a contributed patch).  Its primary purpose is to detect weak
Unix passwords.  Besides several crypt(3) password hash types most
commonly found on various Unix flavors, supported out of the box are
Kerberos/AFS and Windows LM hashes, as well as DES-based tripcodes, plus
hundreds of additional hashes and ciphers in "-jumbo" versions.


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

"-jumbo" versions add support for hundreds of additional hash and cipher
types, including fast built-in implementations of SHA-crypt and SunMD5,
Windows NTLM (MD4-based) password hashes, various macOS and Mac OS X
user password hashes, fast hashes such as raw MD5, SHA-1, SHA-256, and
SHA-512 (which many "web applications" historically misuse for
passwords), various other "web application" password hashes, various SQL
and LDAP server password hashes, and lots of other hash types, as well
as many non-hashes such as SSH private keys, S/Key skeykeys files,
Kerberos TGTs, encrypted filesystems such as macOS .dmg files and
"sparse bundles", encrypted archives such as ZIP (classic PKZIP and
WinZip/AES), RAR, and 7z, encrypted document files such as PDF and
Microsoft Office's - and these are just some examples.  To load some of
these larger files for cracking, a corresponding bundled *2john program
should be used first, and then its output fed into JtR -jumbo.


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
* EXAMPLES - usage examples - strongly recommended
* MODES - cracking modes: what they are
* FAQ - frequently asked questions
* BUGS - list of known bugs
* DYNAMIC - how to use dynamic format in JtR
* DYNAMIC COMPILER FORMATS - List of known hash formats built using the dynamic compiler
* DYNAMIC_SCRIPTING - how to build/optimise a format that uses dynamic
* README.bash-completion - how to enable bash completion for JtR
* CONTACT (*) - how to contact the author or otherwise obtain support
* CONFIG (*) - how to customize
* EXTERNAL (*) - defining an external mode
* RULES (*) - wordlist rules syntax
* CHANGES (*) - history of changes
* CREDITS (*) - credits
* LICENSE - copyrights and licensing terms
* COPYING - GNU GPL version 2, as referenced by LICENSE above

(*) most users can safely skip these.

Happy reading!
