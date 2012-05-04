Cracking Mozilla Firefox, Thunderbird and SeaMonkey master passwords
====================================================================

1. Install NSS library.

   a) On Ubuntu, do

   $ sudo apt-get install libnss3-dev libnspr4-dev

   b) On CentOS / RHEL / Fedora, do

   $ sudo yum install nss-devel

2. Un-comment HAVE_NSS line in src/Makefile and build JtR.

3. Run mozilla2john on key3.db file.

4. Run john on output of mozilla2john.

5. Wait for master password to get cracked.
