IBM Lotus Domino hash extractor
===============================

It just reads the user.id file and extracts the ciphered blob at offset 0xD8
(16 bits word at offset 0xD6 is the blob size) and converts it to a hexadecimal
string to be used with the JtR plugin.

Usage
=====

1. Run lotus2john.py on Lotus Notes ID files

E.g. $ ../run/lotus2john openwall.id > hashes

2. Run john on the output of lotus2john.py utility

E.g. $ ../run/john hashes

Have fun :)
