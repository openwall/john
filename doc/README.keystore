Cracking KeyStore files
======================

1. Run keystore2john.py on .jks file(s).

E.g. $ ../run/keystore2john.py <name>.jks > hash

2. Run john on the output of keystore2john.py utility.

E.g. $ ../run/john hash
     or, for the OpenCL version:
     $ ../run/john --format=keystore-opencl hash

3. Wait for the password to get cracked.
