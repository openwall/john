Cracking PGP Desktop / OpenPGP / GnuPG private (secret) keys with john
======================================================================

1. Run gpg2john on PGP private key files (supports .skr files too!)

E.g. $ ../run/gpg2john openwall.sec.asc > hashes
E.g. $ ../run/gpg2john openwall.skr > hashes

Ensure that the input file to gpg2john contains a single private key.

2. Run john on the output of gpg2john.

E.g. $ ../run/john hashes
