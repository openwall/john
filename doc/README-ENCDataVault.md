Cracking ENCSecurity DataVault
==============================

1. Run encdatavault2john.py on vault folder.

```bash
$ ../run/encdatavault2john.py path/to/vault > hash
```

For Sandisk and Sony the script must be run in the "Settings" or "Vault" folders, for example,
"SanDiskSecureAccess Settings" or "SanDiskSecureAccess Vault".

2. Run john on the file.

```bash
$ ../run/john hash
```

The decryption test is done on a 32-bit magic value, meaning that occasional
false positives can occur. Cracked passwords for those false positives will not
decrypt the vault correctly.

The format using the key derivation algorithm based on MD5 has been tested on
Sony ENCDataVault lite 6.2.13, SanDisk SecureAccess 3.02 and ENC DataVault
7.1.1W. The format using PBKDF-SHA256 has been tested on PrivateAccess 6.3.6W
and ENCDataVault 7.2.1.

The first key derivation based on MD5 was replaced by Western Digital:
https://www.westerndigital.com/en-ap/support/product-security/wdc-21014-sandisk-secureaccess-software-update.
Their new solution is now called PrivateAccess:
https://kb.sandisk.com/app/answers/detail/a_id/21996/
