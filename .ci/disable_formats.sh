#!/bin/bash -e

# There was a bug in echo -e in Travis
# TODO: we know these formats must be fixed (or removed)
echo '[Local:Disabled:Formats]' > ../run/john-local.conf
echo 'Raw-SHA512-free-opencl = Y' >> ../run/john-local.conf
echo 'XSHA512-free-opencl = Y' >> ../run/john-local.conf
echo 'gpg-opencl = Y' >> ../run/john-local.conf
echo 'KeePass-opencl = Y' >> ../run/john-local.conf

# These formats fail OpenCL CPU runtime
echo 'RAR-opencl = Y' >> ../run/john-local.conf

if [[ $(uname -m) == "aarch64" ]]; then
    # SunMD5 format crashes on ARM. macOS and Linux
    # See https://github.com/openwall/john/issues/5296
    echo 'sunmd5 = Y' >> ../run/john-local.conf
fi

# These formats run very slowly inside CI
# Time measures are from Intel CPU driver running inside Docker
echo 'ansible-opencl = Y' >> ../run/john-local.conf    # (282.202952 secs) PASS
echo 'bitlocker-opencl = Y' >> ../run/john-local.conf  # (146.356993 secs) PASS
echo 'bitwarden-opencl = Y' >> ../run/john-local.conf  # (275.649462 secs) PASS
echo 'ethereum-opencl = Y' >> ../run/john-local.conf   # (468.007940 secs) PASS
echo 'FVDE-opencl = Y' >> ../run/john-local.conf       # (184.908568 secs) PASS
echo 'lp-opencl = Y' >> ../run/john-local.conf         # (177.392942 secs) PASS
echo 'notes-opencl = Y' >> ../run/john-local.conf      # (179.212104 secs) PASS
echo 'PBKDF2-HMAC-SHA256-opencl = Y' >> ../run/john-local.conf  # (189.267312 secs) PASS

# Other interesting formats
# Testing: RAR5-opencl [PBKDF2-SHA256 OpenCL] (70.553782 secs) PASS
# Testing: ODF-opencl, OpenDocument Star/Libre/OpenOffice [PBKDF2-SHA1 BF/AES OpenCL] (97.022575 secs) PASS
# Testing: diskcryptor-opencl, DiskCryptor [PBKDF2-SHA512 OpenCL] (71.142642 secs) PASS
# Testing: diskcryptor-aes-opencl, DiskCryptor AES XTS (only) [PBKDF2-SHA512 AES OpenCL] (75.497302 secs) PASS
# Testing: EncFS-opencl [PBKDF2-SHA1 AES OpenCL] (82.412256 secs) PASS
# Testing: ethereum-presale-opencl, Ethereum Presale Wallet [PBKDF2-SHA256 AES Keccak OpenCL] (125.017417 secs) PASS
