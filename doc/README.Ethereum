Cracking Ethereum Geth/Mist/MyEtherWallet/Presale wallets
=========================================================

1. Run ethereum2john.py on .json wallet file(s).

E.g. $ ../run/ethereum2john.py ethwallet.json > hashes

2. Run john on the output of ethereum2john.py utility.

E.g. $ ../run/john hashes

3. Wait for the password(s) to get cracked.


To use a GPU for cracking run john as,

$ ../run/john --format=ethereum-opencl hashes  # for Ethereum wallets using PBKDF2

$ ../run/john --format=ethereum-presale-opencl hashes  # for Ethereum presale wallets
