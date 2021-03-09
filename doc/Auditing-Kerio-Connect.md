### Auditing Kerio Connect hashes with JtR

This document describes the process of auditing Kerio Connect hashes with JtR.


#### Extract the hashes from the database

On Linux, Kerio Connect stores hashes in the following files,

* /opt/kerio/mailserver/users.cfg
* /opt/kerio/mailserver/mailserver.cfg

Passwords can be stored in scrambled form or they can be stored in hashed
form.

These encrypted / hashed passwords strings can be extracted using the following commands,

```
$ cat users.cfg | sed -n 's/<variable name="Password">\([^<]*\)<\/variable>/\1/p' | tr -d " "
D3S:d1ca0cee090ba26a64869078fcc95e46a74b66447f662068
D3S:77b27f3742be6de9db01f240928f714f19470b4f1ff8f4cf
```

These are the scrambled password strings.

```
$ cat users.cfg | sed -n 's/<variable name="PasswordHistory">\([^<]*\)<\/variable>/\1/p' | tr -d " "
SHA:161c91ace6162991d4d73f24921c560622d6f0230c111ef27f4188cf
SHA:e2e9aa4757186ed5e8fdce538ce77b759298e2224f07c43f1d499533
```

These are the hashed passwords. Hashing is done using PKBDF2-HMAC-SHA1 with
10000 iterations.

#### A note about recovering scrambled password strings


The following script can be used to reverse these "D3S" scrambled password strings.

```python
#!/usr/bin/python3

import sys
from Crypto.Cipher import DES3  # pip install --user pycrypto

# Password unscrambler for Kerio Connect.
#
# Tested with kerio-connect-9.2.7-3949-linux-amd64.deb on Ubuntu 18.04 LTS 64-bit.
#
# root@xubuntu:/opt/kerio/mailserver# ls *.cfg
# cluster.cfg  mailserver.cfg  users.cfg
#
# The "users.cfg" file has the "D3S" scrambled password strings.
#
# Sample scrambled password strings with password 123456,
#
# D3S:3795d2bfad3b1a2abb53f8d6efdafc9ef0cdb947f0ff2757
# D3S:3ad3d43e853c12453c39d1f2cdfaf835f0cdb947f0ff2757
# D3S:3aec30b049f5ceddc7bdbbd8895dcaecf0cdb947f0ff2757
# D3S:32fc936ccfab2e3fc7bdbbd8895dcaecf0cdb947f0ff2757
# D3S:c36e4be2280fa230aa5d4a9de5aef11af0cdb947f0ff2757
#
# Password -> 1234567
#
# D3S:10b2f2db66669ef03c39d1f2cdfaf835824e3e787e1f3307
# D3S:7214614a6b3fc1932fd98c8404118268824e3e787e1f3307
#
# Password -> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (32x A)
#
# D3S:8742ddf7db1906c5d54ec948c500e587adfa4447eff8dc42adfa4447eff8dc42adfa4447eff8dc4298558bad76110b35
# D3S:2962f547d408925a8948beccd54c660aadfa4447eff8dc42adfa4447eff8dc42adfa4447eff8dc4298558bad76110b35
#
# Password -> openwall@123
#
# D3S:77b27f3742be6de9db01f240928f714f19470b4f1ff8f4cf
#
# Password -> openwall
#
# D3S:d1ca0cee090ba26a64869078fcc95e46a74b66447f662068

"""
Attach gdb to "mailserver" process.

(gdb) rbreak DES*

Thread 52 "mailserver" hit Breakpoint 66, 0x00007ffab7bdb2f0 in DES_set_key_unchecked () from /opt/kerio/mailserver/libktcrypto.so.1.0.0
(gdb) bt
#0  0x00007ffab7bdb2f0 in DES_set_key_unchecked () from /opt/kerio/mailserver/libktcrypto.so.1.0.0
#1  0x00007ffab7c54160 in des_ede3_init_key () from /opt/kerio/mailserver/libktcrypto.so.1.0.0
#2  0x00007ffab7c52c10 in EVP_CipherInit_ex () from /opt/kerio/mailserver/libktcrypto.so.1.0.0
#3  0x000000000153a735 in kerio::crypto::StreamCrypto::init() ()
#4  0x000000000153b5db in kerio::crypto::StreamCrypto::StreamCrypto(unsigned char*, int, unsigned char*, int, kerio::crypto::StreamCrypto::Cipher, kerio::crypto::StreamCrypto::CipherMode, kerio::crypto::StreamCrypto::EncDec, bool) ()
#5  0x000000000269a075 in kerio::tinydb::decryptPassword(std::string&, char const*, std::string const&, std::string const&) ()
#6  0x000000000269a543 in kerio::tinydb::unscramblePassword(std::string&, bool&, char const*, std::string const&, bool) ()
#7  0x000000000144abbd in kerio::mailserver::dataSwitch::TinydbUserVariablePassword::fillFromResult(kerio::mailserver::dataSwitch::User&, kerio::mailserver::dataSwitch::ColumnsHolder const&, tinydb_result_row const*, kerio::mailserver::dataSwitch::ResultCache&) const ()


Thread 44 "mailserver" hit Breakpoint 74, 0x00007ffab7bdbd60 in DES_ecb3_encrypt () from /opt/kerio/mailserver/libktcrypto.so.1.0.0
...

This call is important. It has the raw encrypted password data from the file.


Thread 46 "mailserver" hit Breakpoint 21, 0x000000000153a1e0 in kerio::crypto::StreamCrypto::getDES3Cipher() ()
(gdb)

(gdb) bt
#0  0x00007ffab7c54140 in des_ede3_init_key () from /opt/kerio/mailserver/libktcrypto.so.1.0.0
#1  0x00007ffab7c52c10 in EVP_CipherInit_ex () from /opt/kerio/mailserver/libktcrypto.so.1.0.0
#2  0x000000000153a735 in kerio::crypto::StreamCrypto::init() ()
#3  0x000000000153b5db in kerio::crypto::StreamCrypto::StreamCrypto(unsigned char*, int, unsigned char*, int, kerio::crypto::StreamCrypto::Cipher, kerio::crypto::StreamCrypto::CipherMode, kerio::crypto::StreamCrypto::EncDec, bool) ()
#4  0x000000000269a075 in kerio::tinydb::decryptPassword(std::string&, char const*, std::string const&, std::string const&) ()
#5  0x000000000269a543 in kerio::tinydb::unscramblePassword(std::string&, bool&, char const*, std::string const&, bool) ()
...

(gdb) x/24bx $rsi
0x7ffa736f5db0:	0x61	0xd0	0xe5	0x49	0x54	0x73	0x3b	0x80
0x7ffa736f5db8:	0x80	0x80	0x80	0x80	0x80	0x80	0x80	0x80
0x7ffa736f5dc0:	0x80	0x80	0x80	0x80	0x80	0x80	0x80	0x80

Function prototype is static int des_ede3_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)

man syscall

$ cat samples
D3S:3795d2bfad3b1a2abb53f8d6efdafc9ef0cdb947f0ff2757
D3S:3ad3d43e853c12453c39d1f2cdfaf835f0cdb947f0ff2757
D3S:3aec30b049f5ceddc7bdbbd8895dcaecf0cdb947f0ff2757
D3S:32fc936ccfab2e3fc7bdbbd8895dcaecf0cdb947f0ff2757
D3S:c36e4be2280fa230aa5d4a9de5aef11af0cdb947f0ff2757
D3S:10b2f2db66669ef03c39d1f2cdfaf835824e3e787e1f3307
D3S:7214614a6b3fc1932fd98c8404118268824e3e787e1f3307
D3S:8742ddf7db1906c5d54ec948c500e587adfa4447eff8dc42adfa4447eff8dc42adfa4447eff8dc4298558bad76110b35
D3S:2962f547d408925a8948beccd54c660aadfa4447eff8dc42adfa4447eff8dc42adfa4447eff8dc4298558bad76110b35
D3S:77b27f3742be6de9db01f240928f714f19470b4f1ff8f4cf
D3S:d1ca0cee090ba26a64869078fcc95e46a74b66447f662068

$ cat samples | python hack.py
123456
123456
123456
123456
123456
1234567
1234567
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
openwall@123
openwall
"""

key = "\x61\xd0\xe5\x49\x54\x73\x3b\x80" + "\x80\x80\x80\x80\x80\x80\x80\x80" + "\x80\x80\x80\x80\x80\x80\x80\x80"

des3 = DES3.new(key, DES3.MODE_ECB)

# Expected input line format -> D3S:d1ca0cee090ba26a64869078fcc95e46a74b66447f662068
for line in sys.stdin.readlines():
    out = ""
    line = line.rstrip()
    tag, data = line.split(":")
    if tag != "D3S":
        continue
    data = data.decode("hex")
    for i in range(1, len(data) // 8):
        chunk = data[8*i:8*(i+1)]
        output = des3.decrypt(chunk)
        if i == 1:
            out = out + output[2:]
        else:
            out = out + output
    if out:
        print(out)
```

Since the last two DES keys are the same, this 3DES EDE operation is equivalent
to a single DES encryption operation. We can simplify the decryption script as
follows,

```python
#!/usr/bin/python3

import sys
from Crypto.Cipher import DES  # pip install --user pycrypto

# Password unscrambler for Kerio Connect.

key = "\x61\xd0\xe5\x49\x54\x73\x3b\x80"

des = DES.new(key, DES.MODE_ECB)

# Expected input line format -> D3S:d1ca0cee090ba26a64869078fcc95e46a74b66447f662068
for line in sys.stdin.readlines():
    out = ""
    line = line.rstrip()
    tag, data = line.split(":")
    if tag != "D3S":
        continue
    data = data.decode("hex")
    for i in range(1, len(data) // 8):
        chunk = data[8*i:8*(i+1)]
        output = des.decrypt(chunk)
        if i == 1:
            out = out + output[2:]
        else:
            out = out + output
    if out:
        padding_length = ord(out[-1])
        if padding_length > 8:
            padding_length = 0
        print(out[:-padding_length])
```


#### Format the hashes

The native PBKDF2-HMAC-SHA1 hashes look like,


```
SHA:161c91ace6162991d4d73f24921c560622d6f0230c111ef27f4188cf
SHA:e2e9aa4757186ed5e8fdce538ce77b759298e2224f07c43f1d499533
```

These can be converted into JtR format using the following script,

```python
#!/usr/bin/python3

import sys

for line in sys.stdin:
    line = line.rstrip()
    tag, data = line.split(":")
    if tag != "SHA":
        continue
    salt = data[:16]
    hsh = data[16:]
    print "$pbkdf2-hmac-sha1$10000$%s$%s" % (salt, hsh)
```


#### Crack the hashes with JtR

```
$ cat hashes
$pbkdf2-hmac-sha1$10000$161c91ace6162991$d4d73f24921c560622d6f0230c111ef27f4188cf

$ ../run/john hashes
Using default input encoding: UTF-8
Loaded 1 password hash (PBKDF2-HMAC-SHA1 [PBKDF2-SHA1 256/256 AVX2 8x])
Cost 1 (iteration count) is 10000 for all loaded hashes
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
openwall         (?)
1g 0:00:00:00 DONE (2018-06-15 11:18) 100.0g/s 700.0p/s 700.0c/s 700.0C/s found..åbc
Use the "--show" option to display all of the cracked passwords reliably
Session complete
```
