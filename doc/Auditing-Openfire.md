### Auditing Openfire hashes with JtR

This document describes the process to audit Openfire hashes.


#### Extract the hashes from the database

The various database schemas are described at the following link,

https://github.com/igniterealtime/Openfire/tree/master/src/database

For modern Openfire versions (4.x.y) using SCRAM hashing, columns named
`username`, `storedKey`, `serverKey` (unused), `salt` and `iterations` need to
be extracted from the `ofUser` table in the database. Here is what the `ofUser`
table looks like,


```
CREATE TABLE ofUser (
  username              VARCHAR(64),
  storedKey             VARCHAR(32),
  serverKey             VARCHAR(32),
  salt                  VARCHAR(32),
  iterations            INTEGER,
  plainPassword         VARCHAR(32),
  encryptedPassword     VARCHAR(255),
....
```

For older Openfire versions (3.x.y), the columns `username`, and
`encryptedPassword` need to be extracted. Note that there is no cracking /
brute-forcing involved in this case.

```
CREATE TABLE ofUser (
  username              VARCHAR(64)
  plainPassword         VARCHAR(32),
  encryptedPassword     VARCHAR(255)
```

The `encryptedPassword` value is the password which is encrypted using
Blowfish/AES. The encryption key can be recovered from the database by running
the `SELECT propValue from ofProperty where name = 'passwordKey'` query. See
`AuthFactory.java` and `Blowfish.java` in Openfire source code for more
details.


Openfire can also use various other hashing schemes. See `JDBCAuthProvider.java`
and `passwordType` in Openfire source code for more details. The `dynamic
compiler` feature of JtR can be quite useful when dealing with "chained hashes"
in Openfire.


#### Format the hashes

The hash format is `username:$xmpp-scram$0$iterations$length(salt)$salt-in-hex$%storedKey-in-hex` when SCRAM
hashing is being used by Openfire.

For a database row with data -> `('lulu','ruklR2KyOjlQ/XyAPKq19mVFh8g=','SUHs97B/HZJpfatHts1tVI3ALII=','vBvWY4oSMf/VT2CJg0JerPcp2EVaRpGX',4096)` the corresponding hash will be,

`lulu:$xmpp-scram$0$4096$24$bc1bd6638a1231ffd54f608983425eacf729d8455a469197$aee9254762b23a3950fd7c....`

Note: The `salt` and `storedKey` values need to be Base64 decoded first.


#### Crack the hashes with JtR

```
$ cat hashes
lulu:$xmpp-scram$0$4096$24$bc1bd6638a1231ffd54f608983425eacf729d8455a469197$aee9254762b23a3950fd7c803caab5f6654587c8
```

```
$ ../run/john hashes
Loaded 1 password hash (xmpp-scram [XMPP SCRAM PBKDF2-SHA1 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
openwall123      (lulu)
```
