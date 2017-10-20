Auditing Kerberos Hashes
========================

This is a brief guide to show the steps involved in auditing Kerberos hashes.

Dumping hashes from KDC
-----------------------

If you are running MIT Kerberos, ``kdb5_util`` utility can be used to dump
the hashes (in encrypted form).

```

$ sudo kdb5_util dump -b7 kdc.dump  # dump "encrypted" hashes

$ cp /etc/krb5kdc/stash stash  # grab the master key

```

In order to decrypt these encrypted hashes, we can use the ``hprop`` utility
which is a part of Heimdal. At least on Ubuntu (and Debian) boxes, installation
of Heimdal conflicts with MIT Kerberos, so we install Heimdal on an another
machine to get access to the ``hprop`` utility.

If you are running Heimdal, ``hprop`` should be able to dump the Kerberos
hashes in non-encrypted format by itself.

Decrypting the hashes
---------------------

Copy "kdc.dump" and "stash" to an another machine. On the another machine, use
``hprop`` to decrypt the data.

```
$ sudo aptitude install heimdal-kdc -y

$ hprop --database=kdc.dump --master-key=stash --source=mit-dump \
		--decrypt --stdout | hpropd -n --print
...
awfuluser@EXAMPLE.NET 1::18:03C95468D076C84FB3932804915C2CCF72A1E2571A....

We can extract EType 23 (rc4-hmac) hashes by running the following command,

$ hprop --database=kdc.dump --master-key=stash --source=mit-dump \
		--decrypt --stdout | hpropd -n --print | \
		grep -oP "23:\K(.+?)(?=:)"
32ED87BDB5FDC5E9CBA88547376818D4
...

$ echo "32ED87BDB5FDC5E9CBA88547376818D4" | tr '[:upper:]' '[:lower:]' > hash
```

Cracking the hashes
-------------------

```
$ cat hash
32ed87bdb5fdc5e9cba88547376818d4

$ ../run/john --format=krb5-23 ~/hash
Loaded 1 password hash (krb5-23, Kerberos 5 db etype 23 rc4-hmac [32/64])
Press 'q' or Ctrl-C to abort, almost any other key for status
123456           (?)
...

$ OMP_NUM_THREADS=4 ../run/john --format=krb5-23 --test
Will run 4 OpenMP threads
Benchmarking: krb5-23, Kerberos 5 db etype 23 rc4-hmac...
Raw:	8036K c/s real, 2060K c/s virtual
```

NOTE: Replace the removed `krb5-23` format with `nt` format in modern versions
of JtR.

```
$ ../run/john --format=nt ~/hash
Loaded 1 password hash (NT [MD4 256/256 AVX2 8x3])
123456           (?)
```

NOTE: Other Kerberos hashing schemes (i.e. aes128-cts-hmac-sha1-96, aes256-cts-hmac-sha1-96)
are handled by other JtR formats like `krb5-17` and `krb5-18`.

Setting up a Kerberos Server
----------------------------

If you would like to play with this stuff, here are the steps to quickly setup
a dummy Kerberos server.

```
$ cat /etc/lsb-release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=14.04
DISTRIB_CODENAME=trusty
DISTRIB_DESCRIPTION="Ubuntu 14.04 LTS"

$ hostname
kdc.example.net

$ cat /etc/host  # this is a virt-manager VM
...
192.168.122.10 kdc.example.net kdc ubuntu

$ sudo apt-get install krb5-{admin-server,kdc} -y

Default Kerberos version 5 realm? EXAMPLE.NET

Kerberos servers for your realm: kdc.example.net

Administrative server for your Kerberos realm: kdc.example.net

...

Running krb5_newrealm inside a VM can take a long time to complete (after
showing "Loading random data" message). You can use the following hack to
quicken things a bit.

$ sudo aptitude install rng-tools -y
$ sudo rngd -r /dev/urandom -o /dev/random  # don't do this in production!

$ sudo krb5_newrealm
...
Enter KDC database master key:

$ sudo vim /etc/krb5.conf  # append to "[domain_realm]" section,
.example.net = EXAMPLE.NET
example.net = EXAMPLE.NET

$ sudo vim /etc/krb5kdc/kadm5.acl  # Enable "*/admin *" line
...

$ sudo invoke-rc.d krb5-admin-server restart
$ sudo invoke-rc.d krb5-kdc restart

$ sudo kadmin.local
...
kadmin.local:  addprinc -policy admin root/admin

$ sudo kadmin -p root/admin
...
kadmin:  addprinc awfuluser
...
kadmin:  addprinc terribleuser
```

Notes
-----

* The stash file holds a key derived from the master password, but this
  derivation is intentionally difficult to reverse.

* http://www.math.cornell.edu/~gaarder/mit-samba-sync.html

* http://tools.ietf.org/html/draft-ietf-krb-wg-des-die-die-die-04
