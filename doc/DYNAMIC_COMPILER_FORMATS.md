# DYNAMIC COMPILER FORMATS

This file tries to document the various known hash formats built using the
dynamic compiler.

`run/dynamic.conf` contains documentation for Redmine, XenForo hash formats.

## Cracking OpenCart hashes

```
mysql> select * from oc_user;
+---------+---------------+----------+------------------------------------------+-----------+...
| user_id | user_group_id | username | password                                 | salt      |...
+---------+---------------+----------+------------------------------------------+-----------+...
|       1 |             1 | admin    | c15552d8ef39cc5ac827e3d6548621e24c161334 | eb3dfe5d9 |...
+---------+---------------+----------+------------------------------------------+-----------+...
1 row in set (0.00 sec)
```

```
$ cat wordlist
password123
openwall
admin
taty
```

```
$ cat OpenCart-sample-hash
c15552d8ef39cc5ac827e3d6548621e24c161334$eb3dfe5d9
```

```
$ ../run/john -form=dynamic='sha1($s.sha1($s.sha1($p)))' OpenCart-sample-hash -w=wordlist
Loaded 1 password hash (dynamic=sha1($s.sha1($s.sha1($p))) [128/128 SSE4.1 4x2])
Press 'q' or Ctrl-C to abort, almost any other key for status
openwall         (?)
...
Session completed
```

```
$ ../run/john -form=dynamic='sha1($s.sha1($s.sha1($p)))' --test  # Intel N2840 CPU
Benchmarking: dynamic=sha1($s.sha1($s.sha1($p))) [128/128 SSE4.1 4x1]... DONE
Many salts:	903840 c/s real, 922285 c/s virtual
Only one salt:	823200 c/s real, 857500 c/s virtual
```

```
$ cat hashes
9c59d3071ee8a6486cf12d54d339f3b783ce2dde$0ccc3a77c
d4d05b388a87e3055cc0ee109801cdca15e8d6d4$dbe8c88e5
fabaff2487d3fc85b0fec32af618f5e8dc19b905$1dab633e0

$ ../run/john -form=dynamic='sha1($s.sha1($s.sha1($p)))' hashes -w=wordlist
Loaded 1 password hash (dynamic=sha1($s.sha1($s.sha1($p))) [128/128 SSE4.1 4x2])
Press 'q' or Ctrl-C to abort, almost any other key for status
admin            (?)
taty             (?)
admin            (?)
```

## Cracking PunBB hashes

PunBB hashing algorithm is similar to Redmine but it uses a salt of length 12
instead of 32.

```
mysql> use punbb;
Database changed

mysql> select username, password, salt from users;
+----------+------------------------------------------+--------------+
| username | password                                 | salt         |
+----------+------------------------------------------+--------------+
| Guest    | Guest                                    | NULL         |
| admin    | 699fce08bf085fb80f5ae1f240cbbe720aa62278 | jxV9tvClmWz0 |
+----------+------------------------------------------+--------------+
2 rows in set (0.00 sec)
```

```
$ cat hashes
699fce08bf085fb80f5ae1f240cbbe720aa62278$jxV9tvClmWz0

$ cat wordlist
openwall
```

```
$ ../run/john -form=dynamic='sha1($s.sha1($p))' hashes -w=wordlist
Using default input encoding: UTF-8
Loaded 1 password hash (dynamic=sha1($s.sha1($p)) [256/256 AVX2 8x1])
...
openwall         (?)
```

TurnKey PunBB 14.0 (which comes with PunBB 1.4.3) was used for generating PunBB
hashes.

## Cracking JBoss AS 7.1 and EAP 6.4 hashes

This information is contributed by Davy Douhine (@ddouhine).

JBoss uses the `md5($u:<realm>:$p)` hashing scheme, and 'ManagementRealm' is
the default realm for new AS 7.1 installations.

Specifying the username in the input hashes is required as it is used as a salt
by the JBoss AS/EAP hashing scheme.


```
$ cat hashes
user:1c3470194afdc84b90a0781c5e4462fc
```

```
$ ../run/john -format='dynamic=md5($u.$c1.$p),c1=:ManagementRealm:' hashes
Loaded 1 password hash (dynamic=md5($u.$c1.$p) [256/256 AVX2 8x3])
...
test             (user)
```

JBoss hashes can be created by using the "add-user.sh" utility included with JBoss.

```
user@kali:~/jboss-as-7.1.1.Final/bin$ ./add-user.sh

What type of user do you wish to add?
 a) Management User (mgmt-users.properties)
 b) Application User (application-users.properties)
(a): a

Enter the details of the new user to add.
Realm (ManagementRealm) :
Username : user
Password :
Re-enter Password :
About to add user 'user' for realm 'ManagementRealm'
Is this correct yes/no? yes
Added user 'user' to file '~/jboss-as-7.1.1.Final/standalone/configuration/mgmt-users.properties'
Added user 'user' to file '~/jboss-as-7.1.1.Final/domain/configuration/mgmt-users.properties'
$ cat ~/jboss-as-7.1.1.Final/standalone/configuration/mgmt-users.properties
#
# Properties declaration of users for the realm 'ManagementRealm' which is the default realm
# for new AS 7.1 installations. Further authentication mechanism can be configured
# as part of the <management /> in standalone.xml.
#
# ...
#
# By default the properties realm expects the entries to be in the format: -
# username=HEX( MD5( username ':' realm ':' password))
#
# ...
#
# The following illustrates how an admin user could be defined, this
# is for illustration only and does not correspond to a usable password.
#
user=1c3470194afdc84b90a0781c5e4462fc
```

## Cracking AuthMe hashes

AuthMe is an authentication plugin used by Minecraft servers. AuthMe hashes are
stored in the following format,

```
$SHA$c7dedf5a36c4a343$05ae3239eee683872ef1cc9096777bf4b1a72a179709efc17d8bf1603b082065
```

To crack such hashes, remove the `$SHA$` signature and move the salt to the end
of the hash string. The resulting hash will thus become,

```
$ cat sample-hash
05ae3239eee683872ef1cc9096777bf4b1a72a179709efc17d8bf1603b082065$c7dedf5a36c4a343
```

```
$ cat wordlist
password123
openwall
admin
pantof
```

```
$ ../run/john -form=dynamic='sha256(sha256($p).$s)' sample-hash -w=wordlist
Using default input encoding: UTF-8
Loaded 1 password hash (dynamic=sha256(sha256($p).$s) [256/256 AVX2 8x])
Press 'q' or Ctrl-C to abort, almost any other key for status
pantof           (?)
Session completed
```

See `Sha256.java` from `https://github.com/AuthMe/AuthMeReloaded` for addtional details.

NOTE: The inbuilt `dynamic_65` format is a bit faster at cracking such hashes.

## Cracking ZooKeeper hashes

Specifying the username in the input ZooKeeper hashes is required as it is used
as a salt by the ZooKeeper hashing scheme.

```
$ cat hashes
super:UdxDQl4f9v5oITwcAsO9bmWgHSI=
```

```
$ ../run/john -form:dynamic='sha1_64($u.$c1.$p),c1=:' hashes
Loaded 1 password hash (dynamic=sha1_64($u.$c1.$p) [256/256 AVX2 8x1])
Press 'q' or Ctrl-C to abort, almost any other key for status
super123         (super)
1g 0:00:00:00 DONE 1/3 (2018-08-02 10:47) 100.0g/s 66300p/s 66300c/s 66300C/s Super69..super6666
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
