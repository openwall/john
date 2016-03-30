# DYNAMIC COMPILER FORMATS

This file tries to document the various known hash formats built using the
dynamic compiler.

`run/dynamic.conf` contains documentation for Redmine, XenForo hash formats.

TODO hash formats -> sha512(sha512($p).$s)  # XenForo SHA-512

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
