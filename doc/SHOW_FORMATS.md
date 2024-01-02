# SHOW FORMATS OPTION

This file tries to document `--show=formats` option (and a bit of
deprecated `--show=types`).

john loads hashes of one format from given hash files. john gives
hints about some other formats seen in the file. `--show=formats` will
try every line against every format (with a few exceptions) and show
formats that can load line independently for each line. It does not
mean that john can load all lines at the same time (in one session).


The exceptions:

- some dynamic formats are disabled in configuration file, they may be
  enabled temporarily specifying the format with `--format=` option
  with exact name,

- ad-hoc dynamic formats (except `dynamic=md5($p)`) are not checked
  even when hashes have respective format tags, ad-hoc format may be
  forced specifying the format with `--format=` option (e.g.
  `--format='dynamic=sha1(sha1($p))'`).


Basic uses include:

- manual and automatic investigation of a file with hashes, hash type
  identification,

- easier understanding of cases when john loads only a part of file,
  - but `--show=invalid` may be more convenient to use,

- help in automated matching of canonical hashes in .pot files with
  hashes in original form.


## Output and manual investigation

john with `--show=formats` will parse specified hash file and print
information about each line in JSON format. JSON format is simple and
almost readable.

Example: 2 descrypt hashes:
```
$ cat ab.pw
AAa6CzJlsalyo
BBODHXVAdtcmc
```

(`--format=descrypt` is specified to reduce output.)
```
$ ./JohnTheRipper/run/john --show=formats ab.pw --format=descrypt
[{"lineNo":1,"ciphertext":"AAa6CzJlsalyo","rowFormats":[{"label":"descrypt","prepareEqCiphertext":true,"canonHash":["AAa6CzJlsalyo"]}]},
{"lineNo":2,"ciphertext":"BBODHXVAdtcmc","rowFormats":[{"label":"descrypt","prepareEqCiphertext":true,"canonHash":["BBODHXVAdtcmc"]}]}]
```

Example: 1 descrypt hash and pretty printing:
```
$ cat a.pw
AAa6CzJlsalyo
```

With pretty printing by json_pp (it is a part of perl package (on Debian)):
```
$ john --show=formats a.pw | json_pp
[
   {
      "ciphertext" : "AAa6CzJlsalyo",
      "lineNo" : 1,
      "rowFormats" : [
         {
            "canonHash" : [
               "AAa6CzJlsalyo"
            ],
            "label" : "descrypt",
            "prepareEqCiphertext" : true
         },
         {
            "label" : "crypt",
            "prepareEqCiphertext" : true,
            "canonHash" : [
               "AAa6CzJlsalyo"
            ]
         }
      ]
   }
]
```

Or with one-liner in python:
```
$ john --show=formats a.pw | python -c 'import json, sys, pprint; pprint.pprint(json.load(sys.stdin))'
[{u'ciphertext': u'AAa6CzJlsalyo',
  u'lineNo': 1,
  u'rowFormats': [{u'canonHash': [u'AAa6CzJlsalyo'],
                   u'label': u'descrypt',
                   u'prepareEqCiphertext': True},
                  {u'canonHash': [u'AAa6CzJlsalyo'],
                   u'label': u'crypt',
                   u'prepareEqCiphertext': True}]}]
```

There is a list of dictionaries with information for each line.

A dictionary for line may contain such keys/fields:

- `lineNo` is the number of line in file starting from 1,
  - numbering is continuous among multiple files with hashes (it may
    be change in future versions),

- `login` is for login,
  - it may be absent if login is empty,
  - it may be absent if login is not specified and line is skipped,
  - it may contain dummy value `?` that john uses when login is not specified,

- `ciphertext` is for ciphertext as it is extracted from hash file,
  - it may be absent if ciphertext is empty (or was cut by john to be empty),

- `rowFormats` is a list for descriptions of john's formats that can
  load the line for cracking (see below),
  - it may be empty list if line was skipped or none of formats can parse it,

- `skipped` is to show that line is too short to be loaded by any
  format, so it is not passed to formats' checks at all,
  - the value does not represent reason, the reason is always the
    same: the hash is too short and none of formats can load it,
  - the value of this field is the origin of decision to skip, that's
    a label of branch in code that skipped the line (so you may check
    code in `loader.c`),

- `uid`, `gid`, `gecos`, `home`, `shell` are for additional
  information about user (provided in some formats of hash files),
  - they may be absent if they are empty,
  - some fields may be used for different purposes in some formats of
    hash files, john should handle it well (i.e. `uid` contains LM
    ciphertext in PWDUMP files),
  - `gecos`, `home`, `shell` may be absent also if they have dummy value `/`.


`rowFormats` field contains a list of dictionaries with results of
successful parsing of line by formats.

Each dictionary in `rowFormats` list may have the following keys/fields:

- `label` is the name of format that may be used for `--format=` option,

- `dynamic` is boolean value,
  - it is true if format uses engine for dynamic formats,
  - it is absent if it is false,

- `prepareEqCiphertext` is boolean value,
  - it is true if `prepare()` method of formats returned same
    ciphertext after processing (it may be interesting to developers
    of formats),
  - it is absent if it is false,

- `canonHash` is a list of strings containing ciphertext in canonical form,
  - cracked hashes are saved to .pot file in canonical form unless it
    is too long (see `truncated` field),
  - it may contain multiple values for some formats (e.g. full LM
    gives two independent halves),
  - canonical hash is almost unambiguous form of hash that allows john
    to load this hash with respective format without `--format=`
    option,
    - there may be a few exceptional formats that have canonical form
      that cannot be distinguished from other formats,
    - formats that are different implementations of same hash type
      have same canonical form usually (e.g. raw-md5 and
      raw-md5-opencl formats),

- `truncHash` is a list like `canonHash` but contains shorter hash
  that would be used instead of canonical hash in .pot file (see
  `truncated` field),

- `truncated` is boolean field that shows whether `canonHash` or
  `truncHash` is used for .pot file,
  - it is absent when `canonHash` would be used in .pot file,
  - it is true when `truncHash` would be used in .pot file,
  - it may be true, while certain hash is short enough to be saved in
    canonical form, there is no `truncHash` field in this case.


Example: a hash is transformed into canonical form and saved to .pot file.
```
$ cat 123456.pw
e10adc3949ba59abbe56e057f20f883e
```

```
$ john --format=raw-md5 123456.pw --show=formats
[{..."rowFormats":[{"label":"Raw-MD5",...,"canonHash":["$dynamic_0$e10adc3949ba59abbe56e057f20f883e"]}]}]
```

```
$ john --format=raw-md5 123456.pw --pot=123456.pot
[...]
123456           (?)
[...]
$ cat 123456.pot
$dynamic_0$e10adc3949ba59abbe56e057f20f883e:123456
```


Example: PWDUMP format and LM halves.
```
$ cat pwdump.pw
alogin:aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb:ccccccccccccccccdddddddddddddddd
```

(Output is reformatted and edited.)
```
$ john --show=formats pwdump.pw
[{"lineNo":1,"login":"alogin",
"ciphertext":"aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb",
"uid":"ccccccccccccccccdddddddddddddddd",
"rowFormats":[
  {"label":"LM","canonHash":["$LM$cccccccccccccccc","$LM$dddddddddddddddd"]},
  ...
  {"label":"NT","prepareEqCiphertext":true,"canonHash":["$NT$aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"]},
  ...
  {"label":"Snefru-128","prepareEqCiphertext":true,"canonHash":["$snefru$aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb"]},
...]}]
```

When PWDUMP format of file is identified, the third field (aka `uid`)
is used for full LM hash. With such line, it is not possible to load
`aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb` as LM, the hash should be extracted
onto a separate line manually.

Despite detection of PWDUMP format of file, `ciphertext` field may be
loaded by other with `--format=` option (except LM). 32 hex may be
loaded by a lot of formats (e.g. `Snefru-128` in the example).


## Interaction with other options

### `--users=`, `--groups=`, `--shells=`

`--users=`, `--groups=`, `--shells=` options affect work of
`--show=formats` but skipped lines will be reported anyway.

### `--format=`

Formats to be tried may be limited with `--format=` option.

- 1 exact format may be specified (e.g. `--format=raw-md5`),

  - a disabled dynamic format may be enabled this way for temporary
    use,

  - ad-hoc dynamic formats may be specified this way (e.g.
    `--format='sha512($s.sha512($p.$s).$p)'`, see doc/DYNAMIC ),

- multiple formats may be specified in `--format=` option
  (e.g. with wildcard `--format=*crypt`; see doc/OPTIONS ),

  - set of formats in john may differ between builds, so
    `--list=formats` with `--format=` may be used to check that
    formats are available and the problem is not specific to
    `--show=formats` (e.g. `--format=*-opencl` would fail when john is
    built without OpenCL support),

- other formats will not be checked and reported, it may be useful
  because `--show=formats` may be slow or produce too much output.


Example: choose a subset of formats (john is built without OpenCL).
```
$ john --format=mssql* --list=formats
mssql, mssql05, mssql12
$ john --format=*crypt --list=formats
descrypt, bsdicrypt, md5crypt, bcrypt, scrypt, adxcrypt, AxCrypt, BestCrypt,
sha1crypt, sha256crypt, sha512crypt, django-scrypt, Raw-SHA1-AxCrypt, crypt
```


Example: `--show=formats` fails due to lack of OpenCL formats, so we
check `--list=formats`.
```
$ john --format=*-opencl --list=formats
Unknown ciphertext format name requested
$ john --format=*-opencl --show=formats t.pw
Unknown ciphertext format name requested
```


## Automatic parsing of output

The whole output may be read as JSON easily (see example above with
a.pw and python).

It is possible to avoid reading of full output into memory for
sequential processing, because output is guaranteed to have one
dictionary for one input line on a single separate output line.

`rowFormats` field's value is a list always. Empty list means that
line cannot be loaded by any format.

Example: print `ciphertext` field and list of format name that can
load it, processing JSON line by line with python.
```
$ cat ab.pw
AAa6CzJlsalyo
BBODHXVAdtcmc
```

```
$ john --show=formats ab.pw | python -c '
> import json, sys
> for l in sys.stdin:
>     l = l.strip("[],\r\n")
>     d = json.loads(l)
>     fs = [ f["label"] for f in d["rowFormats"] ]
>     print(d["ciphertext"], fs)
> '
(u'AAa6CzJlsalyo', [u'descrypt', u'crypt'])
(u'BBODHXVAdtcmc', [u'descrypt', u'crypt'])
```
