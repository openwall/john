# SHOW FORMATS OPTION

This file tries to document `--show=formats` option (and a bit of deprecated `--show=types`).

john loads hashes of one format from given hash files. john gives hints about some other formats seen in the file. `--show=formats` will try every line against every format and show formats that can load it independently. It does not mean that load all lines at the same time.

Basic uses include:
- manual investigation of a file with hashes, hash type identification,
- easier understanding of cases when john loads only a part of file,
- help in automated matching of canonical hashes in .pot files with hashes in original form.

## Output and manual investigation

john with `--show=formats` will parse specified hash file and print information about each line in JSON format. JSON format is simple and almost readable.

Example: 2 raw md5 hashes with `$dynamic_0$` format:
```
$ cat ab.pw
$dynamic_0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
$dynamic_0$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

(`--format=raw-md5` is specified to reduce output.)
```
$ john --show=formats ab.pw --format=raw-md5
[{"lineNo":1,"ciphertext":"$dynamic_0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","rowFormats":[{"label":"Raw-MD5","prepareEqCiphertext":true,"canonHash":["$dynamic_0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}]},
{"lineNo":2,"ciphertext":"$dynamic_0$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","rowFormats":[{"label":"Raw-MD5","prepareEqCiphertext":true,"canonHash":["$dynamic_0$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"]}]}]
```

Example: 1 raw md5 hash and pretty printing:
```
$ cat a.pw
$dynamic_0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```

(json_pp is a part of perl package (on Debian))
```
$ john --show=formats a.pw | json_pp
[
   {
      "lineNo" : 1,
      "rowFormats" : [
         {
            "label" : "Raw-MD5",
            "canonHash" : [
               "$dynamic_0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ],
            "prepareEqCiphertext" : true
         },
         {
            "dynamic" : true,
            "label" : "dynamic_0",
            "canonHash" : [
               "$dynamic_0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            ],
            "prepareEqCiphertext" : true
         }
      ],
      "ciphertext" : "$dynamic_0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
   }
]
```

Or with one-liner in python:
```
$ john --show=formats a.pw | python -c 'import json, sys, pprint; pprint.pprint(json.loads(sys.stdin.read()))'
[{u'ciphertext': u'$dynamic_0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  u'lineNo': 1,
  u'rowFormats': [{u'canonHash': [u'$dynamic_0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
                   u'label': u'Raw-MD5',
                   u'prepareEqCiphertext': True},
                  {u'canonHash': [u'$dynamic_0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'],
                   u'dynamic': True,
                   u'label': u'dynamic_0',
                   u'prepareEqCiphertext': True}]}]
```

There is a list of dictionaries with information for each line.

A dictionary for line may contain such keys/fields:
- "lineNo" is the number of line in file starting from 1,
  - numbering is continuous among multiple files with hashes (it may be change in future versions),
- "login" is for login,
  - it may be absent if login is empty,
  - it may be absent if login is not specified and line is skipped,
  - it may contain dummy value "?" that john uses when login is not specified,
- "ciphertext" is for ciphertext as it is extracted from hash file,
  - it may be absent if ciphertext is empty (or cut by john to be empty),
- "rowFormats" is a list for descriptions of john's formats that can load the line for cracking (see below),
  - it may be empty list if line was skipped or none of formats can parse it,
- "skipped" is to show that line is too short to be loaded by any format, so it is not passed to formats' checks at all,
  - the value does not represent reason, the reason is always the same: the hash is too short and none of formats can load it,
  - the value of this field is the origin of decision to skip, that's a label of branch in code that skipped the line (so you may check code in `loader.c`),
- "uid", "gid", "gecos", "home", "shell" are for additional information about user (provided in some formats of hash files),
  - they may be absent if they are empty,
  - "gecos", "home", "shell" may be absent also if they have dummy value "/".

"rowFormats" field contains a list of dictionaries with results of successful parsing of line by formats.

Each dictionary in "rowFormats" list may have the following field/keys:
- "label" is the name of format that may be used for `--format=` option,
- "dynamic" is boolean value,
  - it is true if format uses engine for dynamic formats,
  - it is absent if it is false,
- "prepareEqCiphertext" is boolean value,
  - it is true if `prepare()` method of formats returned same ciphertext after processing (it may be interesting to developers of formats),
  - it is absent if it is false,
- "canonHash" is a list containing ciphertext in canonical form,
  - it may contain multiple values for some formats of hash files (e.g. pwdump),
  - canonical hash is almost unambiguous form of hash that allows john to load this hash with respective format without `--format=` option,
    - there may be a few exceptional formats that have canonical form that cannot be distinguished from other formats,
    - formats that are different implementations of same hash type have same canonical form usually (e.g. raw-md5 and raw-md5-opencl formats),
  - cracked hashes are saved to .pot file in canonical form unless it is too long (see "truncated" field),
- "truncHash" is a list like "canonHash" but contains shorter hash that would be used instead of canonical hash in .pot file (see "truncated" field),
- "truncated" is boolean field that shows whether "canonHash" or "truncHash" is used for .pot file,
  - it is absent when "canonHash" would be used in .pot file,
  - it is true when "truncHash" would be used in .pot file,
  - it may be true, while certain hash is short enough to be saved in canonical form, there is no "truncHash" field in this case.

Example of hash transformation into canonical form:
```
$ cat 123456.pw
e10adc3949ba59abbe56e057f20f883e
```

```
$ john --format=raw-md5 123456.pw --show=formats
..."rowFormats":[{"label":"Raw-MD5",...,"canonHash":["$dynamic_0$e10adc3949ba59abbe56e057f20f883e"]}]}]
```

```
$ john --format=raw-md5 123456.pw --pot=123456.pot
[...]
123456           (?)
[...]
```

```
$ cat 123456.pot
$dynamic_0$e10adc3949ba59abbe56e057f20f883e:123456
```

## Interaction with other options

Formats to be tried may be limited with `--format=` option.
- 1 exact format may be specified (e.g. `--format=raw-md5`),
  - a disabled dynamic format may be enabled this way for temporary use,
- other formats will not be checked and reported, it may be useful because `--show=formats` may be slow.

`--users=`, `--groups=`, `--shells=` options affect work of `--show=formats` but skipped lines will be reported anyway.

## Automatic parsing of output

The whole output may be read as JSON easily (see example above with a.pw and python).

It is possible to avoid reading of full output into memory for sequential processing, because output is guaranteed to have one dictionary for one input line on a single separate output line.

```
$ cat ab.pw
$dynamic_0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
$dynamic_0$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
```

```
$ john --show=formats ab.pw | python -c '
> import json, sys
> for l in sys.stdin:
>     l = l.strip("[],\r\n")
>     d = json.loads(l)
>     fs = [ f["label"] for f in d["rowFormats"] ]
>     print(d.get("ciphertext", None), fs)
> '
(u'$dynamic_0$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', [u'Raw-MD5', u'dynamic_0'])
(u'$dynamic_0$bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', [u'Raw-MD5', u'dynamic_0'])
```
