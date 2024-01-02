# Eclipse mosquitto_password cracking

mosquitto2john.py is a helper script to allow you to convert Eclipse Mosquitto
passwd files into a John friendly format. The script takes a
[mosquitto_passwd file](https://mosquitto.org/man/mosquitto_passwd-1.html) as
its only required input.

## Usage

```
❯ mosquitto2john.py --help
usage: mosquitto2john.py [-h] [-hc] [passwd_file ...]

positional arguments:
  passwd_file     Path to the source mosquitto_passwd file(s).

optional arguments:
  -h, --help      show this help message and exit
  -hc, --hashcat  Convert hashes to hashcat friendly formats.

Find more Information:
    See doc/README-mosquitto.md for info/troubleshooting.
```

This script is intended to work in the classic something2john.py way, provide
mosquitto_passwd files and pipe the output into an outfile of your choosing:

```
❯ mosquitto2john.py mosquitto_passwd mosquitto_passwd_2 > mosquitto.hash
❯ john ./mosquitto.hash
[...SNIP...]
Session completed.
```
### Hashcat

The hashcat option converts the hashes to Hashcat friendly formats - mode 1710
for SHA512 and 12100 for pbkdf2-hmac-sha512 hashes. In the following example,
some SHA512 and pbkdf2-hmac-sha512 hashes have already been exported into
separate files according to their type:

```
❯ ls
sha512_hashes     HMAC_hashes
# Identify the SHA512 hashes by their format: HEX_DIGEST:HEX_SALT
❯ head -n 1 sha512_hashes
SOMELONGHEXDIGEST:SOMEHEXSALT
❯ hashcat -a 0 -m 1710 --hex-salt ./sha512_hashes [WORDLIST]
[... SNIP ...]
# Identify the HMAC hashes by a leading sha512: and following iteration count
# These also have base64 salt and digests
❯ head -n 1 HMAC_hashes
sha512:101:BaSe64SaLt:BaSe64DiGeSt==
❯ hashcat -a 0 -m 12100 ./HMAC_hashes [WORDLIST]
[... SNIP ...]
```

**Note** the *use of --hex-salt in mode 1710* this is required for successful
cracking.

## Troubleshooting

### No hashes loaded?

In certain older versions of JtR and only for the SHA512 format hashes
(dynamic_82), you may have problems autodetecting the hash format. You
can manually specify the format with *--format=dynamic_82 in this instance*:

```
# Peek at the format to spot the issue -  just after the username field
❯ head -n 1 ./mosquitto.hash
username:$dynamic_82$SOMELONGHASH$SOMESALT
# Now manually specify the dynamic_82 format
❯ john ./mosquitto.hash --format=dynamic_82
[...SNIP...]
Session completed.
```

### Mixed Hash Types?

The Eclipse mosquitto_passwd program might allow different hash varieties,
depending on the Version you're working against. In the rare case that this
could come up, the output can either be split into two (using, say grep), or
you can simply specify the hash format on the command line. In the following
example, hashes are stored in a single file and each format worked against
sequentially:

```
❯ ls
mosquitto_out
# Now crack one at a time because different hash modes
❯ john ./mosquitto_out --format=dynamic_82
[... SNIP ...]
Session completed.
❯ john ./mosquitto_out --format=pbkdf2-hmac-sha512
[... SNIP ...]
Session completed.
```

Similarly, if using Hashcat, we need to crack any mixed hash formats one
flavour at a time. The following is an equivalent example in Hashcat:

```
❯ ls
hcat_out_file
❯ hashcat -a 0 -m 1710 --hex-salt hcat_out_file [WORDLIST]
[... SNIP ...]
Hashfile 'hcat_out_file' on line 1 [...SNIP...]: Token length exception
[... SNIP ...]
❯ hashcat -a 0 -m 12100 hcat_out_file [WORDLIST]
[... SNIP ...]
Hashfile 'hcat_out_file' on line 2 [...SNIP...]: Token length exception
[... SNIP ...]
```
This time, a Token length exception is raised for the hashes whose format
doesn't match the current mode. Hashcat will continue to crack the valid
hashes just fine, but to avoid this,you may instead choose to split the two
formats into separate files. See the usage section for hashcat hash
identification.

Again, note the need to **specify --hex-salt** for the 1710 format hashes.

### Invalid input. Try removing ':' from username

You may see this error on (hopefully) rare occasions if the mosquitto_passwd
file itself  contains an error. Eclipse mention in one line of the
[mosquitto_passwd README](https://mosquitto.org/man/mosquitto_passwd-1.html)
that colons are a forbidden username character. Just because there's nothing
stopping this happening and it's not a huge warning, mosquitto2john looks out
for it and will tell you what to do if you have a non-conforming passwd file.

The simplest solution in this instance is to make a note of the username,
remove the colon and try your conversion again. Happy hacking.

## More info? Troubleshooting the Script itself?

See https://github.com/eclipse/mosquitto/search?q=pw_sha512_pbkdf2 for info
on HMAC formats. An equivalent search can be made for SHA512. This is the
information used to infer the valid hash formats.

Hashes have been assumed to always be of the format:
username:$[HASHNO][$ITER(HMAC ONLY)]$SALT$HASH
Where salt and hash are always B64 encoded and usernames SHOULD not include a
colon. Any usernames with a colon are out of spec, but possible, so we handle
by alerting the user and advising on manual management.
