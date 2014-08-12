SecureMode
==========

Using JtR in enterprise environments as a strong password auditing and compliance
tool can be problematic as cracked passwords are visibly displayed (and
stored).

To get around this problem, we can use John the Ripper’s SecureMode feature for
auditing hashes in a "secure" fashion.

When this feature is enabled in john.conf (by setting SecureMode=Y), no cracked
password is ever printed, logged or stored in plaintext. Instead you get an
indication of length and use of classes. For example, the password "Ignit3"
would output as “L6-?l?d?u” telling you that the cracked password is six
characters long and consists of lowercase, digits and uppercase characters.

Usage
-----

```

$ cat hashes
dummyuser:$dummy$70617373776f7264

$ cat worst-passwords-top25-2013-SplashData.txt
123456
password
12345678
qwerty
abc123
123456789
111111
1234567
iloveyou
adobe123
123123
admin
1234567890
letmein
photoshop
1234
monkey
shadow
sunshine
12345
password1
princess
azerty
trustno1
000000

$ ../run/john -w=worst-passwords-top25-2013-SplashData.txt hashes
Loaded 1 password hash (dummy [N/A])
...
L8-?l            (dummyuser)

$ cat ../run/john.pot
$dummy$70617373776f7264:L8-?l

$ ../run/john --show hashes
dummyuser:L8-?l

1 password hash cracked, 0 left

```
