Cracking LUKS passphrases
=========================

1. Run luks2john on a LUKS encrypted device or the output of
   cryptsetup luksHeaderBackup <device> --header-backup-file <file>

2. Run john on the output of luks2john

NOTES:

This version of John the Ripper supports cracking LUKS passphrases in a
very limited fashion.
The luks2john utility extracts just the information of one keyslot (the one
with the lowest iteration count), instead of extracting the information of
all used keyslots.
John's current LUKS hash representation has several drawbacks.
(Some information is stored more than once. The hash representation is
longer than it needs to be.)

For that reason, the LUKS hash representation used by this John the Ripper
version will most likely not be supported in future John the Ripper versions
which address the issues mentioned above.

That means, once a future John the Ripper release with full support for
cracking LUKS passphrases is released, you'll most likely need to re-run 
luks2john on the LUKS encrypted device or LUKS header backup, and you'll
need to re-run john so that the new LUKS hashes will be stored in your pot file.
(The passwords you found for the old LUKS hash representation will work
for the new LUKS hash representation.)
