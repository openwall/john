This document is about cracking password protected FileVault 2 encrypted
volumes with JtR.

First, build the "fvde2john" (https://github.com/kholia/fvde2john) project from
source. See https://github.com/libyal/libfvde/wiki/Building for help.


Second, use the built fvde2john project to extract hash(es) from the encrypted
FileVault 2 volume.

$ tar -xJf fvde-1.raw.tar.xz  # sample image for testing, from fvde2john project

$ sudo kpartx -v -a fvde-1.raw
add map loop2p1 (253:5): 0 1048496 linear /dev/loop2 40

$ sudo fvdetools/fvdeinfo -p dummy /dev/mapper/loop2p1  # this extracts the hashes
fvdeinfo 20160918

$fvde$1$16$e7eebaabacaffe04dd33d22fd09e30e5$41000$e9acbb4bc6dafb74aadb72c576fecf69c2ad45ccd4776d76


Here is how to extract hashes without using kpartx,

$ fdisk -l fvde-2.raw
Disk fvde-2.raw: 512 MiB, 536870912 bytes, 1048576 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: gpt
Disk identifier: EBED216B-95C5-40D3-9C15-D352C8E9E357

Device      Start     End Sectors  Size Type
fvde-2.raw1    40 1048535 1048496  512M Apple Core storage

40 (Start) * 512 (Sector size) => 20480 => volume offset

$ ./fvdetools/fvdeinfo -o 20480 fvde-2.raw
fvdeinfo 20160918

$fvde$1$16$94c438acf87d68c2882d53aafaa4647d$70400$2deb811f803a68e5e1c4d63452f04e1cac4e5d259f2e2999
$fvde$1$16$94c438acf87d68c2882d53aafaa4647d$70400$2deb811f803a68e5e1c4d63452f04e1cac4e5d259f2e2999


Finally, give this hash string to JtR jumbo to crack.

$ cat hash
$fvde$1$16$e7eebaabacaffe04dd33d22fd09e30e5$41000$e9acbb4bc6dafb74aadb72c576fecf69c2ad45ccd4776d76

$ ../run/john hash -wordlist=wordlist
Using default input encoding: UTF-8
Loaded 1 password hash (FVDE, FileVault 2 [PBKDF2-SHA256 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
openwall         (?)


For more help with fvde2john, see the following URLs,

https://github.com/libyal/libfvde/wiki
https://github.com/libyal/libfvde/wiki/Troubleshooting
