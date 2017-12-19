This document is about cracking password protected BitLocker encrypted
volumes with JtR.

Step 1: Extract the hash
------------------------

In order to use the BitLocker-OpenCL format, you must produce a well-formatted
hash from your BitLocker encrypted image. Use the bitlocker2john tool to
extract hashes from password protected BitLocker encrypted volumes. It returns
four output hashes with different prefixes:

* If the device was encrypted using the User Password authentication method,
  bitlocker2john prints these two hashes:
  * $bitlocker$0$... : it starts the User Password fast attack mode
  * $bitlocker$1$... : it starts the User Password attack mode with MAC verification (slower execution, no false positives)

* In any case, bitlocker2john prints these two hashes:
  * $bitlocker$2$... : it starts the Recovery Password fast attack mode
  * $bitlocker$3$... : it starts the Recovery Password attack mode with MAC verification (slower execution, no false positives)

Hash extraction example,

$ ../run/bitlocker2john minimalistic.raw  # operate on a disk image
Signature found at 0x00010003
Version: 8
Invalid version, looking for a signature with valid version...
Signature found at 0x02110000
Version: 2 (Windows 7 or later)
VMK entry found at 0x021100b6
Key protector with user password found
minimalistic.raw:$bitlocker$0$16$e221443f32c419b74504ed51b0d66dbf$1048576$12$704e12c6c...

Instead of running bitlocker2john directly on BitLocker encrypted devices
(e.g. /dev/sdb1), you may use the dd command to create a disk image of a
device encrypted with BitLocker

$ sudo dd if=/dev/disk2 of=disk_image conv=noerror,sync
+4030464+0 records in
+4030464+0 records out
+2063597568 bytes transferred in 292.749849 secs (7049013 bytes/sec)

For further details about User Password and Recovery Password attacks, please
refer to the Wiki page: http://openwall.info/wiki/john/OpenCL-BitLocker.

Step 2: Attack!
---------------

Use the BitLocker-OpenCL format specifying the hash file:

$ ./john --format=bitlocker-opencl --wordlist=wordlist target_hash

Currently, this format is able to evaluate passwords having length between 8
(minimum password length) and 55 characters.

The mask you can use to generate Recovery Passwords is:

-mask=?d?d?d?d?d?d[-]?d?d?d?d?d?d[-]?d?d?d?d?d?d[-]?d?d?d?d?d?d[-]?d?d?d?d?d?d[-]?d?d?d?d?d?d[-]?d?d?d?d?d?d[-]?d?d?d?d?d?d

Links
-----

Samples BitLocker images for testing are available at,

* https://github.com/kholia/libbde/tree/bitlocker2john/samples
* https://github.com/e-ago/bitcracker/tree/master/Images

Samples of User Password/Recovery Passwords dictionaries are available at
https://github.com/e-ago/bitcracker/tree/master/Dictionary

More information on BitLocker cracking can be found at,

* http://openwall.info/wiki/john/OpenCL-BitLocker
* https://github.com/e-ago/bitcracker
