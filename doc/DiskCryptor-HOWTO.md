#### Cracking DiskCryptor with JtR

Heres are steps to crack DiskCryptor encrypted partitions with JtR Jumbo.

1. Extract DiskCryptor hashes from DiskCryptor encrypted partitions.

   ```
   $ ../run/diskcryptor2john.py  # see program's help

   $ ../run/diskcryptor2john.py /dev/sdb1 >> hashes
   ```

   The `diskcryptor2john.py` program requires Linux to run. See step 2, in case
   you don't have Linux and want to get Linux going quickly.

2. (Optional) Install `SystemRescueCd` to a USB stick. Boot from this USB stick.

   - Get SystemRescueCd ISO image from http://www.system-rescue-cd.org/Download/ page.

   - Use [Rufus](https://rufus.ie) to `burn` this ISO image to a USB stick.

   - Boot a machine from this USB stick.

   - Some useful debugging commands -> `fdisk -l`, `dmesg`, `lspci`.

3. Run `john` on the extracted hashes.

   ```
   $ ../run/john hashes
   ```

   For taking advantage of GPU acceleration, use a command like,

   ```
   $ ../run/john --format=diskcryptor-opencl hashes
   ```

4. See the help files included with JtR Jumbo to customize your attacks.
