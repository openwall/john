### Testing JtR on BE (big endian) systems

Here are two options for testing JtR on BE (big endian) systems.

#### GCC Compile Farm account

It is possible to get access to a variety of hardware by applying for a GCC
Compile Farm account.

See https://gcc.gnu.org/wiki/CompileFarm for more information.

GCC Compile Farm has PPC64 hardware available which is a big endian architecture.

#### Local PPC64 Virtual Machine

1. Install QEMU package. Make sure that you have `qemu-system-ppc64` command available.

3. Download `debian-8.9.0-powerpc-CD-1.iso` from a Debian mirror.

2. Create the virtual hard disk image by running,

   ```
   qemu-img create -f qcow2 disk.qcow2 8G
   ```

3. Boot the downloaded ISO image, and install Debian by using the following script.

   ```
   #!/bin/sh
   common_args="-M pseries -cpu POWER8E -smp 4 -m 2G --accel tcg,thread=multi \
       -drive file=disk.qcow2,if=virtio,format=qcow2,index=0 \
       -netdev user,id=net0 -device e1000-82545em,netdev=net0,id=net0,mac=52:54:00:c8:19:17 \
       -redir tcp:2222::22"

   # qemu-system-ppc64 $common_args -cdrom debian-8.9.0-powerpc-CD-1.iso -boot d  # for installation

   qemu-system-ppc64 $common_args  # for normal use
   ```

   These instructions were tested with QEMU 2.10. I am not sure if the SMP
   acceleration is working well.

4. To enable Debian software repositories in the VM, modify `/etc/apt/sources.list` to include the following lines,

   ```
   deb http://mirrors.kernel.org/debian/ jessie main
   deb-src http://mirrors.kernel.org/debian/ jessie main

   deb http://security.debian.org/ jessie/updates main
   deb-src http://security.debian.org/ jessie/updates main
   ```

   Here is an alternate sources.list file, generated from https://debgen.simplylinux.ch/index.php?generate
   ```
   deb http://deb.debian.org/debian/ oldstable main contrib non-free
   deb-src http://deb.debian.org/debian/ oldstable main contrib non-free

   deb http://deb.debian.org/debian/ oldstable-updates main contrib non-free
   deb-src http://deb.debian.org/debian/ oldstable-updates main contrib non-free

   deb http://deb.debian.org/debian-security oldstable/updates main
   deb-src http://deb.debian.org/debian-security oldstable/updates main

   deb http://ftp.debian.org/debian jessie-backports main
   deb-src http://ftp.debian.org/debian jessie-backports main
   ```

   and then run `su -c "apt-get update"`.

5. Install the required software packages,

   ```
   $ su -c "apt-get install build-essential gdb ctags libssl-dev sudo vim git openssh-server gcc-multilib -y"

   ```

   Enable `sudo` for the local user.

   ```
   $ su -c "/usr/sbin/usermod -a -G sudo <username>"
   ```

   See `INSTALL-UBUNTU` file for more information on this topic.

6. SSH from the host machine to the VM machine by executing `ssh -p2222
   <username>@localhost`.

#### References

* https://gmplib.org/~tege/qemu.html

* https://en.wikibooks.org/wiki/QEMU/Networking

* https://people.debian.org/~aurel32/qemu/powerpc/ (old "wheezy" release)
