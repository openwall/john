====================
PRELUDE:
====================

You can use OpenCL if your video card - from now GPU - supports it.
ATI/AMD and Nvidia support it through their SDK available at
nvidia and ATI/AMD website.

Some recent distros have all (proprietry) stuff available as normal
packages. N.B. DON'T use X11 opensource drivers provided by your
distribution, only the vendor-supplied drivers support OpenCL. Either
install fglrx (for AMD) or nvidia dkms package or go directly with the
ones provided by nvidia and ATI.

You can also use OpenCL with CPU, mostly useful if you have several
(or loads of) cores. This sometimes outperforms the CPU-only formats
due to better scaling than OMP, or due to vectorizing. See Intel's
and AMD's web sites for drivers. Note that an Intel driver does
support AMD CPU's and vice versa.

This code is still experimental, try at your own risk. GPU should not
get overheated due to some protection in the hardware, however keep
an eye on temperatures (use "aticonfig -odgt" for AMD cards, or
"nvidia-smi" for nvidia cards).

This code has been tested on Linux, OSX and Windows, see doc/BUGS for
known issues.

OpenCL won't:
- improve your speed on very short runs (due to longer startup).
- work well in single mode due to using large sets of password (but some
  formats now handle this better by adopting work sizes).


====================
COMPILING:
====================

The new autoconf (./configure) should find your OpenCL installation and
enable it. If it doesn't, you may need to pass some parameters about where
it's located, eg.
    ./configure LDFLAGS=-L/opt/AMDAPP/lib CFLAGS=-I/opt/AMDAPP/include
    make -s

To build without OpenCL, use:
    ./configure --disable-opencl
    make -s

As a last resort, you can use the legacy Makefile:
    make -sf Makefile.legacy linux-x86-64-opencl


ATI/AMD suggest you to use ATISTREAMSDKROOT env variable to
provide where you have installed their SDK root.
nvidia simply install it in /usr/local/nvidia .

The legacy Makefile assumes you have $ATISTREAMSDKROOT set up to point
to your ATI installation or you have $NVIDIA_CUDA pointing to nvidia
installation.

If in doubt do a

# updatedb && locate CL/cl.h && locate libOpenCL.so

to locate your path to the includes and libOpenCL.

Adjust NVIDIA_CUDA or ATISTREAMSDKROOT to your needs and
if something is still wrong (but it shouldn't) send
an email to john-users@lists.openwall.com for help.


====================
USAGE:
====================

You can use john with your favourite options and the corresponding
OpenCL format you need.

For most OpenCL formats there are two environment variables you can adjust:
these are $LWS and $GWS.

LWS is the local work size, aka the number of "threads" the job
will be split and sent to the GPU.

- If $LWS is not set, john will try to get the one
  best for your system. On some slow hashes, a good default
  is going to be picked.

GWS is the Global Work Size. For non-vectorized format it is the same as
Keys Per Crypt, the number of keys that will be tried in a GPU call.
- If you unset GWS, john will use a default work size, which depends on
  what format is used.
- If GWS is set to 0 some formats will try to get the one best for
  your system, BEWARE it may take a couple of minutes.
- GWS is highly dependent on your PCI-E bandwidth rate which at the
  moment is one of the biggest bottlenecks for OpenCL in john.


Once you have found the best LWS or GWS for your system you can do

export LWS=NUM1
or
export GWS=NUM2

to avoid testing. Or set them for a one-off run like this:

$ LWS=64 GWS=8192 ./john -format=(...)

Warning! LWS and GWS are highly dependent on the format you are using.
LWS and GWS are not yet in every OpenCL format john is using.

- There's no check for LWS and GWS values so you should know how
  to set them to proper values, if in doubt just use the defaults
  and unset them.


====================
Optimization:
====================

- For most current cards, a good LWS is nearly always a multiple
  of 32.
- GWS must always be a multiple of LWS: you should always
  be able to divide GWS / LWS and get an integer number.


====================
Multi-device support
====================

Currently only mscash2-OpenCL support multiple devices by itself. However,
All other formats can use it together with MPI or the --fork option. For
example, let's say you have four GPU or accelerator cards in your local host:

$ ./john -fork=4 -dev=gpu,acc -format=(...)

The above will fork to four processes and each process will use a different
GPU or Accelerator device. The "-dev" option (--device) is likely needed
because it defaults to 'all' which may include unwanted devices. Instead
of -dev=gpu,acc (use all/any GPUs and accelerators) you could specify them
explicitly if needed, eg. -dev=0,1,5,6.

Or maybe you have two cards in a remote host called alpha and one card in
a host called bravo. Build with MPI support and use this variant of the above:

$ mpirun -host alpha,alpha,bravo ./john -dev=gpu,acc -format=(...)

The above will start two processes on alpha, using different GPUs, as well
as one process on bravo. In this case, the "-dev=gpu" option will be
enumerated on each host so if GPUs are devices 1 & 3 on alpha but device 0 on
bravo, that is not a problem.

If for some reason you want to run eg. two processes on each GPU, just double
the -fork argument or the MPI number of hosts (using -np option to mpirun).
The device list will round-robin.


====================
Supported formats:
====================

More information about supported hashes can be seen at:
http://openwall.info/wiki/john/GPU

Currently John the Ripper supports OpenCL enabled devices for
the following hashes:

agilekeychain-opencl       1Password Agile Keychain
bcrypt-opencl              bcrypt
blockchain-opencl          blockchain My Wallet
descrypt-opencl            traditional crypt(3)
dmg-opencl                 Apple DMG
encfs-opencl               EncFS
gpg-opencl                 OpenPGP / GnuPG Secret Key
grub-opencl                GRUB2 / OS X 10.8+
keychain-opencl            Mac OS X Keychain
keyring-opencl             GNOME Keyring
krb5pa-md5-opencl          Kerberos 5 AS-REQ Pre-Auth etype 23
krb5pa-sha1-opencl         Kerberos 5 AS-REQ Pre-Auth etype 17/18
md5crypt-opencl            crypt(3) $1$
mscash2-opencl             MS Cache Hash 2 (DCC2)
mysql-sha1-opencl          MySQL 4.1+
nt-opencl                  NT
ntlmv2-opencl              NTLMv2 C/R
o5logon-opencl             Oracle O5LOGON protocol w/ OpenCL SHA1
ODF-AES-opencl             Open Document Format (AES)
ODF-opencl                 Open Document Format (Blowfish)
office2007-opencl          MS Office 2007
office2010-opencl          MS Office 2010
office2013-opencl          MS Office 2013
PBKDF2-HMAC-SHA256-opencl
phpass-opencl              PHPass MD5
pwsafe-opencl              Password Safe
RAKP-opencl                IPMI 2.0 RAKP (RMCP+)
rar-opencl                 RAR3
Raw-MD4-opencl
Raw-MD5-opencl
Raw-SHA1-opencl
Raw-SHA256-opencl
Raw-SHA512-ng-opencl       (pwlen < 55)
Raw-SHA512-opencl
sha256crypt-opencl         crypt(3) $5$
sha512crypt-opencl         crypt(3) $6$
ssha-opencl                Netscape LDAP {SSHA}
strip-opencl               STRIP Password Manager
sxc-opencl                 StarOffice .sxc
wpapsk-opencl              WPA/WPA2 PSK
XSHA512-ng-opencl          Mac OS X 10.7 salted (pwlen < 55)
XSHA512-opencl             Mac OS X 10.7+
zip-opencl                 ZIP


==================
Vectorized formats
==================

A few formats will ask your device if it runs better vectorized,  and at what
width, and act accordingly.   A vectorized format runs faster on such devices
(notably CPUs,  depending on driver,  and pre-GCN AMD GPUs).  However, a side
effect might be register spilling which will just make it slower. If a format
defaults  to vectorizing,  --force-scalar  will disable it.  You can also set
ForceScalar = Y  in john.conf to disable it globally.

The following formats currently support such vectorizing:

encfs-opencl              EncFS
krb5pa-sha1-opencl        Kerberos 5 AS-REQ Pre-Auth etype 17/18
ntlmv2-opencl             NTLMv2 C/R
office2007-opencl         Office 2007
office2010-opencl         Office 2010
office2013-opencl         Office 2013
RAKP-opencl               IPMI 2.0 RAKP (RMCP+)
WPAPSK-opencl             WPA/WPA2 PSK

If/when a format runs vectorized, it will show algorithm name eg. as
[OpenCL 4x] as opposed to just [OpenCL].


=================
Watchdog Timer:
=================

If your GPU is also your active display device, a watchdog timer is enabled
by default, killing any kernel that runs for more than about five seconds
(nvidia) or two seconds (AMD). You will normally not get a proper error
message, just some kind of failure after five seconds or more, like:

  OpenCL error (CL_INVALID_COMMAND_QUEUE) in file (OpenCL_encfs_fmt.c) (...)

Our goal is to split such kernels into subkernels with shorter durations but
in the meantime (and especially if running slow kernels on weak devices) you
might need to disable this watchdog. For nvidia cards, you can check this
setting using "--list=OpenCL-devices". Example output:

    Platform version: OpenCL 1.1 CUDA 4.2.1
        Device #0 name:         GeForce GT 650M
        Device vendor:          NVIDIA Corporation
        Device type:            GPU (LE)
        Device version:         OpenCL 1.1 CUDA
        Driver version:         304.51
        Global Memory:          1023.10 MB
        Global Memory Cache:    32.0 KB
        Local Memory:           48.0 KB (Local)
        Max clock (MHz) :       900
        Max Work Group Size:    1024
        Parallel compute cores: 2
        Stream processors:      384  (2 x 192)
        Warp size:              32
        Max. GPRs/work-group:   65536
        Compute capability:     3.0 (sm_30)
        Kernel exec. timeout:   yes            <-- enabled watchdog

This particular output is not always available under OSX but you can get the
information using "--list=cuda-devices" instead, see doc/README-CUDA. We are
currently not aware of any way to disable this watchdog under OSX.  Under
Linux (and possibly other systems using X), you can disable it for nvidia
cards by adding the 'Option "Interactive"' line to /etc/X11/xorg.conf:

    Section "Device"
        Identifier     "Device0"
        Driver         "nvidia"
        VendorName     "NVIDIA Corporation"
        Option         "Interactive"        "False"
    EndSection

At this time we are not aware of any way to check or change this for AMD cards.
What we do know is that some old AMD drivers will crash after repeated runs of
as short durations as 200 ms, necessating a reboot. If this happens, just
upgrade your driver.


============================================================
Following is the verbatim original content of this file:
============================================================

This distribution of John the Ripper requires OpenCL to compile.

If you don't have OpenCL, download install and configure it before
proceeeding.

Any bugs, patches, comments or love letters should be sent to
samu@linuxasylum.net or jtr-dev mailing list.

Enjoy.
--
Samuele Giovanni Tonon <samu@linuxasylum.net>
