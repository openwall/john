====================
PRELUDE:
====================

You can use OpenCL if your video Card - from now GPU - support it.
Ati/AMD and Nvidia support it through their SDK available at
nvidia and ati/amd website.

N.B. DON'T use X11 opensource drivers provided by your distribution,
either install fglrx or nvidia dkms package or go directly with the
ones provided by nvidia and ati.

This code is still highly experimental, therefore we suggest you
to try at your own risk.
GPU should not get overheated due to some limitation from the hardware
however keep checking your temperature .

This code has been tested on Linux, any chance it will work as it is
under other Operating System is due to a luck factor :-)

OpenCL patches have been lately introduced to add GPU support to john;
unfortunately, due to opencl design they shine when you have million
of password to test.

OpenCL won't:
- improve your speed if you have dictionary less then 1 000 000 words
- work well in single mode due to using large sets of password
- work with ATI and a remote console unser some certain condition
  (see http://goo.gl/4L8Tt for more information )
- make this world a better place


====================
COMPILING:
====================

Ati/AMD suggest you to use ATISTREAMSDKROOT env variable to
provide where you have installed their SDK root.
nvidia simply install it in /usr/local/nvidia .

Makefile assume you have $ATISTREAMSDKROOT setted up to point
to your ati installation or you have $NVIDIA_CUDA pointing to
nvidia installation.

In in doubt do a

#updatedb && locate CL/cl.h && locate libOpenCL.so

to locate your path to the includes and libOpenCL .

Adjust NVIDIA_CUDA or ATISTREAMSDKROOT to your needs and
if something is still wrong (but it shouldn't) send
an email to john-users@lists.openwall.com for help.



====================
USAGE:
====================

You can use john with your favourite options and the relative
opencl format you need.

BEWARE! single mode doesn't work and won't work due to failing
in allocating memory; i strongly recommend using opencl patch
in wordlist and incremental modes only.

On some opencl formats there are two variables you can adjust:
these are $LWS and $GWS

LWS is the local work size aka, the number of "threads" the job
will be split and sent to the GPU.

- if $LWS is not setted john will try to get the one
  best for your system. On some slow hashes, a good default
  is going to be picked.

GWS is the Global Work Size. For non-vectorized format it is the same as
Keys Per Crypt, the number of keys that will be tried in a GPU call.
- If you unset GWS, john will use a default work size, which depends on
  what format is used.
- if GWS is set to 0 john will try to get the one best for
  you system, BEWARE it will take a couple of minutes
- GWS is highly dependant on you PCI-E bandwith rate which at the
  moment is one of the biggest bottleneck for opencl in john


once you have found the best LWS or GWS for your system you can
do
export LWS=NUM1
or
export GWS=NUM2

to avoid testing.

Warning ! LWS and GWS are highly dependant on the format you are
using.
LWS and GWS are not yet in every opencl format john is using.

- There's no check for LWS and GWS values so you should now how
  to set them to properly values, if in doubt just use the defaults
  and unset them

====================
Optimization:
====================

if you plan on using opencl only for incremental mode (which at
the moment is the one that gives the fastest speed) it could be
a good idea to set up PLAINTEXT_LENGTH to a lower value than
32.

- LWS and GWS should be set with numbers that are power of two

- GWS should always be the possible product of LWS: you should always
  be able to divide GWS / LWS and get an integer number

====================
Supported formats:
====================

More information about supported hashes can be seen at:
http://openwall.info/wiki/john/GPU

Currently John the Ripper supports OpenCL enabled devices for
the following hashes:
- crypt MD5
- crypt SHA-512 (http://openwall.info/wiki/john/OpenCL-SHA-512)
- Mac OS X 10.7+ salted SHA-512
- MsCash2
- MySQL 4.1 double-SHA-1
- Netscape LDAP SSHA
- NT MD4
- phpass
- RAR3
- Raw MD4
- Raw MD5
- Raw SHA-1
- WPA-PSK

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
