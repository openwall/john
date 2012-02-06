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
- work in single mode due to using large sets of password
- work with ATI and a remote console if you haven't a X running and 
  DISPLAY env variable correctly setted (see http://goo.gl/4L8Tt for
  more information )
   

====================
COMPILING:
====================

Ati/AMD suggest you to use ATISTREAMSDKROOT env variable to
provide where you have installed their SDK root, while nvidia
simply install it in /usr/local/nvidia .

Makefile assume you have either /usr/local/nvidia either 
$ATISTREAMSDKROOT 

do a 

#updatedb && locate CL/cl.h && locate libOpenCL.so 

to locate your path to the includes and libOpenCL .
Adapt the Makefile to your needs and feel free to drop
an email to john-users@lists.openwall.com with your changes.



====================
USAGE:
====================

You can use john with your favourite options and the relative
opencl format you need.

BEWARE! single mode doesn't work and won't work due to failing
in allocating memory; i strongly recommend using opencl patch
in wordlist and incremental modes only.

On incremental mode


====================
CAVEATS:
====================

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
