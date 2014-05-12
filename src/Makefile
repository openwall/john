#
# This file is part of John the Ripper password cracker,
# Copyright (c) 1996-2013 by Solar Designer
#
# ...with changes in the jumbo patch, by various authors
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted.
#
# There's ABSOLUTELY NO WARRANTY, express or implied.
#
# This file converted into autoconf format by Jim Fougeron and
# others, in 2014. That is still a work in progress.
#

SHELL = /bin/sh


subdirs = aes escrypt
top_srcdir = .
srcdir = .
prefix = /usr/local
exec_prefix = ${prefix}
bindir = $(exec_prefix)/bin
infodir = $(prefix)/info
libdir = $(prefix)/lib/gnudl
mandir = $(prefix)/man/man1

CC = gcc
CXX = g++
AS = gcc
LD = gcc
CPP = gcc
#INSTALL = @INSTALL@
# these are set lower. We may 'set them' initiall, and then we += this stuff.
# as we develop, and remove ALL of the self checking code and move it to configure,
# we will also move this code back to top, since it will be fully set from configure script.

CP = cp
CP_PRESERVE = cp -p
LN = ln -f -s
RM = rm -f
MKDIR = mkdir -p
TR = tr
SED = sed
NULL = /dev/null
SORT = sort
STRIP = strip

# CUDA settings. Instead of "-arch sm_10" you could use sm_20 or sm_30 or
# -gencode arch=compute_10,code=sm_10 -gencode arch=compute_20,code=sm_21
# but that leads to problems on GTX Titan.
# You could add "-gencode arch=compute_30,code=sm_30" too but that just
# leads to regressions for Kepler cards, when it works at all.
NVCC_FLAGS = -c -Xptxas -v -fmad=true -arch sm_10
CUDAPATH = /usr/local/cuda
NVCC = PATH=$(PATH):$(CUDAPATH)/bin/ nvcc
CCBIN_OSX = /usr/bin/llvm-gcc-4.2

ifdef NVIDIA_CUDA
OCLROOT = $(NVIDIA_CUDA)
else
OCLROOT = /usr/local/cuda
endif
ifdef AMDAPPSDKROOT
AMDAPP = -DAMDAPPSDK
OCLROOT = $(AMDAPPSDKROOT)
endif
ifdef ATISTREAMSDKROOT
AMDAPP = -DAMDAPPSDK
OCLROOT = $(ATISTREAMSDKROOT)
endif

# -DHAVE_SKEY
# -lskey

CPPFLAGS += 
CFLAGSX = -m32 -DAC_BUILT $(CPPFLAGS) -c -Wall -Wdeclaration-after-statement -g -O2 -DHAVE_NSS -I/usr/include/nss -I/usr/include/nspr   -fopenmp -DHAVE_MPI -fomit-frame-pointer -I/usr/local/include $(AMDAPP) $(RELEASE_BLD)
# CFLAGS for use on the main john.c file only
CFLAGS_MAIN = -DJOHN_XOP $(CFLAGSX)
CFLAGS = -march=native -mxop $(CFLAGSX)
ASFLAGS = -march=native -mxop -m32 -c -fopenmp -DHAVE_MPI  -DUNDERSCORES
LIBS = -lmpi -lwst -lwsock32 -lrt -lpthread -llibrexgen -ldl -lkernel32 -lgmp -lcrypt -lz -lm -lcrypto -lssl  -lssl3 -lsmime3 -lnssutil3 -lnss3 -lplds4 -lplc4 -lnspr4  
LDFLAGS = -m32 -g -L/usr/local/lib -L/usr/local/ssl/lib  $(LIBS) -fopenmp -DHAVE_MPI
LDFLAGS_MKV = -g -fopenmp
#
OPT_NORMAL = -funroll-loops
# Remove the "-Os" if you're using an ancient version of gcc
OPT_INLINE = -Os -funroll-loops -finline-functions
#

##########################################################
# TBD:  This code should be done by the run of configure
##########################################################

# Works with Solaris make, and GNU make
PLUGFORMATS_SRCS: sh =echo *_plug.c
PLUGFORMATS_SRCS += $(wildcard *_plug.c)
PLUGFORMATS_OBJS = $(PLUGFORMATS_SRCS:.c=.o)

JOHN_OBJS = \
	john-mpi.o \
	DES_fmt.o DES_std.o DES_bs.o DES_bs_b.o \
	BSDI_fmt.o \
	MD5_fmt.o MD5_std.o \
	BF_fmt.o BF_std.o \
	scrypt_fmt.o \
	escrypt/crypto_scrypt-best.o escrypt/crypto_scrypt-common.o \
	escrypt/sha256.o \
	AFS_fmt.o \
	LM_fmt.o \
	trip_fmt.o \
	timer.o \
	md5_go.o \
	md5.o \
	rc4.o \
	hmacmd5.o \
	base64.o \
	md4.o sha2.o \
	dynamic_fmt.o dynamic_parser.o dynamic_preloads.o dynamic_utils.o dynamic_big_crypt.o \
	hmacMD5_fmt.o hmacSHA1_fmt.o \
	django_fmt.o \
	truecrypt_fmt.o \
	SKEY_fmt.o \
	ssh_fmt.o ssh2john.o \
	pfx_fmt.o pfx2john.o \
	unrarcmd.o unrarfilter.o unrarhlp.o unrar.o unrarppm.o unrarvm.o \
	rar_fmt.o rar2john.o \
	rawSHA0_fmt.o \
	zip_fmt.o zip2john.o gladman_hmac.o gladman_pwd2key.o \
	racf2john.o \
	keychain2john.o \
	kwallet2john.o \
	pwsafe2john.o \
	dmg2john.o \
	keepass2john.o \
	keyring2john.o keystore2john.o \
	truecrypt_volume2john.o \
	wpapsk_fmt.o hccap2john.o \
	mozilla_fmt.o KeyDBCracker.o mozilla_des.o lowpbe.o mozilla2john.o \
	krb5-18_fmt.o krb5-23_fmt.o \
	$(PLUGFORMATS_OBJS) \
	rawSHA1_ng_fmt.o rawSHA256_ng_fmt.o rawSHA512_ng_fmt.o rawSHA256_ng_i_fmt.o rawSHA512_ng_i_fmt.o \
	plugin.o \
	dummy.o \
	NT_fmt.o \
	gost.o \
	common-gpu.o \
	batch.o bench.o charset.o common.o compiler.o config.o cracker.o \
	crc32.o external.o formats.o getopt.o idle.o inc.o john.o list.o \
	loader.o logger.o mask.o math.o memory.o misc.o options.o params.o \
	path.o recovery.o rpp.o rules.o signals.o single.o status.o tty.o \
	wordlist.o \
	mkv.o mkvlib.o \
	listconf.o \
	fake_salts.o \
	win32_memmap.o \
	unicode.o \
	unshadow.o \
	unafs.o \
	undrop.o \
	regex.o \
	c3_fmt.o \
	unique.o putty2john.o gpg2john.o memdbg.o

OCL_OBJS = \
	common-opencl.o common_opencl_pbkdf2.o opencl_mysqlsha1_fmt.o \
	opencl_cryptmd5_fmt.o opencl_phpass_fmt.o opencl_rawsha1_fmt.o \
	opencl_nt_fmt.o opencl_rawmd5_fmt.o opencl_nsldaps_fmt.o \
	opencl_cryptsha512_fmt.o opencl_mscash2_fmt.o opencl_wpapsk_fmt.o \
	opencl_xsha512_fmt.o opencl_rawsha512_fmt.o opencl_bf_std.o \
	opencl_bf_fmt.o opencl_pwsafe_fmt.o opencl_rawmd4_fmt.o \
	opencl_keychain_fmt.o opencl_agilekeychain_fmt.o opencl_zip_fmt.o \
	opencl_encfs_fmt.o opencl_odf_fmt.o opencl_sxc_fmt.o opencl_gpg_fmt.o \
	opencl_cryptsha256_fmt.o opencl_rawsha512-ng_fmt.o opencl_dmg_fmt.o \
	opencl_DES_fmt.o opencl_DES_bs.o opencl_DES_bs_b.o opencl_strip_fmt.o \
	opencl_office2007_fmt.o opencl_office2010_fmt.o opencl_office2013_fmt.o \
	opencl_ntlmv2_fmt.o opencl_rawsha256_fmt.o \
	opencl_krb5pa-sha1_fmt.o opencl_rar_fmt.o opencl_odf_aes_fmt.o \
	opencl_sha2_common.o opencl_autotune.o opencl_blockchain_fmt.o \
	opencl_pbkdf2_hmac_sha256_fmt.o opencl_rakp_fmt.o \
	opencl_krb5pa-md5_fmt.o opencl_keyring_fmt.o opencl_pbkdf2_hmac_sha512_fmt.o \
	opencl_o5logon_fmt.o
# broken:
# opencl_7z_fmt.o

CUDA_OBJS = \
	common-cuda.o cuda_common.o \
	cuda_cryptmd5_fmt.o cuda_cryptmd5.o \
	cuda_phpass_fmt.o cuda_phpass.o \
	cuda_cryptsha256_fmt.o cuda_cryptsha256.o \
	cuda_cryptsha512_fmt.o cuda_cryptsha512.o \
	cuda_mscash2_fmt.o cuda_mscash2.o \
	cuda_rawsha256_fmt.o cuda_rawsha256.o \
	cuda_rawsha224_fmt.o cuda_rawsha224.o \
	cuda_mscash_fmt.o cuda_mscash.o \
	cuda_xsha512_fmt.o cuda_xsha512.o \
	cuda_wpapsk_fmt.o cuda_wpapsk.o \
	cuda_rawsha512_fmt.o cuda_rawsha512.o \
	cuda_pwsafe_fmt.o cuda_pwsafe.o

GENMKVPWD_OBJS = \
	genmkvpwd.o mkvlib.o memory.o miscnl.o path.o memdbg.o

PROJ = ../run/john ../run/unshadow ../run/unafs ../run/unique ../run/undrop \
	../run/ssh2john ../run/rar2john ../run/zip2john \
	../run/genmkvpwd ../run/mkvcalcproba ../run/calc_stat \
	../run/tgtsnarf ../run/racf2john ../run/mozilla2john ../run/hccap2john \
	../run/pwsafe2john ../run/raw2dyna ../run/keepass2john ../run/pfx2john \
	../run/keychain2john ../run/keyring2john ../run/kwallet2john \
	../run/dmg2john ../run/putty2john john.local.conf ../run/uaf2john \
	../run/truecrypt_volume2john ../run/keystore2john ../run/wpapcap2john \
	../run/gpg2john ../run/cprepair ../run/luks2john

WITH_PCAP=
ifdef WITH_PCAP
PROJ += ../run/SIPdump ../run/vncpcap2john
endif

WITH_CUDA=
ifdef WITH_CUDA
CFLAGS += -I$(CUDAPATH)/include -DHAVE_CUDA
CFLAGS_MAIN += -I$(CUDAPATH)/include -DHAVE_CUDA
ifneq ($(wildcard $(CUDAPATH)/lib),)
LDFLAGS += -L$(CUDAPATH)/lib
endif
ifneq ($(wildcard $(CUDAPATH)/lib32),)
LDFLAGS += -L$(CUDAPATH)/lib32
endif
JOHN_OBJS += $(CUDA_OBJS)
ifneq ($(wildcard $(CCBIN_OSX)),)
NVCC_FLAGS += -m32 -ccbin=$(CCBIN_OSX)
endif
endif

WITH_OPENCL=
ifdef WITH_OPENCL
CFLAGS += -DHAVE_OPENCL 
CFLAGS_MAIN += -DHAVE_OPENCL 
LDFLAGS += 
JOHN_OBJS += $(OCL_OBJS)
endif

#########################################################
# this is what ./configure && make
# gets you. NOTE, we have to do the link in ./configure.
#   ** DONE $(LN) x86-sse.h arch.h or $(LN) x86-64 arch.h
# for now, in my testing, this is hard coded to x86-32.h
# NOTE, we also need to add extra .o file's some how.
#  ** DONE x86-64.o sse-intrinsics.o for 64 bit
#  ** DONE x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o  for 32 bit:
#
# for ssexi builds:
# x86-64.o sse-intrinsics-64.o for 64 bit
# x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o  for 32 bit:
#   and add -DUSING_ICC_S_FILE to CFLAGS
#
#  also need to figure out -DUNDERSCORES and add to ASFLAGS
#  also need to figure out -mpreferred-stack-boundary=4 and add (or whatever the stack size is)
#
#########################################################
default:
	@echo "#define JOHN_BLD" '"'32-bit XOP-autoconf'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		AESNI_ARCH=32
ifdef WITH_OPENCL
	$(MKDIR) ../run/kernels/
	$(CP_PRESERVE) opencl/*.cl ../run/kernels/
	$(CP_PRESERVE) opencl_*.h ../run/kernels/
endif
	@echo
	@echo Make process completed.

#########################################################
## This is the 'END' of the main default make target.
#########################################################

help:
	@echo "The 'older' fat makefile can be done with make --file=Makefile.orig [target]"

cuda_common.o:	cuda/cuda_common.cuh cuda/cuda_common.cu
	cd cuda; $(NVCC) $(NVCC_FLAGS) cuda_common.cu -o ../cuda_common.o

cuda_cryptmd5.o:  cuda_cryptmd5.h cuda/cryptmd5.cu cuda_common.o
	cd cuda; $(NVCC) $(NVCC_FLAGS) cryptmd5.cu -o ../cuda_cryptmd5.o

cuda_cryptmd5_fmt.o: cuda_cryptmd5.o cuda_cryptmd5_fmt.c
	$(CC)  $(CFLAGS) cuda_cryptmd5_fmt.c -o cuda_cryptmd5_fmt.o

cuda_phpass.o:  cuda_phpass.h cuda/phpass.cu cuda_common.o
	cd cuda; $(NVCC) $(NVCC_FLAGS) phpass.cu -o ../cuda_phpass.o

cuda_phpass_fmt.o: cuda_phpass.o cuda_phpass_fmt.c
	$(CC)  $(CFLAGS) cuda_phpass_fmt.c -o cuda_phpass_fmt.o

cuda_cryptsha256.o:  cuda_cryptsha256.h cuda/cryptsha256.cu cuda_common.o
	cd cuda; $(NVCC) $(NVCC_FLAGS) cryptsha256.cu -o ../cuda_cryptsha256.o

cuda_cryptsha256_fmt.o: cuda_cryptsha256.o cuda_cryptsha256_fmt.c
	$(CC)  $(CFLAGS) cuda_cryptsha256_fmt.c -o cuda_cryptsha256_fmt.o

cuda_cryptsha512.o:  cuda_cryptsha512.h cuda/cryptsha512.cu cuda_common.o
	cd cuda; $(NVCC) $(NVCC_FLAGS) cryptsha512.cu -o ../cuda_cryptsha512.o

cuda_cryptsha512_fmt.o: cuda_cryptsha512.o cuda_cryptsha512_fmt.c
	$(CC)  $(CFLAGS) cuda_cryptsha512_fmt.c -o cuda_cryptsha512_fmt.o

cuda_mscash2.o:  cuda_mscash2.h cuda/mscash2.cu cuda_common.o
	cd cuda; $(NVCC) $(NVCC_FLAGS) mscash2.cu -o ../cuda_mscash2.o

cuda_mscash2_fmt.o: cuda_mscash2.o cuda_mscash2_fmt.c
	$(CC)  $(CFLAGS) cuda_mscash2_fmt.c -o cuda_mscash2_fmt.o

cuda_mscash.o:  cuda_mscash.h cuda/mscash.cu cuda_common.o
	cd cuda; $(NVCC) $(NVCC_FLAGS) mscash.cu -o ../cuda_mscash.o

cuda_mscash_fmt.o: cuda_mscash.o cuda_mscash_fmt.c
	$(CC)  $(CFLAGS) cuda_mscash_fmt.c -o cuda_mscash_fmt.o

cuda_rawsha256.o:  cuda_rawsha256.h cuda/rawsha256.cu cuda_common.o
	cd cuda; $(NVCC) $(NVCC_FLAGS) -DSHA256 rawsha256.cu -o ../cuda_rawsha256.o

cuda_rawsha256_fmt.o: cuda_rawsha256.o cuda_rawsha256_fmt.c
	$(CC)  $(CFLAGS) -DSHA256 cuda_rawsha256_fmt.c -o cuda_rawsha256_fmt.o

cuda_rawsha224.o:  cuda_rawsha256.h cuda/rawsha256.cu cuda_common.o
	cd cuda; $(NVCC) $(NVCC_FLAGS) -DSHA224 rawsha256.cu -o ../cuda_rawsha224.o

cuda_rawsha224_fmt.o: cuda_rawsha224.o cuda_rawsha256_fmt.c
	$(CC)  $(CFLAGS) -DSHA224 cuda_rawsha256_fmt.c -o cuda_rawsha224_fmt.o

cuda_xsha512.o: cuda_xsha512.h cuda/xsha512.cu cuda_common.o
	cd cuda; $(NVCC) $(NVCC_FLAGS) xsha512.cu -o ../cuda_xsha512.o

cuda_xsha512_fmt.o: cuda_xsha512.o cuda_xsha512_fmt.c
	$(CC) $(CFLAGS) cuda_xsha512_fmt.c -o cuda_xsha512_fmt.o

cuda_wpapsk.o:  cuda_wpapsk.h cuda/wpapsk.cu cuda_common.o
	cd cuda; $(NVCC) $(NVCC_FLAGS) wpapsk.cu -o ../cuda_wpapsk.o

cuda_wpapsk_fmt.o: cuda_wpapsk.o cuda_wpapsk_fmt.c
	$(CC)  $(CFLAGS) cuda_wpapsk_fmt.c -o cuda_wpapsk_fmt.o

cuda_rawsha512.o: cuda_rawsha512.h cuda/rawsha512.cu cuda_common.o
	cd cuda; $(NVCC) $(NVCC_FLAGS) rawsha512.cu -o ../cuda_rawsha512.o

cuda_rawsha512_fmt.o: cuda_rawsha512.o cuda_rawsha512_fmt.c
	$(CC) $(CFLAGS) cuda_rawsha512_fmt.c -o cuda_rawsha512_fmt.o

cuda_pwsafe.o: cuda_pwsafe.h cuda/pwsafe.cu cuda_common.o
	cd cuda; $(NVCC) $(NVCC_FLAGS) pwsafe.cu -o ../cuda_pwsafe.o

cuda_pwsafe_fmt.o: cuda_pwsafe.o cuda_pwsafe_fmt.c
	$(CC)  $(CFLAGS) cuda_pwsafe_fmt.c -o cuda_pwsafe_fmt.o

common_opencl_pbkdf2.o: common_opencl_pbkdf2.h common_opencl_pbkdf2.c
	$(CC)  $(CFLAGS) common_opencl_pbkdf2.c -o common_opencl_pbkdf2.o

opencl_mscash2_fmt.o: common_opencl_pbkdf2.h common_opencl_pbkdf2.o opencl_mscash2_fmt.c
	$(CC)  $(CFLAGS) opencl_mscash2_fmt.c -o opencl_mscash2_fmt.o

SUBDIRS = aes

.PHONY: subdirs $(SUBDIRS)

subdirs: $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ all

# Inlining the S-boxes produces faster code as long as they fit in the cache.
DES_bs_b.o: DES_bs_b.c sboxes.c nonstd.c sboxes-s.c
	$(CC) $(CFLAGS) $(OPT_INLINE) DES_bs_b.c

# TBD  (plug building will be put into configure.ac, so this
# target will likely disappear soon
*_fmt_plug.c: Makefile john.c
	@

miscnl.o: misc.c
	$(CC) $(CFLAGS) $(OPT_NORMAL) -D_JOHN_MISC_NO_LOG misc.c -o miscnl.o

# This must not be specified with path because "make clean" would delete it.
john.local.conf:
	[ -f ../run/john.local.conf ] || touch ../run/john.local.conf

###############################################################################
#  Process targets.  Note, these are *nix targets, but also work fine under
#  cygwin.  The only problem with cygwin, is that the ln -s will NOT generate
#  a valid exe which can be run under native Win32 cmd shell (same for mingw)
#  If a use wants that behavior, then the  needs to be set to .exe
#  and the later group of exe targets will be used, and will use symlink.c and
#  not simply do a ln -s.  This will be done in configure, with something like
#  --enable-exe-ext=.exe   or something like that.  By default, it is set to
#  to empty, and the 'normal' target path (with ln -s) will be used.
###############################################################################
../run/john: $(JOHN_OBJS) $(SUBDIRS)
	$(LD) $(JOHN_OBJS) $(LDFLAGS) aes/aes.a -o ../run/john

../run/unshadow: ../run/john
	$(RM) ../run/unshadow
	ln -s john ../run/unshadow

../run/unafs: ../run/john
	$(RM) ../run/unafs
	ln -s john ../run/unafs

../run/undrop: ../run/john
	$(RM) ../run/undrop
	ln -s john ../run/undrop

../run/ssh2john: ../run/john
	$(RM) ../run/ssh2john
	ln -s john ../run/ssh2john

../run/putty2john: ../run/john
	$(RM) ../run/putty2john
	ln -s john ../run/putty2john

../run/pfx2john: ../run/john
	$(RM) ../run/pfx2john
	ln -s john ../run/pfx2john

../run/keepass2john: ../run/john
	$(RM) ../run/keepass2john
	ln -s john ../run/keepass2john

../run/keyring2john: ../run/john
	$(RM) ../run/keyring2john
	ln -s john ../run/keyring2john

../run/zip2john: ../run/john
	$(RM) ../run/zip2john
	ln -s john ../run/zip2john

../run/gpg2john: ../run/john
	$(RM) ../run/gpg2john
	ln -s john ../run/gpg2john

../run/rar2john: ../run/john
	$(RM) ../run/rar2john
	ln -s john ../run/rar2john

../run/mozilla2john: ../run/john
ifdef HAVE_NSS
	$(RM) ../run/mozilla2john
	ln -s john ../run/mozilla2john
endif

../run/racf2john: ../run/john
	$(RM) ../run/racf2john
	ln -s john ../run/racf2john

../run/keychain2john: ../run/john
	$(RM) ../run/keychain2john
	ln -s john ../run/keychain2john

../run/kwallet2john: ../run/john
	$(RM) ../run/kwallet2john
	ln -s john ../run/kwallet2john

../run/pwsafe2john: ../run/john
	$(RM) ../run/pwsafe2john
	ln -s john ../run/pwsafe2john

../run/dmg2john: ../run/john
	$(RM) ../run/dmg2john
	ln -s john ../run/dmg2john

../run/hccap2john: ../run/john
	$(RM) ../run/hccap2john
	ln -s john ../run/hccap2john

../run/truecrypt_volume2john: ../run/john
	$(RM) ../run/truecrypt_volume2john
	ln -s john ../run/truecrypt_volume2john

../run/keystore2john: ../run/john
	$(RM) ../run/keystore2john
	ln -s john ../run/keystore2john

../run/unique: ../run/john
	$(RM) ../run/unique
	ln -s john ../run/unique

#####################################################################
# These targets MUST match ALL of the john targets that use ln -s
# These are built for Win32, so that we have a 'native' symlink back
# to the john exe.  The john exe is still built fat, but there is no
# workable ln -s, so we have built a 'symlink.c' file. It works in
# a limited way, like symlink.
#####################################################################
../run/unshadow.exe: symlink.c
	$(CC) symlink.c -o ../run/unshadow.exe
	$(STRIP) ../run/unshadow.exe

../run/unafs.exe: symlink.c
	$(CC) symlink.c -o ../run/unafs.exe
	$(STRIP) ../run/unafs.exe

../run/undrop.exe: symlink.c
	$(CC) symlink.c -o ../run/undrop.exe
	$(STRIP) ../run/undrop.exe

../run/ssh2john.exe: symlink.c
	$(CC) symlink.c -o ../run/ssh2john.exe
	$(STRIP) ../run/ssh2john.exe

../run/putty2john.exe: symlink.c
	$(CC) symlink.c -o ../run/putty2john.exe
	$(STRIP) ../run/putty2john.exe

../run/pfx2john.exe: symlink.c
	$(CC) symlink.c -o ../run/pfx2john.exe
	$(STRIP) ../run/pfx2john.exe

../run/keepass2john.exe: symlink.c
	$(CC) symlink.c -o ../run/keepass2john.exe
	$(STRIP) ../run/keepass2john.exe

../run/keyring2john.exe: symlink.c
	$(CC) symlink.c -o ../run/keyring2john.exe
	$(STRIP) ../run/keyring2john.exe

../run/zip2john.exe: symlink.c
	$(CC) symlink.c -o ../run/zip2john.exe
	$(STRIP) ../run/zip2john.exe

../run/gpg2john.exe: symlink.c
	$(CC) symlink.c -o ../run/gpg2john.exe
	$(STRIP) ../run/gpg2john.exe

../run/rar2john.exe: symlink.c
	$(CC) symlink.c -o ../run/rar2john.exe
	$(STRIP) ../run/rar2john.exe

../run/mozilla2john.exe: symlink.c
ifdef HAVE_NSS
	$(CC) symlink.c -o ../run/mozilla2john.exe
	$(STRIP) ../run/mozilla2john.exe
endif

../run/racf2john.exe: symlink.c
	$(CC) symlink.c -o ../run/racf2john.exe
	$(STRIP) ../run/racf2john.exe

../run/keychain2john.exe: symlink.c
	$(CC) symlink.c -o ../run/keychain2john.exe
	$(STRIP) ../run/keychain2john.exe

../run/kwallet2john.exe: symlink.c
	$(CC) symlink.c -o ../run/kwallet2john.exe
	$(STRIP) ../run/kwallet2john.exe

../run/pwsafe2john.exe: symlink.c
	$(CC) symlink.c -o ../run/pwsafe2john.exe
	$(STRIP) ../run/pwsafe2john.exe

../run/dmg2john.exe: symlink.c
	$(CC) symlink.c -o ../run/dmg2john.exe
	$(STRIP) ../run/dmg2john.exe

../run/hccap2john.exe: symlink.c
	$(CC) symlink.c -o ../run/hccap2john.exe
	$(STRIP) ../run/hccap2john.exe

../run/truecrypt_volume2john.exe: symlink.c
	$(CC) symlink.c -o ../run/truecrypt_volume2john.exe
	$(STRIP) ../run/truecrypt_volume2john.exe

../run/keystore2john.exe: symlink.c
	$(CC) symlink.c -o ../run/keystore2john.exe
	$(STRIP) ../run/keystore2john.exe

../run/unique.exe: symlink.c
	$(CC) symlink.c -o ../run/unique.exe
	$(STRIP) ../run/unique.exe

########################################################
# Not linked to symlink for a .exe file, so simply make
# single targets, using the EXE_EXT macro
########################################################
../run/genmkvpwd: $(GENMKVPWD_OBJS)
	$(LD) $(GENMKVPWD_OBJS) $(LDFLAGS) -o ../run/genmkvpwd

../run/mkvcalcproba: mkvcalcproba.o
	$(LD) mkvcalcproba.o memdbg.o $(LDFLAGS) -o ../run/mkvcalcproba

../run/calc_stat: calc_stat.o
	$(LD) calc_stat.o memdbg.o $(LDFLAGS) -o ../run/calc_stat

../run/raw2dyna: raw2dyna.o
	$(LD) raw2dyna.o memdbg.o $(LDFLAGS) -o ../run/raw2dyna

../run/SIPdump: SIPdump.o
	$(LD) SIPdump.o memdbg.o $(LDFLAGS) -o ../run/SIPdump

../run/vncpcap2john: vncpcap2john.o
	$(CC) -Wall vncpcap2john.o memdbg.o $(LDFLAGS) -o ../run/vncpcap2john

../run/uaf2john: uaf2john.o uaf_encode_plug.o
	$(LD) $(LDFLAGS) uaf2john.o uaf_encode_plug.o memdbg.o -o ../run/uaf2john

../run/wpapcap2john: wpapcap2john.o
	$(LD) $(LDFLAGS) wpapcap2john.o memdbg.o -o ../run/wpapcap2john

# Requires extra -lcrypto and -lssl aftger luks2john.o.  Not sure why, link fails without that change
../run/luks2john: luks2john.o
	$(LD) ${LDFLAGS} luks2john.o -s -lcrypto -lssl memdbg.o -o ../run/luks2john

../run/cprepair: cprepair.c unicode.c unicode.h options.h misc.h misc.c \
	memdbg.h memdbg.c
	gcc -Wall -O3 -s -DNOT_JOHN -D_JOHN_MISC_NO_LOG cprepair.c unicode.c \
	misc.c memdbg.c -o ../run/cprepair

../run/tgtsnarf: tgtsnarf.o
	$(LD) tgtsnarf.o memdbg.o $(LDFLAGS) -o ../run/tgtsnarf

##########################################################
# TBD:  This code should be done by the run of configure
##########################################################
fmt_externs.h: $(PLUGFORMATS_SRCS) Makefile *_fmt_plug.c
	LC_ALL=C $(SED) -n 's/^\(struct fmt_main [^ ]*\) =.*/extern \1;/p' *_fmt_plug.c | LC_ALL=C $(SORT) > fmt_externs.h

fmt_registers.h: $(PLUGFORMATS_SRCS) Makefile *_fmt_plug.c
	LC_ALL=C $(SED) -n 's/^struct fmt_main \([^ ]*\) =.*/john_register_one(\&\1);/p' *_fmt_plug.c | LC_ALL=C $(SORT) > fmt_registers.h

john.o: john.c fmt_externs.h fmt_registers.h
	$(CC) $(CFLAGS_MAIN) $(OPT_NORMAL) -O0 $*.c

.c.o:
	$(CC) $(CFLAGS) $(OPT_NORMAL) $< -o $@

.S.o:
	$(AS) $(ASFLAGS) $*.S

check:
	../run/john --make_check

depend:
	makedepend -fMakefile.dep -Y *.c 2>> /dev/null

test:
	cd ../test && perl jtrts.pl -q

test_full:
	cd ../test && perl jtrts.pl -q -type full

test_utf8:
	cd ../test && perl jtrts.pl -q -type utf-8

test_verbose:
	cd ../test && perl jtrts.pl

test_full_verbose:
	cd ../test && perl jtrts.pl -type full

test_utf8_verbose:
	cd ../test && perl jtrts.pl -type utf-8

bash-completion:
	@echo
	@echo NOTE: Administrative priviledges required for this make target.
	[ -d /etc/bash_completion.d ] && $(CP) ../run/john.bash_completion /etc/bash_completion.d/ || true
	[ -d /usr/local/etc/bash_completion.d ] && $(CP) ../run/john.bash_completion /usr/local/etc/bash_completion.d/ || true
	[ -d /opt/local/etc/bash_completion.d ] && $(CP) ../run/john.bash_completion /opt/local/etc/bash_completion.d/ || true
	@echo
	@echo Bash-completion for JtR opportunistically installed.
	@echo Source \". ../run/john.bash_completion\" or logout/login to activate the changes

zsh-completion:
	@echo
	@echo NOTE: Administrative priviledges required for this make target.
	[ -d /usr/share/zsh/functions/Completion/Unix ] && $(CP) ../run/john.zsh_completion /usr/share/zsh/functions/Completion/Unix/_john || true
	[ -d /usr/share/zsh/site-functions ] && $(CP) ../run/john.zsh_completion /usr/share/zsh/site-functions/_john || true
	[ -d /usr/local/share/zsh/site-functions ] && $(CP) ../run/john.zsh_completion /usr/local/share/zsh/site-functions/_john || true
	@echo
	@echo zsh-completion for JtR opportunistically installed.
	@echo Source \". ../run/john.zsh_completion\" or logout/login to activate the changes

shell-completion: bash-completion zsh-completion
	@echo
	@echo "You should have bash and zsh completion now"

clean:
	$(RM) $(PROJ)
	@for exe in ${PROJ}; do \
	  ($(RM) $$exe.exe) \
	done
	$(RM) john-macosx-* *.o escrypt/*.o *.bak core
	$(RM) ../run/kernels/*.cl ../run/kernels/*.h ../run/kernels/*.bin
	$(RM) detect bench para-bench generic.h tmp.s
	$(RM) cuda/*.o cuda/*~ *~
#	arch.h now only cleaned up in distclean
#	$(RM) arch.h
#	later we may also want to NOT clean these (fmt_registers.h fmt_externs.h john_build_rule.h), if built in the ./configure run
	$(RM) fmt_registers.h fmt_externs.h john_build_rule.h
	$(CP) $(NULL) Makefile.dep
#	make -C aes clean
	@for dir in ${subdirs}; do \
	  (cd $$dir && make clean) \
	  || case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac; \
	done && test -z "$$fail"

# These are mostly for internal use.
charsets: ../run/ascii.chr ../run/alpha.chr ../run/lowernum.chr ../run/uppernum.chr ../run/lowerspace.chr ../run/lower.chr ../run/upper.chr ../run/digits.chr ../run/alnum.chr ../run/lanman.chr ../run/lm_ascii.chr ../run/alnumspace.chr ../run/latin1.chr ../run/utf8.chr

../run/ascii.chr: charset.c params.h
	../run/john -make-charset=../run/ascii.chr -pot:rockyou.ansi.pot -ext:filter_ascii

../run/alpha.chr: charset.c params.h
	../run/john -make-charset=../run/alpha.chr -pot:rockyou.ansi.pot -ext:filter_alpha

../run/lowernum.chr: charset.c params.h
	../run/john -make-charset=../run/lowernum.chr -pot:rockyou.ansi.pot -ext:filter_lowernum

../run/uppernum.chr: charset.c params.h
	../run/john -make-charset=../run/uppernum.chr -pot:rockyou.ansi.pot -ext:filter_uppernum

../run/lowerspace.chr: charset.c params.h
	../run/john -make-charset=../run/lowerspace.chr -pot:rockyou.ansi.pot -ext:filter_lowerspace

../run/lower.chr: charset.c params.h
	../run/john -make-charset=../run/lower.chr -pot:rockyou.ansi.pot -ext:filter_lower

../run/upper.chr: charset.c params.h
	../run/john -make-charset=../run/upper.chr -pot:rockyou.ansi.pot -ext:filter_upper

../run/digits.chr: charset.c params.h
	../run/john -make-charset=../run/digits.chr -pot:rockyou.ansi.pot -ext:filter_digits

../run/alnum.chr: charset.c params.h
	../run/john -make-charset=../run/alnum.chr -pot:rockyou.ansi.pot -ext:filter_alnum

../run/lanman.chr: charset.c params.h
	../run/john -make-charset=../run/lanman.chr -pot:rockyou.lm850.pot -ext:filter_lanman

../run/lm_ascii.chr: charset.c params.h
	../run/john -make-charset=../run/lm_ascii.chr -pot:rockyou.lm850.pot -ext:filter_lm_ascii

../run/alnumspace.chr: charset.c params.h
	../run/john -make-charset=../run/alnumspace.chr -pot:rockyou.ansi.pot -ext:filter_alnumspace

../run/latin1.chr: charset.c params.h
	../run/john -make-charset=../run/latin1.chr -pot:rockyou.ansi.16.pot

../run/utf8.chr: charset.c params.h
	../run/john -make-charset=../run/utf8.chr -pot:rockyou.utf8.24.pot


# For the time being, icc builds a better sse-intrinsics.S but this may
# change over time. NOTE that sse-intrinsics.S is never re-built unless you
# manually do a "make intrinsics".
intrinsics: clean-intrinsics sse-intrinsics-64.S sse-intrinsics-32.S

clean-intrinsics:
	$(RM) sse-intrinsics-64.S sse-intrinsics-32.S sse-intrinsics-win32.S

sse-intrinsics-64.S:
	$(LN) x86-64.h arch.h
	icc -S -o sse-intrinsics-64.S sse-intrinsics.c -O2 -fno-builtin -fno-verbose-asm -openmp -DUSING_ICC_S_FILE -Wall

sse-intrinsics-32.S:
	$(LN) x86-sse.h arch.h
	icc -m32 -S -o sse-intrinsics-32.S sse-intrinsics.c -O2 -fno-builtin -fno-verbose-asm -openmp -DUSING_ICC_S_FILE -Wall
	perl sse2i_winfix.pl sse-intrinsics-32.S sse-intrinsics-win32.S
	mv sse-intrinsics-win32.S sse-intrinsics-32.S

#######################################################################
## NOTE, auto re-building configure will ONLY happen IF the user has ##
## CONFIG_MAINT=1 environment variable.  Beware.                     ##
#######################################################################

## automatic re-running of configure if the configure.ac file has changed
ifeq ($(CONFIG_MAINT), 1)
configure: configure.ac
	autoconf
else
configure: configure.ac
	@touch configure
endif

# autoheader might not change autoconfig.h.in, so touch a stamp file
ifeq ($(CONFIG_MAINT), 1)
autoconfig.h.in: autoconfig-stamp-h
autoconfig-stamp-h-in: configure.ac aclocal.m4
	autoheader
	echo "timestamp from Makefile" > autoconfig-stamp-h-in
else
autoconfig.h.in: autoconfig-stamp-h
autoconfig-stamp-h-in: configure.ac aclocal.m4
	echo "timestamp from Makefile" > autoconfig-stamp-h-in
endif

ifeq ($(CONFIG_MAINT), 1)
autoconfig.h: autoconfig-stamp-h
autoconfig-stamp-h: autoconfig.h.in config.status
	./config.status
else
autoconfig.h: autoconfig-stamp-h
autoconfig-stamp-h: autoconfig.h.in config.status
	@touch config.status
	@touch autoconfig.h.in
	@touch autoconfig-stamp-h
	@touch autoconfig.h
endif

ifeq ($(CONFIG_MAINT), 1)
Makefile: Makefile.in config.status
	./config.status
endif

ifeq ($(CONFIG_MAINT), 1)
config.status: configure
	./config.status --recheck
endif

all:
	@for dir in ${subdirs}; do \
	  (cd $$dir && $(MAKE) all) \
	  || case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac; \
	done && test -z "$$fail"

distclean: clean
	$(RM) -rf autom4te.cache
	@for dir in ${subdirs}; do \
	  (cd $$dir && $(MAKE) distclean) \
	  || case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac; \
	done && test -z "$$fail"
	$(RM) -f Makefile autoconfig.h config.status config.cache config.log autoconfig-stamp-h stamp-h1 ../run/john.log
	$(LN) Makefile.stub Makefile
#	moved from older clean target.
	$(RM) arch.h
#	We may later also 'move' the creation of these 3 into configure. If we do, we only smoke them on distclean
#	$(RM) fmt_registers.h fmt_externs.h john_build_rule.h

# a rule to make snapshots  (NOTE, still to be done for JtR)
snapshot: $(SOURCES) $(DOCS) $(OTHERFILES)
	@echo
	@echo "->Note: The version for now is hacked into Makefile.in as"
	@echo "->" $(VERS)
	@echo
	@echo "->copying all release files to the directory " xyplot-$(VERS)
	@echo
	tar cf - $(SOURCES) $(DOCS) $(OTHERFILES) | gzip > xyplot-$(VERS).tar.gz
	-mkdir xyplot-$(VERS)
	gzcat xyplot-$(VERS).tar.gz | (cd xyplot-$(VERS); tar xf -)
	/bin/rm -f xyplot-$(VERS).tar.gz
	@echo
	@echo "->making the compressed tar file " xyplot-$(VERS).tar.gz
	@echo
	tar cf - xyplot-$(VERS) | gzip > xyplot-$(VERS).tar.gz
	@echo
#	@echo "->placing the snapshot for anonymous ftp in " $(FTPDIR)
#	@echo
#	rcp xyplot-$(VERS).tar.gz $(FTPDIR)
	echo "->removnig the temporary directory " xyplot-$(VERS)
	/bin/rm -rf xyplot-$(VERS)             # remove the old directory

#install:
#	@for dir in ${subdirs}; do \
#	  (cd $$dir && $(MAKE) install) \
#	  || case "$(MFLAGS)" in *k*) fail=yes;; *) exit 1;; esac; \
#	done && test -z "$$fail"

# TBD JtR
#install: all
#	$(top_srcdir)/mkinstalldirs $(bindir)
#	$(top_srcdir)/mkinstalldirs $(libdir)
#	$(INSTALL) xyplot $(bindir)
#	$(INSTALL) xyps $(bindir)
#	$(INSTALL) xyug $(bindir)
#	$(INSTALL) xypost $(libdir)

# TBD JtR
uninstall:
	-/bin/rm -f $(bindir)/xyplot
	-/bin/rm -f $(bindir)/xyps
	-/bin/rm -f $(bindir)/xyug
	-/bin/rm -f $(libdir)/xypost

include Makefile.dep
