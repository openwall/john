#
# This file is part of John the Ripper password cracker,
# Copyright (c) 1996-2011 by Solar Designer
#
# ...with changes in the jumbo patch, by various authors
#

CC = gcc
AS = $(CC)
LD = $(CC)
CPP = $(CC)
CP = cp
LN = ln -f -s
RM = rm -f
TR = tr
SED = sed
NULL = /dev/null
CPPFLAGS = -E

## Uncomment the TWO lines below for MPI (can be used together with OMP as well)
## For experimental MPI_Barrier support, add -DJOHN_MPI_BARRIER too.
## For experimental MPI_Abort support, add -DJOHN_MPI_ABORT too.
#CC = mpicc -DHAVE_MPI
#MPIOBJ = john-mpi.o

OMPFLAGS =
# gcc with OpenMP
#OMPFLAGS = -fopenmp
#OMPFLAGS = -fopenmp -msse2
# Sun Studio with OpenMP (set the OMP_NUM_THREADS env var at runtime)
#OMPFLAGS = -xopenmp
# icc with OpenMP (for make target linux-x86-64-icc)
#ICCOMPFLAGS = -openmp

# NSS (and NSPR) flag, un-comment if installed (needed for mozilla format)
#HAVE_NSS = -DHAVE_NSS `pkg-config --cflags nss`

# Uncomment the below if you have GMP library installed (faster wowsrp format)
#HAVE_GMP = -DHAVE_GMP

# Uncomment the below if you have KRB5 library installed (krb5-18/23 formats)
#HAVE_KRB5 = -DHAVE_KRB5

# Change sm_10 to sm_20 if you have Fermi support (400 series or later) or
# sm_30 if you have Kepler (600 series or later) and your nvcc supports it.
NVCC_FLAGS = -c -Xptxas -v -arch sm_10
CUDAPATH = /usr/local/cuda/lib
CUDA64PATH = /usr/local/cuda/lib64

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
ifdef HAVE_NSS
NSS_LDFLAGS = `pkg-config --libs nss`
endif
ifdef HAVE_GMP
GMP_LDFLAGS = -lgmp
endif
ifdef HAVE_KRB5
KRB5_LDFLAGS = -lk5crypto -lkrb5
endif

CFLAGS = -c -Wall -O2 -fomit-frame-pointer -Wdeclaration-after-statement -I/usr/local/include $(HAVE_NSS) $(HAVE_GMP) $(HAVE_KRB5) $(OMPFLAGS) $(JOHN_CFLAGS) $(AMDAPP)
# -DHAVE_SKEY
# CFLAGS for use on the main john.c file only
CFLAGS_MAIN = $(CFLAGS)
ASFLAGS = -c $(JOHN_CFLAGS) $(OMPFLAGS)
LDFLAGS = -s -L/usr/local/lib -L/usr/local/ssl/lib -lssl -lcrypto -lm -lz $(JOHN_CFLAGS) $(OMPFLAGS) $(NSS_LDFLAGS) $(GMP_LDFLAGS) $(KRB5_LDFLAGS)
# -lskey
LDFLAGS_SOLARIS = -lrt -lnsl -lsocket -lm -lz -lcrypto -lssl
LDFLAGS_MKV = -s -lm
OPT_NORMAL = -funroll-loops
# Remove the "-Os" if you're using an ancient version of gcc
OPT_INLINE = -Os -funroll-loops -finline-functions

# Works with Solaris make, and GNU make
PLUGFORMATS_SRCS: sh =echo *_plug.c
PLUGFORMATS_SRCS += $(wildcard *_plug.c)
PLUGFORMATS_OBJS = $(PLUGFORMATS_SRCS:.c=.o)

JOHN_OBJS = \
	$(MPIOBJ) \
	DES_fmt.o DES_std.o DES_bs.o DES_bs_b.o \
	BSDI_fmt.o \
	MD5_fmt.o MD5_std.o \
	BF_fmt.o BF_std.o \
	AFS_fmt.o \
	LM_fmt.o \
	trip_fmt.o \
	timer.o \
	md5_go.o \
	md5_eq.o \
	md5.o \
	rc4.o \
	hmacmd5.o \
	base64.o \
	md4.o sha2.o \
	dynamic_fmt.o dynamic_parser.o dynamic_preloads.o dynamic_utils.o \
	hmacMD5_fmt.o hmacSHA1_fmt.o \
	django_fmt.o \
	truecrypt_fmt.o \
	SKEY_fmt.o \
	ssh_fmt.o ssh2john.o \
	pfx_fmt.o pfx2john.o \
	pdf_fmt.o pdf2john.o pdfcrack_common.o pdfcrack_md5.o pdfparser.o pdfcrack.o pdfcrack_rc4.o \
	unrarcmd.o unrarfilter.o unrarhlp.o unrar.o unrarppm.o unrarvm.o \
	rar_fmt.o rar2john.o \
	rawSHA0_fmt.o \
	zip_fmt.o zip2john.o gladman_hmac.o gladman_pwd2key.o \
	racf2john.o \
	keychain2john.o \
	pwsafe2john.o \
	keepass2john.o \
	wpapsk_fmt.o hccap2john.o \
	mozilla_fmt.o KeyDBCracker.o mozilla_des.o lowpbe.o mozilla2john.o \
	krb5-18_fmt.o krb5-23_fmt.o \
	$(PLUGFORMATS_OBJS) \
	rawSHA1_ng_fmt.o \
	plugin.o \
	dummy.o \
	batch.o bench.o charset.o common.o compiler.o config.o cracker.o \
	crc32.o external.o formats.o getopt.o idle.o inc.o john.o list.o \
	loader.o logger.o math.o memory.o misc.o options.o params.o path.o \
	recovery.o rpp.o rules.o signals.o single.o status.o tty.o wordlist.o \
	mkv.o mkvlib.o \
	fake_salts.o \
	win32_memmap.o \
	unicode.o \
	unshadow.o \
	unafs.o \
	undrop.o \
	unique.o

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
	opencl_ntlmv2_fmt.o

CUDA_OBJS = \
	cuda_common.o \
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

BENCH_DES_OBJS_ORIG = \
	DES_fmt.o DES_std.o

BENCH_DES_OBJS_DEPEND = \
	$(BENCH_DES_OBJS_ORIG)

BENCH_DES_BS_OBJS_DEPEND = \
	DES_bs_b.o

BENCH_MD5_OBJS_DEPEND = \
	MD5_fmt.o MD5_std.o

BENCH_BF_OBJS_DEPEND = \
	BF_fmt.o BF_std.o

BENCH_OBJS = \
    $(MPIOBJ) \
	$(BENCH_DES_OBJS_DEPEND) \
	DES_bsg.o $(BENCH_DES_BS_OBJS_DEPEND) \
	$(BENCH_MD5_OBJS_DEPEND) \
	$(BENCH_BF_OBJS_DEPEND) \
	bench-t.o best.o common.o config_g.o formats_g.o math.o memory.o \
	miscnl.o params.o path.o signals.o tty.o

PARA_BENCH_32_OBJS = \
	bench-t.o para-best.o common.o config_g.o formats_g.o math.o memory.o \
	miscnl.o params.o path.o signals.o tty.o sha1-mmx.o md4-mmx.o \
	md5-mmx.o x86.S $(BENCH_PARA_DEPEND)

PARA_BENCH_OBJS = \
	bench-t.o para-best.o common.o config_g.o formats_g.o math.o memory.o \
	miscnl.o params.o path.o signals.o tty.o $(BENCH_PARA_DEPEND)

BENCH_PARA_DEPEND = \
	sse-intrinsics.o rawMD4_fmt_plug.o rawMD5_fmt_plug.o rawSHA1_fmt_plug.o MD5_fmt.o MD5_std.o

GENMKVPWD_OBJS = \
	genmkvpwd.o mkvlib.o memory.o miscnl.o

PROJ = ../run/john ../run/unshadow ../run/unafs ../run/unique ../run/undrop \
	../run/ssh2john ../run/pdf2john ../run/rar2john ../run/zip2john \
	../run/genmkvpwd ../run/mkvcalcproba ../run/calc_stat \
	../run/tgtsnarf ../run/racf2john ../run/mozilla2john ../run/hccap2john \
	../run/pwsafe2john ../run/raw2dyna ../run/keepass2john ../run/pfx2john \
	../run/keychain2john ../run/to_dyna john.local.conf
PROJ_DOS = ../run/john.bin ../run/john.com \
	../run/unshadow.com ../run/unafs.com ../run/unique.com \
	../run/undrop.com \
	../run/ssh2john.com ../run/pdf2john.com ../run/rar2john.com ../run/zip2john \
	../run/racf2john.com ../run/mozilla2john.com ../run/hccap2john.com \
	../run/pwsafe2john.com ../run/keepass2john.com ../run/pfx2john.com \
	../run/keychain2john.com john.local.conf
PROJ_WIN32 = ../run/john.exe \
	../run/unshadow.exe ../run/unafs.exe ../run/unique.exe \
	../run/undrop.exe \
	../run/ssh2john.exe ../run/pdf2john.exe ../run/rar2john.exe ../run/zip2john.exe \
	../run/genmkvpwd.exe ../run/mkvcalcproba.exe ../run/calc_stat.exe \
	../run/racf2john.exe ../run/mozilla2john.exe ../run/hccap2john.exe \
	../run/pwsafe2john.exe ../run/raw2dyna.exe ../run/keepass2john.exe \
	../run/pfx2john.exe ../run/keychain2john.exe ../run/to_dyna.exe john.local.conf
PROJ_WIN32_MINGW = ../run/john-mingw.exe \
	../run/unshadow.exe ../run/unafs.exe ../run/unique.exe \
	../run/undrop.exe \
	../run/ssh2john.exe ../run/pdf2john.exe ../run/rar2john.exe ../run/zip2john.exe \
	../run/genmkvpwd.exe ../run/mkvcalcproba.exe ../run/calc_stat.exe \
	../run/racf2john.exe ../run/mozilla2john.exe ../run/hccap2john.exe \
	../run/pwsafe2john.exe ../run/raw2dyna.exe ../run/keepass2john.exe \
	../run/pfx2john.exe ../run/keychain2john.exe ../run/to_dyna.exe john.local.conf

default:
	@echo "To build John the Ripper, type:"
	@echo "	make clean SYSTEM"
	@echo "where SYSTEM can be one of the following:"
	@echo "([i] is an optional letter for pre-built intrinsics, eg. -sse2i vs -sse2):"
	@echo "linux-x86-64-native      Linux, x86-64 'native' (all CPU features you've got)"
	@echo "linux-x86-64-gpu         Linux, x86-64 'native', CUDA and OpenCL (experimental)"
	@echo "linux-x86-64-opencl      Linux, x86-64 'native', OpenCL (experimental)"
	@echo "linux-x86-64-cuda        Linux, x86-64 'native', CUDA (experimental)"
	@echo "linux-x86-64-avx         Linux, x86-64 with AVX (2011+ Intel CPUs)"
	@echo "linux-x86-64-xop         Linux, x86-64 with AVX and XOP (2011+ AMD CPUs)"
	@echo "linux-x86-64[i]          Linux, x86-64 with SSE2 (most common)"
	@echo "linux-x86-64-icc         Linux, x86-64 compiled with icc"
	@echo "linux-x86-64-clang       Linux, x86-64 compiled with clang"
#	@echo "linux-x86-64-clang-debug Linux, x86-64 compiled with clang (with debugging options)
#	@echo "linux-x86-64-32-native   Linux, x86-64, 32-bit with everything (for regression tests)"
#	@echo "linux-x86-64-32-sse2asm  Linux, x86-64, 32-bit with asm SSE2 (for regression tests)"
#	@echo "linux-x86-64-32-sse2[i]  Linux, x86-64, 32-bit with SSE2 (for regression tests)"
#	@echo "linux-x86-64-32-mmx      Linux, x86-64, 32-bit with MMX (for regression tests)"
#	@echo "linux-x86-64-32-any      Linux, x86-64, 32-bit (for regression tests)"
	@echo "linux-x86-gpu            Linux, x86 32-bit with SSE2, CUDA and OpenCL (experimental)"
	@echo "linux-x86-opencl         Linux, x86 32-bit with SSE2 and OpenCL (experimental)"
	@echo "linux-x86-cuda           Linux, x86 32-bit with SSE2 and CUDA (experimental)"
	@echo "linux-x86-sse2[i]        Linux, x86 32-bit with SSE2 (most common, 32-bit)"
	@echo "linux-x86-native         Linux, x86 32-bit, with all CPU features you've got (not necessarily best)"
	@echo "linux-x86-mmx            Linux, x86 32-bit with MMX (for old computers)"
	@echo "linux-x86-any            Linux, x86 32-bit (for truly ancient computers)"
	@echo "linux-x86-clang          Linux, x86 32-bit with SSE2, compiled with clang"
#	@echo "linux-x86-clang-debug    Linux, x86 32-bit with SSE2, compiled with clang (with debugging options)
	@echo "linux-alpha              Linux, Alpha"
	@echo "linux-sparc              Linux, SPARC 32-bit"
	@echo "linux-ppc32-altivec      Linux, PowerPC w/AltiVec (best)"
	@echo "linux-ppc32              Linux, PowerPC 32-bit"
#	@echo "linux-ppc64-altivec      Linux, PowerPC 64-bit w/AltiVec"
	@echo "linux-ppc64              Linux, PowerPC 64-bit"
	@echo "linux-ia64               Linux, IA-64"
	@echo "freebsd-x86-64[i]        FreeBSD, x86-64 with SSE2 (best)"
	@echo "freebsd-x86-sse2[i]      FreeBSD, x86 with SSE2 (best if 32-bit)"
	@echo "freebsd-x86-mmx          FreeBSD, x86 with MMX"
	@echo "freebsd-x86-any          FreeBSD, x86"
	@echo "freebsd-alpha            FreeBSD, Alpha"
	@echo "openbsd-x86-64[i]        OpenBSD, x86-64 with SSE2 (best)"
	@echo "openbsd-x86-sse2[i]      OpenBSD, x86 with SSE2 (best if 32-bit)"
	@echo "openbsd-x86-mmx          OpenBSD, x86 with MMX"
	@echo "openbsd-x86-any          OpenBSD, x86"
	@echo "openbsd-alpha            OpenBSD, Alpha"
	@echo "openbsd-sparc64          OpenBSD, SPARC 64-bit (best)"
	@echo "openbsd-sparc            OpenBSD, SPARC 32-bit"
	@echo "openbsd-ppc32            OpenBSD, PowerPC 32-bit"
	@echo "openbsd-ppc64            OpenBSD, PowerPC 64-bit"
	@echo "openbsd-pa-risc          OpenBSD, PA-RISC"
	@echo "openbsd-vax              OpenBSD, VAX"
	@echo "netbsd-sparc64           NetBSD, SPARC 64-bit"
	@echo "netbsd-vax               NetBSD, VAX"
	@echo "solaris-sparc64-cc       Solaris, SPARC V9 64-bit, cc (best)"
	@echo "solaris-sparc64-gcc      Solaris, SPARC V9 64-bit, gcc"
	@echo "solaris-sparcv9-cc       Solaris, SPARC V9 32-bit, cc"
	@echo "solaris-sparcv8-cc       Solaris, SPARC V8 32-bit, cc"
	@echo "solaris-sparc-gcc        Solaris, SPARC 32-bit, gcc"
	@echo "solaris-x86-64-cc        Solaris, x86-64 with SSE2, cc"
	@echo "solaris-x86-64[i]-gcc    Solaris, x86-64 with SSE2, gcc"
	@echo "solaris-x86-sse2-cc      Solaris 9 4/04+, x86 with SSE2, cc"
	@echo "solaris-x86-sse2[i]-gcc  Solaris 9 4/04+, x86 with SSE2, gcc"
	@echo "solaris-x86-mmx-cc       Solaris, x86 with MMX, cc"
	@echo "solaris-x86-mmx-gcc      Solaris, x86 with MMX, gcc"
	@echo "solaris-x86-any-cc       Solaris, x86, cc"
	@echo "solaris-x86-any-gcc      Solaris, x86, gcc"
	@echo "sco-x86-any-gcc          SCO, x86, gcc"
	@echo "sco-x86-any-cc           SCO, x86, cc"
	@echo "tru64-alpha              Tru64 (Digital UNIX, OSF/1), Alpha"
	@echo "aix-ppc32                AIX, PowerPC 32-bit"
	@echo "macosx-x86-64            Mac OS X 10.5+, Xcode 3.0+, x86-64 with SSE2 (best)"
	@echo "macosx-x86-64-gpu        Mac OS X 10.5+, Xcode 3.0+, x86-64 with SSE2, CUDA and OpenCL support"
	@echo "macosx-x86-64-opencl     Mac OS X 10.5+, Xcode 3.0+, x86-64 with SSE2, OpenCL support"
	@echo "macosx-x86-64-cuda       Mac OS X 10.5+, Xcode 3.0+, x86-64 with SSE2, CUDA support"
	@echo "macosx-x86-sse2          Mac OS X, x86 with SSE2"
	@echo "macosx-ppc32-altivec     Mac OS X, PowerPC w/AltiVec (best)"
	@echo "macosx-ppc32             Mac OS X, PowerPC 32-bit"
#	@echo "macosx-ppc64-altivec     Mac OS X, PowerPC 64-bit w/AltiVec"
	@echo "macosx-ppc64             Mac OS X 10.4+, PowerPC 64-bit"
	@echo "macosx-universal         Mac OS X, Universal Binary (x86 + x86-64 + PPC)"
	@echo "hpux-pa-risc-gcc         HP-UX, PA-RISC, gcc"
	@echo "hpux-pa-risc-cc          HP-UX, PA-RISC, ANSI cc"
	@echo "irix-mips64-r10k         IRIX, MIPS 64-bit (R10K) (best)"
	@echo "irix-mips64              IRIX, MIPS 64-bit"
	@echo "irix-mips32              IRIX, MIPS 32-bit"
	@echo "dos-djgpp-x86-mmx        DOS, DJGPP, x86 with MMX"
	@echo "dos-djgpp-x86-any        DOS, DJGPP, x86"
	@echo "win32-cygwin-x86-sse2[i] Win32, Cygwin, x86 with SSE2 (best)"
	@echo "win32-cygwin-x86-mmx     Win32, Cygwin, x86 with MMX"
	@echo "win32-cygwin-x86-any     Win32, Cygwin, x86"
	@echo "win32-mingw-x86-sse2[i]  Win32, MinGW, x86 with SSE2 (best)"
	@echo "win32-mingw-x86-mmx      Win32, MinGW, x86 with MMX"
	@echo "win32-mingw-x86-any      Win32, MinGW, x86"
	@echo "beos-x86-sse2            BeOS, x86 with SSE2 (best)"
	@echo "beos-x86-mmx             BeOS, x86 with MMX"
	@echo "beos-x86-any             BeOS, x86"
	@echo "generic                  Any other Unix-like system with gcc"

linux-x86-64-avx:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o sse-intrinsics.o" \
		CFLAGS_MAIN="$(CFLAGS) -DJOHN_AVX -DHAVE_CRYPT -DHAVE_DL" \
		CFLAGS="$(CFLAGS) -mavx -DHAVE_CRYPT -DHAVE_DL" \
		ASFLAGS="$(ASFLAGS) -mavx" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl"

linux-x86-64-xop:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o sse-intrinsics.o" \
		CFLAGS_MAIN="$(CFLAGS) -DJOHN_XOP -DHAVE_CRYPT -DHAVE_DL" \
		CFLAGS="$(CFLAGS) -mxop -DHAVE_CRYPT -DHAVE_DL" \
		ASFLAGS="$(ASFLAGS) -mxop" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl"

linux-x86-64-gpu:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) $(OCL_OBJS) $(CUDA_OBJS) c3_fmt.o x86-64.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -I$(OCLROOT)/include -DHAVE_CRYPT -DCL_VERSION_1_0 -DHAVE_CUDA -DHAVE_DL -march=native" \
		ASFLAGS="$(ASFLAGS) -march=native" \
		LDFLAGS="$(LDFLAGS) -L$(OCLROOT)/lib/x86_64 -L$(OCLROOT)/lib64 -L$(CUDA64PATH) -lcrypt -lOpenCL -ldl -lcudart -march=native"
	$(CP) opencl/*.cl ../run/
	$(CP) opencl_*.h ../run/

linux-x86-64-opencl:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) $(OCL_OBJS) c3_fmt.o x86-64.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -I$(OCLROOT)/include -DHAVE_CRYPT -DCL_VERSION_1_0 -DHAVE_DL -march=native" \
		ASFLAGS="$(ASFLAGS) -march=native" \
		LDFLAGS="$(LDFLAGS) -L$(OCLROOT)/lib/x86_64 -L$(OCLROOT)/lib64 -lcrypt -lOpenCL -ldl -march=native"
	$(CP) opencl/*.cl ../run/
	$(CP) opencl_*.h ../run/

linux-x86-64-cuda:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) $(CUDA_OBJS) c3_fmt.o x86-64.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -DHAVE_DL -DHAVE_CUDA -march=native" \
		ASFLAGS="$(ASFLAGS) -march=native" \
		LDFLAGS="$(LDFLAGS) -L$(CUDA64PATH) -lcrypt -ldl -lcudart -march=native"

linux-x86-64-native:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -DHAVE_DL -march=native" \
		ASFLAGS="$(ASFLAGS) -march=native" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl -march=native"

linux-x86-64:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -DHAVE_DL" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl"

linux-x86-64i:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o sse-intrinsics-64.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -DHAVE_DL -DUSING_ICC_S_FILE" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl"

linux-x86-64-clang:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o sse-intrinsics.o" \
		CFLAGS="-Wall -c -O2 -I/usr/include -msse2 -DHAVE_CRYPT -DHAVE_DL $(HAVE_NSS) $(HAVE_GMP) $(HAVE_KRB5) $(JOHN_CFLAGS)" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl" \
		CPP="clang" CC="clang" AS="clang" LD="clang"

linux-x86-64-clang-debug:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o sse-intrinsics.o" \
		CFLAGS="-Wall -Wdeclaration-after-statement -c -g -O1 -faddress-sanitizer -I/usr/include -msse2 -DHAVE_CRYPT -DHAVE_DL $(HAVE_NSS) $(HAVE_GMP) $(HAVE_KRB5) $(JOHN_CFLAGS)" \
		LDFLAGS="-L/usr/local/lib -L/usr/local/ssl/lib -lssl -lcrypto -lm -lz -lcrypt -ldl -faddress-sanitizer $(NSS_LDFLAGS) $(GMP_LDFLAGS) $(KRB5_LDFLAGS)" \
		CPP="clang" CC="clang" AS="clang" LD="clang"

linux-x86-64-icc:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o sse-intrinsics.o" \
		CFLAGS="-c -fast -O2 -I/usr/include -static-intel -DHAVE_CRYPT -DHAVE_DL $(ICCOMPFLAGS) $(HAVE_NSS) $(HAVE_GMP) $(HAVE_KRB5) $(JOHN_CFLAGS)" \
		ASFLAGS="-c -xHost" \
		LDFLAGS="-lm -lssl -lcrypto -ipo -static-intel -lcrypt -ldl -lz $(ICCOMPFLAGS) -s $(NSS_LDFLAGS) $(GMP_LDFLAGS) $(KRB5_LDFLAGS)" \
		CPP="icc" CC="icc" AS="icc" LD="icc"

linux-x86-64-32-native:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -m32 -msse2 -DHAVE_CRYPT -DHAVE_DL -march=native" \
		ASFLAGS="$(ASFLAGS) -m32 -msse2 -march=native" \
		LDFLAGS="$(LDFLAGS) -m32 -lcrypt -ldl -march=native"

linux-x86-64-32-sse2:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -m32 -msse2 -DHAVE_CRYPT -DHAVE_DL" \
		ASFLAGS="$(ASFLAGS) -m32 -msse2" \
		LDFLAGS="$(LDFLAGS) -m32 -lcrypt -ldl"

linux-x86-64-32-sse2asm:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -m32 -msse2 -DHAVE_CRYPT -DHAVE_DL -DJOHN_DISABLE_INTRINSICS" \
		ASFLAGS="$(ASFLAGS) -m32 -msse2" \
		LDFLAGS="$(LDFLAGS) -m32 -lcrypt -ldl"

linux-x86-64-32-sse2i:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o" \
		CFLAGS="$(CFLAGS) -m32 -msse2 -DHAVE_CRYPT -DHAVE_DL -DUSING_ICC_S_FILE" \
		ASFLAGS="$(ASFLAGS) -m32 -msse2" \
		LDFLAGS="$(LDFLAGS) -m32 -lcrypt -ldl"

linux-x86-64-32-mmx:
	$(LN) x86-mmx.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-mmx.o sha1-mmx.o md4-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -m32 -DHAVE_CRYPT -DHAVE_DL" \
		ASFLAGS="$(ASFLAGS) -m32" \
		LDFLAGS="$(LDFLAGS) -m32 -lcrypt -ldl"

linux-x86-64-32-any:
	$(LN) x86-any.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o" \
		CFLAGS="$(CFLAGS) -m32 -DHAVE_CRYPT -DHAVE_DL" \
		ASFLAGS="$(ASFLAGS) -m32" \
		LDFLAGS="$(LDFLAGS) -m32 -lcrypt -ldl"

linux-x86-avx:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		CFLAGS_MAIN="$(CFLAGS) -m32 -DJOHN_AVX -DHAVE_CRYPT" \
		CFLAGS="$(CFLAGS) -m32 -mavx -DHAVE_CRYPT" \
		ASFLAGS="$(ASFLAGS) -m32 -mavx" \
		LDFLAGS="$(LDFLAGS) -m32 -lcrypt"

linux-x86-xop:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		CFLAGS_MAIN="$(CFLAGS) -m32 -DJOHN_XOP -DHAVE_CRYPT" \
		CFLAGS="$(CFLAGS) -m32 -mxop -DHAVE_CRYPT" \
		ASFLAGS="$(ASFLAGS) -m32 -mxop" \
		LDFLAGS="$(LDFLAGS) -m32 -lcrypt"

linux-x86-gpu:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) $(OCL_OBJS) $(CUDA_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o" \
		CFLAGS="$(CFLAGS) -I$(OCLROOT)/include -DHAVE_CRYPT -DCL_VERSION_1_0 -DHAVE_CUDA -DHAVE_DL -DUSING_ICC_S_FILE" \
		LDFLAGS="$(LDFLAGS) -L$(OCLROOT)/lib/x86 -L$(OCLROOT)/lib -L$(CUDAPATH) -lcrypt -lOpenCL -ldl -lcudart"
	$(CP) opencl/*.cl ../run/
	$(CP) opencl_*.h ../run/

linux-x86-opencl:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) $(OCL_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o" \
		CFLAGS="$(CFLAGS) -I$(OCLROOT)/include -DHAVE_CRYPT -DCL_VERSION_1_0 -DHAVE_DL -DUSING_ICC_S_FILE" \
		LDFLAGS="$(LDFLAGS) -L$(OCLROOT)/lib/x86 -L$(OCLROOT)/lib -lcrypt -lOpenCL -ldl"
	$(CP) opencl/*.cl ../run/
	$(CP) opencl_*.h ../run/

linux-x86-cuda:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) $(CUDA_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -DHAVE_DL -DHAVE_CUDA -DUSING_ICC_S_FILE" \
		LDFLAGS="$(LDFLAGS) -L$(CUDAPATH) -lcrypt -ldl -lcudart"

linux-x86-native:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -DHAVE_DL -march=native" \
		ASFLAGS="$(ASFLAGS) -march=native" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl -march=native"

linux-x86-sse2:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -msse2 -DHAVE_CRYPT -DHAVE_DL" \
		ASFLAGS="$(ASFLAGS) -msse2" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl"

linux-x86-sse2i:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o" \
		CFLAGS="$(CFLAGS) -msse2 -DHAVE_CRYPT -DHAVE_DL -DUSING_ICC_S_FILE" \
		ASFLAGS="$(ASFLAGS) -msse2" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl"

linux-x86-mmx:
	$(LN) x86-mmx.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-mmx.o sha1-mmx.o md4-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -DHAVE_DL" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl"

linux-x86-any:
	$(LN) x86-any.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -DHAVE_DL" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl"

linux-x86-clang:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		CFLAGS="-Wall -c -O2 -I/usr/include -msse2 -DHAVE_CRYPT -DHAVE_DL $(HAVE_NSS) $(HAVE_GMP) $(HAVE_KRB5) $(OMPFLAGS) $(JOHN_CFLAGS)" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl" \
		CPP="clang" CC="clang" AS="clang" LD="clang"

linux-x86-clang-debug:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		CFLAGS="-Wall -Wdeclaration-after-statement -c -g -O1 -faddress-sanitizer -I/usr/include -msse2 -DHAVE_CRYPT -DHAVE_DL $(HAVE_NSS) $(HAVE_GMP) $(HAVE_KRB5) $(OMPFLAGS) $(JOHN_CFLAGS)" \
		LDFLAGS="-L/usr/local/lib -L/usr/local/ssl/lib -lssl -lcrypto -lm -lz -lcrypt -ldl -faddress-sanitizer $(NSS_LDFLAGS) $(GMP_LDFLAGS) $(KRB5_LDFLAGS)" \
		CPP="clang" CC="clang" AS="clang" LD="clang"

linux-alpha:
	$(LN) alpha.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o alpha.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -DHAVE_DL" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl"

# This target is currently "undocumented" as ccc generates much slower
# code for the large unrolled loops in John; let's hope it gets fixed.
linux-alpha-ccc:
	$(LN) alpha.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o alpha.o" \
		CC=ccc \
		CFLAGS="-c -Wf,-switch,noil_schedule -DHAVE_CRYPT -DHAVE_DL" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl" \
		OPT_NORMAL="-fast" \
		OPT_INLINE="-O2 -arch host"

linux-sparc:
	$(LN) sparc32.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -DHAVE_DL" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl"

linux-ppc32-altivec:
	$(LN) ppc32alt.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -DHAVE_DL" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl" \
		OPT_INLINE="-finline-functions -finline-limit=4000 -maltivec"

linux-ppc32:
	$(LN) ppc32.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -DHAVE_DL" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl"

# This is slightly slower than linux-ppc32-altivec for most hash types.
linux-ppc64-altivec:
	$(LN) ppc64alt.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -m64 -DHAVE_CRYPT -DHAVE_DL" \
		LDFLAGS="$(LDFLAGS) -m64 -lcrypt -ldl" \
		OPT_INLINE="-finline-functions -finline-limit=4000 -maltivec"

linux-ppc64:
	$(LN) ppc64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -m64 -DHAVE_CRYPT -DHAVE_DL" \
		LDFLAGS="$(LDFLAGS) -m64 -lcrypt -ldl" \
		OPT_INLINE="-finline-functions -finline-limit=4000"

linux-ia64:
	$(LN) ia64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -DHAVE_DL" \
		LDFLAGS="$(LDFLAGS) -lcrypt -ldl"

freebsd-x86-64:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86-64.o sse-intrinsics.o"

freebsd-x86-64i:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86-64.o sse-intrinsics-64.o" \
		CFLAGS="$(CFLAGS) -DUSING_ICC_S_FILE"

freebsd-x86-sse2:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

freebsd-x86-sse2i:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o" \
		CFLAGS="$(CFLAGS) -msse2 -DUSING_ICC_S_FILE" \
		ASFLAGS="$(ASFLAGS) -msse2 -DBSD" \

freebsd-x86-mmx:
	$(LN) x86-mmx.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md4-mmx.o md5-mmx.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

freebsd-x86-any:
	$(LN) x86-any.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

freebsd-x86-any-a.out:
	$(LN) x86-any.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DALIGN_LOG -DBSD"

freebsd-alpha:
	$(LN) alpha.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) alpha.o"

openbsd-x86-64:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86-64.o sse-intrinsics.o"

openbsd-x86-64i:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86-64.o sse-intrinsics-64.o" \
		CFLAGS="$(CFLAGS) -DUSING_ICC_S_FILE"

openbsd-x86-sse2:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

openbsd-x86-sse2i:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o" \
		CFLAGS="$(CFLAGS) -msse2 -DUSING_ICC_S_FILE" \
		ASFLAGS="$(ASFLAGS) -msse2 -DBSD"

openbsd-x86-mmx:
	$(LN) x86-mmx.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md4-mmx.o md5-mmx.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

openbsd-x86-any:
	$(LN) x86-any.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

openbsd-x86-any-a.out:
	$(LN) x86-any.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DALIGN_LOG -DBSD"

openbsd-alpha:
	$(LN) alpha.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) alpha.o"

openbsd-sparc64:
	$(LN) sparc64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CFLAGS="$(CFLAGS) -m64 -mcpu=ultrasparc" \
		LDFLAGS="$(LDFLAGS) -m64"

openbsd-sparc:
	$(LN) sparc32.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ)

openbsd-ppc32:
	$(LN) ppc32.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ)

openbsd-ppc64:
	$(LN) ppc64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CFLAGS="$(CFLAGS) -m64" \
		LDFLAGS="$(LDFLAGS) -m64" \
		OPT_INLINE="-finline-functions -finline-limit=4000"

openbsd-pa-risc:
	$(LN) pa-risc.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CFLAGS="-c -Wall -O3 -fomit-frame-pointer"

openbsd-vax:
	$(LN) vax.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ)

netbsd-sparc64:
	$(LN) sparc64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CFLAGS="$(CFLAGS) -m64 -mcpu=ultrasparc" \
		LDFLAGS="$(LDFLAGS) -m64"

netbsd-vax:
	$(LN) vax.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ)

solaris-sparc64-cc:
	$(RM) arch.h
	$(LN) sparc64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CC=cc \
		CFLAGS="-c -fast -xarch=native64 -DHAVE_CRYPT $(OMPFLAGS)" \
		LDFLAGS="-s -xarch=native64 $(OMPFLAGS) -lc $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-sparc64-gcc:
	$(RM) arch.h
	$(LN) sparc64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -m64 -mcpu=ultrasparc -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -m64 $(LDFLAGS_SOLARIS)"

solaris-sparcv9-cc:
	$(RM) arch.h
	$(LN) sparc32.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CC=cc \
		CFLAGS="-c -xO4 -xarch=v8plusa -xchip=ultra -DHAVE_CRYPT $(OMPFLAGS)" \
		LDFLAGS="-s $(OMPFLAGS) -lc $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-sparcv8-cc:
	$(RM) arch.h
	$(LN) sparc32.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CC=cc \
		CFLAGS="-c -xO4 -xarch=v8 -DHAVE_CRYPT $(OMPFLAGS)" \
		LDFLAGS="-s $(OMPFLAGS) -lc $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-sparc-gcc:
	$(RM) arch.h
	$(LN) sparc32.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) $(LDFLAGS_SOLARIS)"

solaris-x86-64-cc:
	$(RM) arch.h
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o sse-intrinsics.o" \
		CC=cc \
		CFLAGS="-c -fast -xarch=native64 -DHAVE_CRYPT $(OMPFLAGS)" \
		ASFLAGS="-c -xarch=native64 $(OMPFLAGS)" \
		LDFLAGS="-s -xarch=native64 $(OMPFLAGS) $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-x86-64-gcc:
	$(RM) arch.h
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -m64 -DHAVE_CRYPT" \
		ASFLAGS="$(CFLAGS) -m64" \
		LDFLAGS="$(LDFLAGS) -m64 $(LDFLAGS_SOLARIS)"

solaris-x86-64i-gcc:
	$(RM) arch.h
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o x86-64.o sse-intrinsics-64.o" \
		CFLAGS="$(CFLAGS) -m64 -DHAVE_CRYPT -DUSING_ICC_S_FILE" \
		ASFLAGS="$(CFLAGS) -m64" \
		LDFLAGS="$(LDFLAGS) -m64 $(LDFLAGS_SOLARIS)"

solaris-x86-sse2-cc:
	$(RM) arch.h
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o solaris-x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o" \
		CC=cc \
		CFLAGS="-c -fast -xarch=native -DHAVE_CRYPT $(OMPFLAGS)" \
		ASFLAGS="-c -xarch=native $(OMPFLAGS)" \
		LDFLAGS="-s -xarch=native $(OMPFLAGS) $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-x86-sse2-gcc:
	$(RM) arch.h
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o solaris-x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) $(LDFLAGS_SOLARIS)"

solaris-x86-sse2i-gcc:
	$(RM) arch.h
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o solaris-x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT -msse2 -DUSING_ICC_S_FILE" \
		ASFLAGS="$(ASFLAGS) -msse2" \
		LDFLAGS="$(LDFLAGS) $(LDFLAGS_SOLARIS)"

solaris-x86-mmx-cc:
	$(RM) arch.h
	$(LN) x86-mmx.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o solaris-x86.o x86-mmx.o sha1-mmx.o md4-mmx.o md5-mmx.o" \
		CC=cc \
		CFLAGS="-c -fast -xarch=native -DHAVE_CRYPT $(OMPFLAGS)" \
		ASFLAGS="-c -xarch=native $(OMPFLAGS)" \
		LDFLAGS="-s -xarch=native $(OMPFLAGS) $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-x86-mmx-gcc:
	$(RM) arch.h
	$(LN) x86-mmx.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o solaris-x86.o x86-mmx.o sha1-mmx.o md4-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) $(LDFLAGS_SOLARIS)"

solaris-x86-any-cc:
	$(RM) arch.h
	ln -s x86-any.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		SHELL=/bin/sh \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o solaris-x86.o" \
		CC=cc \
		CFLAGS="-c -xO4 -DHAVE_CRYPT $(OMPFLAGS)" \
		ASFLAGS="-c $(OMPFLAGS)" \
		LDFLAGS="-s $(OMPFLAGS) -lc $(LDFLAGS_SOLARIS)" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-x86-any-gcc:
	$(RM) arch.h
	ln -s x86-any.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		SHELL=/bin/sh \
		JOHN_OBJS="$(JOHN_OBJS) c3_fmt.o solaris-x86.o" \
		CFLAGS="$(CFLAGS) -DHAVE_CRYPT" \
		LDFLAGS="$(LDFLAGS) -lc $(LDFLAGS_SOLARIS)"

# Older versions of Sun's assembler had a line length restriction (and some
# other problems, which affect newer versions as well and which are worked
# around in x86.S).
solaris-x86.o: x86.S
	$(CPP) $(CPPFLAGS) -P -DDUMBAS x86.S | $(TR) \; \\n > tmp.s
	$(AS) $(ASFLAGS) tmp.s -o solaris-x86.o
	$(RM) tmp.s

sco-x86-any-gcc:
	$(RM) arch.h
	ln -s x86-any.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		SHELL=/bin/sh \
		JOHN_OBJS="$(JOHN_OBJS) sco-x86.o"

sco-x86-any-cc:
	$(RM) arch.h
	ln -s x86-any.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		SHELL=/bin/sh \
		JOHN_OBJS="$(JOHN_OBJS) sco-x86.o" \
		CC=cc \
		CFLAGS="-c -b elf -O3" \
		ASFLAGS="-c -b elf" \
		OPT_NORMAL="-K loop_unroll,no_inline" \
		OPT_INLINE="-K inline"

# SCO is even worse than Solaris x86
sco-x86.o: x86.S
	$(CPP) $(CPPFLAGS) -DDUMBAS x86.S | \
		$(TR) \; \\n | $(SED) 's/\([%.]\) /\1/g' > tmp.s
	$(AS) $(ASFLAGS) tmp.s -o sco-x86.o
	$(RM) tmp.s

tru64-alpha:
	$(LN) alpha.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) digipaq-alpha.o" \
		CC=cc \
		CFLAGS="-c -O4 -arch host" \
		OPT_NORMAL="" \
		OPT_INLINE="-inline all"

# Digital/Compaq's cc and make use the .S suffix for a different purpose...
digipaq-alpha.o: alpha.S
	$(CPP) $(CPPFLAGS) alpha.S > tmp.s
	$(AS) $(ASFLAGS) tmp.s -o digipaq-alpha.o
	$(RM) tmp.s

aix-ppc32:
	$(LN) ppc32.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CC=cc \
		CFLAGS="-c -qunroll=2 -qarch=ppc -qchars=signed" \
		LDFLAGS="$(LDFLAGS) -lbsd" \
		OPT_NORMAL="-O2" \
		OPT_INLINE="-O3 -Q=99 -w"

macosx-x86-64-gpu:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) $(OCL_OBJS) $(CUDA_OBJS) x86-64.o sse-intrinsics.o" \
		ASFLAGS="$(ASFLAGS) -m64 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -m64 -I$(OCLROOT)/include -DBSD -DCL_VERSION_1_0 -DHAVE_CUDA -Wno-deprecated-declarations" \
		LDFLAGS="$(LDFLAGS) -m64 -L$(CUDAPATH) -lcudart -framework OpenCL" \
		NVCC_FLAGS="$(NVCC_FLAGS) -m64"
	$(CP) opencl/*.cl ../run/
	$(CP) opencl_*.h ../run/

macosx-x86-64-opencl:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) $(OCL_OBJS) x86-64.o sse-intrinsics.o" \
		ASFLAGS="$(ASFLAGS) -m64 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -m64 -I$(OCLROOT)/include -DBSD -DCL_VERSION_1_0 -Wno-deprecated-declarations" \
		LDFLAGS="$(LDFLAGS) -m64 -framework OpenCL" \
		NVCC_FLAGS="$(NVCC_FLAGS) -m64"
	$(CP) opencl/*.cl ../run/
	$(CP) opencl_*.h ../run/

macosx-x86-64-cuda:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) $(CUDA_OBJS) x86-64.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -DBSD -DHAVE_CUDA -m64 -Wno-deprecated-declarations" \
		ASFLAGS="$(ASFLAGS) -m64 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		LDFLAGS="$(LDFLAGS) -m64 -L$(CUDAPATH) -lcudart" \
		NVCC_FLAGS="$(NVCC_FLAGS) -m64"

macosx-x86-64:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86-64.o sse-intrinsics.o" \
		ASFLAGS="$(ASFLAGS) -m64 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -m64 -Wno-deprecated-declarations" \
		LDFLAGS="$(LDFLAGS) -m64"

macosx-x86-64i:
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86-64.o sse-intrinsics-64.o" \
		ASFLAGS="$(ASFLAGS) -m64 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -m64 -DUSING_ICC_S_FILE -Wno-deprecated-declarations" \
		LDFLAGS="$(LDFLAGS) -m64"

macosx-x86-sse2:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		ASFLAGS="$(ASFLAGS) -m32 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -m32 -Wno-deprecated-declarations" \
		LDFLAGS="$(LDFLAGS) -m32"

macosx-x86-sse2i:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o" \
		ASFLAGS="$(ASFLAGS) -m32 -msse2 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -m32 -msse2 -DUSING_ICC_S_FILE -Wno-deprecated-declarations" \
		LDFLAGS="$(LDFLAGS) -m32"

macosx-x86-mmx:
	$(LN) x86-mmx.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md4-mmx.o md5-mmx.o" \
		ASFLAGS="$(ASFLAGS) -m32 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -m32 -Wno-deprecated-declarations" \
		LDFLAGS="$(LDFLAGS) -m32"

macosx-ppc32-altivec:
	$(LN) ppc32alt.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CFLAGS="-c -Wall -fomit-frame-pointer" \
		OPT_NORMAL="-fast -mcpu=7450" \
		OPT_INLINE="-fast -mcpu=7450 -finline-limit=4000 -faltivec -maltivec"

# The -cross targets can be used to compile PowerPC binaries on x86.
macosx-ppc32-altivec-cross:
	$(LN) ppc32alt.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		ASFLAGS="$(ASFLAGS) -arch ppc" \
		CFLAGS="-c -Wall -arch ppc -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -arch ppc" \
		OPT_NORMAL="-fast -mcpu=7450" \
		OPT_INLINE="-fast -mcpu=7450 -finline-limit=4000 -faltivec -maltivec"

# "cc -traditional-cpp" was needed on older versions of Mac OS X; it might
# actually be problematic on current ones, but those will hopefully use other
# make targets anyway (e.g., macosx-ppc32-altivec above).
macosx-ppc32:
	$(LN) ppc32.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CC=cc \
		CFLAGS="-c -traditional-cpp" \
		OPT_NORMAL="-O2" \
		OPT_INLINE="-O3"

macosx-ppc32-cross:
	$(LN) ppc32.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		ASFLAGS="$(ASFLAGS) -arch ppc" \
		CFLAGS="-c -Wall -arch ppc -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -arch ppc" \
		OPT_NORMAL="-O2" \
		OPT_INLINE="-O3 -finline-limit=4000"

# This is slightly slower than macosx-ppc32-altivec for most hash types.
macosx-ppc64-altivec:
	$(LN) ppc64alt.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CFLAGS="-c -m64 -Wall -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -m64" \
		OPT_NORMAL="-fast" \
		OPT_INLINE="-fast -finline-limit=4000 -faltivec -maltivec"

macosx-ppc64-altivec-cross:
	$(LN) ppc64alt.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		ASFLAGS="$(ASFLAGS) -arch ppc" \
		CFLAGS="-c -arch ppc -m64 -Wall -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -arch ppc -m64" \
		OPT_NORMAL="-fast" \
		OPT_INLINE="-fast -finline-limit=4000 -faltivec -maltivec"

macosx-ppc64:
	$(LN) ppc64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CFLAGS="-c -m64 -Wall -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -m64" \
		OPT_NORMAL="-fast" \
		OPT_INLINE="-fast -finline-limit=4000"

macosx-ppc64-cross:
	$(LN) ppc64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		ASFLAGS="$(ASFLAGS) -arch ppc" \
		CFLAGS="-c -arch ppc -m64 -Wall -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -arch ppc -m64" \
		OPT_NORMAL="-fast" \
		OPT_INLINE="-fast -finline-limit=4000"

john-macosx-x86-64:
	$(RM) *.o
	$(LN) x86-64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86-64.o sse-intrinsics.o" \
		ASFLAGS="$(ASFLAGS) -arch x86_64 -m64 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -arch x86_64 -m64" \
		LDFLAGS="$(LDFLAGS) -arch x86_64 -m64"
	mv ../run/john john-macosx-x86-64

john-macosx-x86:
	$(RM) *.o
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		ASFLAGS="$(ASFLAGS) -arch i386 -m32 -DUNDERSCORES -DBSD -DALIGN_LOG" \
		CFLAGS="$(CFLAGS) -arch i386 -m32" \
		LDFLAGS="$(LDFLAGS) -arch i386 -m32"
	mv ../run/john john-macosx-x86

john-macosx-ppc:
	$(RM) *.o
	$(LN) ppc32alt.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		ASFLAGS="$(ASFLAGS) -arch ppc" \
		CFLAGS="-c -Wall -arch ppc -fomit-frame-pointer" \
		LDFLAGS="$(LDFLAGS) -arch ppc" \
		OPT_NORMAL="-fast -mcpu=7450" \
		OPT_INLINE="-fast -mcpu=7450 -finline-limit=4000 -faltivec -maltivec"
	mv ../run/john john-macosx-ppc

macosx-universal: john-macosx-x86-64 john-macosx-x86 john-macosx-ppc
	lipo -create john-macosx-x86-64 john-macosx-x86 john-macosx-ppc \
		-output ../run/john

hpux-pa-risc-gcc:
	$(LN) pa-risc.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CFLAGS="-c -Wall -O3 -fomit-frame-pointer"

hpux-pa-risc-cc:
	$(LN) pa-risc.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CC=cc \
		CFLAGS="-c -Aa -D_HPUX_SOURCE -DANSI_CPP" \
		OPT_NORMAL="+O2" \
		OPT_INLINE="+O3 +Oinline"

irix-mips64-r10k:
	$(LN) mips64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CC=cc \
		CFLAGS="-c -O2 -64 -mips4 -r10000 -signed" \
		LDFLAGS="$(LDFLAGS) -64 -mips4 -r10000" \
		OPT_NORMAL="-LNO:opt=1 -OPT:Olimit=2194" \
		OPT_INLINE="-INLINE:all"

irix-mips64:
	$(LN) mips64.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CC=cc \
		CFLAGS="-c -O2 -64 -mips3 -signed" \
		LDFLAGS="$(LDFLAGS) -64 -mips3" \
		OPT_NORMAL="-LNO:opt=1 -OPT:Olimit=2194" \
		OPT_INLINE="-INLINE:all"

irix-mips32:
	$(LN) mips32.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		CC=cc \
		CFLAGS="-c -O2 -32 -signed" \
		LDFLAGS="$(LDFLAGS) -32" \
		OPT_NORMAL="-LNO:opt=1 -OPT:Olimit=2194" \
		OPT_INLINE="-INLINE:all"

#	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
# Not sure we can do the above.  Thus we set the 'no build' rule

dos-djgpp-x86-mmx:
	copy x86-mmx.h arch.h
	$(MAKE) $(PROJ_DOS) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md4-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -DNO_JOHN_BLD -mpreferred-stack-boundary=2" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DALIGN_LOG"

dos-djgpp-x86-any:
	copy x86-any.h arch.h
	$(MAKE) $(PROJ_DOS) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		CFLAGS="$(CFLAGS) -DNO_JOHN_BLD -mpreferred-stack-boundary=2" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DALIGN_LOG"

win32-cygwin-x86-sse2i:
	$(CP) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ_WIN32) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o" \
		CFLAGS="$(CFLAGS) -Wall -mpreferred-stack-boundary=4 -msse2 -m32 -DUSING_ICC_S_FILE" \
		ASFLAGS="$(ASFLAGS) -msse2 -m32 -DUNDERSCORES"

win32-cygwin-x86-sse2:
	$(CP) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ_WIN32) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=4 -msse2 -m32" \
		ASFLAGS="$(ASFLAGS) -msse2 -m32 -DUNDERSCORES"

win32-cygwin-x86-mmx:
	$(CP) x86-mmx.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ_WIN32) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md4-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=3" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES"

win32-cygwin-x86-any:
	$(CP) x86-any.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ_WIN32) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=2" \
		CFLAGS_MAIN="$(CFLAGS) -O0" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES"

win32-mingw-x86-sse2i:
	$(CP) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ_WIN32_MINGW) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics-32.o" \
		CFLAGS="$(CFLAGS) -Wall -mpreferred-stack-boundary=4 -msse2 -m32 -DUSING_ICC_S_FILE" \
		ASFLAGS="$(ASFLAGS) -msse2 -m32  -DUNDERSCORES"

win32-mingw-x86-sse2:
	$(CP) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ_WIN32_MINGW) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o sse-intrinsics.o" \
		CFLAGS="$(CFLAGS) -Wall -mpreferred-stack-boundary=4 -msse2 -m32" \
		ASFLAGS="$(ASFLAGS) -msse2 -m32 -DUNDERSCORES"

win32-mingw-x86-mmx:
	$(CP) x86-mmx.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ_WIN32_MINGW) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md4-mmx.o md5-mmx.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=3 -mmmx -m32" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES"

win32-mingw-x86-any:
	$(CP) x86-any.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ_WIN32_MINGW) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		CFLAGS="$(CFLAGS) -Wall -mpreferred-stack-boundary=2 -m32" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES"

beos-x86-sse2:
	$(LN) x86-sse.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-sse.o sha1-mmx.o md4-mmx.o md5-mmx.o"

beos-x86-mmx:
	$(LN) x86-mmx.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o sha1-mmx.o md4-mmx.o md5-mmx.o"

beos-x86-any:
	$(LN) x86-any.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o"

generic: generic.h
	$(RM) arch.h
	ln -s generic.h arch.h
	@echo "#define JOHN_BLD" '"'$@'"' > john_build_rule.h
	$(MAKE) $(PROJ)

generic.h:
	$(RM) arch.h
	$(CC) $(CFLAGS) detect.c
	$(LD) detect.o $(LDFLAGS) -o detect
	./best.sh "$(MAKE)" \
		"$(BENCH_DES_OBJS_DEPEND)" \
		"$(BENCH_DES_BS_OBJS_DEPEND)" \
		"$(BENCH_MD5_OBJS_DEPEND)" \
		"$(BENCH_BF_OBJS_DEPEND)"

testpara:
	$(LN) x86-64.h arch.h
	perl ./para-best.pl "$(CC)" "$(MAKE)" \
		"$(BENCH_PARA_DEPEND)" "-msse2" 64

testpara-native:
	$(LN) x86-64.h arch.h
	perl ./para-best.pl "$(CC)" "$(MAKE)" \
		"$(BENCH_PARA_DEPEND)" "-march=native" 64

testpara32:
	$(LN) x86-sse.h arch.h
	CFLAGS="$(CFLAGS) -m32 -msse2" \
	perl ./para-best.pl "$(CC)" "$(MAKE)" \
		"$(BENCH_PARA_DEPEND)" "-m32 -msse2" 32

bench: $(BENCH_OBJS)
	$(LD) $(BENCH_OBJS) $(LDFLAGS) -o bench

para-bench64: $(PARA_BENCH_OBJS)
	$(LD) $(PARA_BENCH_OBJS) $(LDFLAGS) -o para-bench

para-bench32: $(PARA_BENCH_32_OBJS)
	$(LD) $(PARA_BENCH_32_OBJS) $(LDFLAGS) -o para-bench

cuda_common.o:	cuda/cuda_common.cuh cuda/cuda_common.cu
	cd cuda; nvcc $(NVCC_FLAGS) cuda_common.cu -o ../cuda_common.o

cuda_cryptmd5.o:  cuda_cryptmd5.h cuda/cryptmd5.cu cuda_common.o
	cd cuda; nvcc $(NVCC_FLAGS) cryptmd5.cu -o ../cuda_cryptmd5.o

cuda_cryptmd5_fmt.o: cuda_cryptmd5.o cuda_cryptmd5_fmt.c
	$(CC)  $(CFLAGS) cuda_cryptmd5_fmt.c -o cuda_cryptmd5_fmt.o

cuda_phpass.o:  cuda_phpass.h cuda/phpass.cu cuda_common.o
	cd cuda; nvcc $(NVCC_FLAGS) phpass.cu -o ../cuda_phpass.o

cuda_phpass_fmt.o: cuda_phpass.o cuda_phpass_fmt.c
	$(CC)  $(CFLAGS) cuda_phpass_fmt.c -o cuda_phpass_fmt.o

cuda_cryptsha256.o:  cuda_cryptsha256.h cuda/cryptsha256.cu cuda_common.o
	cd cuda; nvcc $(NVCC_FLAGS) cryptsha256.cu -o ../cuda_cryptsha256.o

cuda_cryptsha256_fmt.o: cuda_cryptsha256.o cuda_cryptsha256_fmt.c
	$(CC)  $(CFLAGS) cuda_cryptsha256_fmt.c -o cuda_cryptsha256_fmt.o

cuda_cryptsha512.o:  cuda_cryptsha512.h cuda/cryptsha512.cu cuda_common.o
	cd cuda; nvcc $(NVCC_FLAGS) cryptsha512.cu -o ../cuda_cryptsha512.o

cuda_cryptsha512_fmt.o: cuda_cryptsha512.o cuda_cryptsha512_fmt.c
	$(CC)  $(CFLAGS) cuda_cryptsha512_fmt.c -o cuda_cryptsha512_fmt.o

cuda_mscash2.o:  cuda_mscash2.h cuda/mscash2.cu cuda_common.o
	cd cuda; nvcc $(NVCC_FLAGS) mscash2.cu -o ../cuda_mscash2.o

cuda_mscash2_fmt.o: cuda_mscash2.o cuda_mscash2_fmt.c
	$(CC)  $(CFLAGS) cuda_mscash2_fmt.c -o cuda_mscash2_fmt.o

cuda_mscash.o:  cuda_mscash.h cuda/mscash.cu cuda_common.o
	cd cuda; nvcc $(NVCC_FLAGS) mscash.cu -o ../cuda_mscash.o

cuda_mscash_fmt.o: cuda_mscash.o cuda_mscash_fmt.c
	$(CC)  $(CFLAGS) cuda_mscash_fmt.c -o cuda_mscash_fmt.o

cuda_rawsha256.o:  cuda_rawsha256.h cuda/rawsha256.cu cuda_common.o
	cd cuda; nvcc $(NVCC_FLAGS) -DSHA256 rawsha256.cu -o ../cuda_rawsha256.o

cuda_rawsha256_fmt.o: cuda_rawsha256.o cuda_rawsha256_fmt.c
	$(CC)  $(CFLAGS) -DSHA256 cuda_rawsha256_fmt.c -o cuda_rawsha256_fmt.o

cuda_rawsha224.o:  cuda_rawsha256.h cuda/rawsha256.cu cuda_common.o
	cd cuda; nvcc $(NVCC_FLAGS) -DSHA224 rawsha256.cu -o ../cuda_rawsha224.o

cuda_rawsha224_fmt.o: cuda_rawsha224.o cuda_rawsha256_fmt.c
	$(CC)  $(CFLAGS) -DSHA224 cuda_rawsha256_fmt.c -o cuda_rawsha224_fmt.o

cuda_xsha512.o: cuda_xsha512.h cuda/xsha512.cu cuda_common.o
	cd cuda; nvcc $(NVCC_FLAGS) xsha512.cu -o ../cuda_xsha512.o

cuda_xsha512_fmt.o: cuda_xsha512.o cuda_xsha512_fmt.c
	$(CC) $(CFLAGS) cuda_xsha512_fmt.c -o cuda_xsha512_fmt.o

cuda_wpapsk.o:  cuda/wpapsk.cu cuda_common.o
	cd cuda; nvcc $(NVCC_FLAGS) wpapsk.cu -o ../cuda_wpapsk.o

cuda_wpapsk_fmt.o: cuda_wpapsk.o cuda_wpapsk_fmt.c
	$(CC)  $(CFLAGS) cuda_wpapsk_fmt.c -o cuda_wpapsk_fmt.o

cuda_rawsha512.o: cuda_rawsha512.h cuda/rawsha512.cu cuda_common.o
	cd cuda; nvcc $(NVCC_FLAGS) rawsha512.cu -o ../cuda_rawsha512.o

cuda_rawsha512_fmt.o: cuda_rawsha512.o cuda_rawsha512_fmt.c
	$(CC) $(CFLAGS) cuda_rawsha512_fmt.c -o cuda_rawsha512_fmt.o

cuda_pwsafe.o: cuda/pwsafe.cu cuda_common.o
	cd cuda; nvcc $(NVCC_FLAGS) pwsafe.cu -o ../cuda_pwsafe.o

cuda_pwsafe_fmt.o: cuda_pwsafe.o cuda_pwsafe_fmt.c
	$(CC)  $(CFLAGS) cuda_pwsafe_fmt.c -o cuda_pwsafe_fmt.o

../run/john: $(JOHN_OBJS)
	$(LD) $(JOHN_OBJS) $(LDFLAGS) -o ../run/john

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

../run/pfx2john: ../run/john
	$(RM) ../run/pfx2john
	ln -s john ../run/pfx2john

../run/keepass2john: ../run/john
	$(RM) ../run/keepass2john
	ln -s john ../run/keepass2john

../run/zip2john: ../run/john
	$(RM) ../run/zip2john
	ln -s john ../run/zip2john

../run/pdf2john: ../run/john
	$(RM) ../run/pdf2john
	ln -s john ../run/pdf2john

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

../run/pwsafe2john: ../run/john
	$(RM) ../run/pwsafe2john
	ln -s john ../run/pwsafe2john

../run/hccap2john: ../run/john
	$(RM) ../run/hccap2john
	ln -s john ../run/hccap2john

../run/unique: ../run/john
	$(RM) ../run/unique
	ln -s john ../run/unique

../run/to_dyna: to_dyna.c
	$(CC) -o ../run/to_dyna to_dyna.c

../run/to_dyna.exe: to_dyna.c
	$(CC) -o ../run/to_dyna.exe to_dyna.c

../run/john.bin: $(JOHN_OBJS)
	$(LD) $(JOHN_OBJS) $(LDFLAGS) -o ../run/john.exe
	if exist ..\run\john.bin del ..\run\john.bin
	ren ..\run\john.exe john.bin

../run/john.com: john.com
	copy john.com ..\run\john.com

../run/unshadow.com: john.com
	copy john.com ..\run\unshadow.com

../run/unafs.com: john.com
	copy john.com ..\run\unafs.com

../run/undrop.com: john.com
	copy john.com ..\run\undrop.com

../run/ssh2john.com: john.com
	copy john.com ..\run\ssh2john.com

../run/pfx2john.com: john.com
	copy john.com ..\run\pfx2john.com

../run/keepass2john.com: john.com
	copy john.com ..\run\keepass2john.com

../run/pdf2john.com: john.com
	copy john.com ..\run\pdf2john.com

../run/rar2john.com: john.com
	copy john.com ..\run\rar2john.com

../run/mozilla2john.com: john.com
ifdef HAVE_NSS
	copy john.com ..\run\mozilla2john.com
endif

../run/racf2john.com: john.com
	copy john.com ..\run\racf2john.com

../run/keychain2john.com: john.com
	copy john.com ..\run\keychain2john.com

../run/pwsafe2john.com: john.com
	copy john.com ..\run\pwsafe2john.com

../run/zip2john.com: john.com
	copy john.com ..\run\zip2john.com

../run/hccap2john.com: john.com
	copy john.com ..\run\hccap2john.com

../run/unique.com: john.com
	copy john.com ..\run\unique.com

john.local.conf:
	[ -f ../run/john.local.conf ] || touch ../run/john.local.conf

john.com: john.asm
	@echo Use Borland TASM/TLINK to make JOHN.COM

# this LD line removed from the ../run/john.exe rule (Cygwin builds)
# this change needed for full openssl linking, in 1.7.7-jumbo-6
# this comment should stay for a jumbo or 2, to make sure this does not break
# other peoples cygwin builds.
#	$(LD) $(JOHN_OBJS) -lkernel32 -lcrypto -o ../run/john.exe

../run/john.exe: $(JOHN_OBJS)
	$(LD) $(JOHN_OBJS) $(LDFLAGS) -lkernel32 -o ../run/john.exe
	strip ../run/john.exe

# this LD line removed from the ../run/john-mingw.exe rule (MinGW32 builds)
# this change needed for full openssl linking, in 1.7.7-jumbo-6
#	$(LD) $(JOHN_OBJS) -lkernel32 -leay32 -o ../run/john-mingw.exe
#	$(LD) $(JOHN_OBJS) $(LDFLAGS) -lkernel32 -o ../run/john-mingw.exe

../run/john-mingw.exe: $(JOHN_OBJS)
	$(LD) $(JOHN_OBJS) $(LDFLAGS) -lkernel32 -o ../run/john-mingw.exe
	strip ../run/john-mingw.exe
	cp ../run/john-mingw.exe ../run/john.exe

../run/unshadow.exe: symlink.c
	$(CC) symlink.c -o ../run/unshadow.exe
	strip ../run/unshadow.exe

../run/unafs.exe: symlink.c
	$(CC) symlink.c -o ../run/unafs.exe
	strip ../run/unafs.exe

../run/undrop.exe: symlink.c
	$(CC) symlink.c -o ../run/undrop.exe
	strip ../run/undrop.exe

../run/ssh2john.exe: symlink.c
	$(CC) symlink.c -o ../run/ssh2john.exe
	strip ../run/ssh2john.exe

../run/pfx2john.exe: symlink.c
	$(CC) symlink.c -o ../run/pfx2john.exe
	strip ../run/pfx2john.exe

../run/keepass2john.exe: symlink.c
	$(CC) symlink.c -o ../run/keepass2john.exe
	strip ../run/keepass2john.exe

../run/pdf2john.exe: symlink.c
	$(CC) symlink.c -o ../run/pdf2john.exe
	strip ../run/pdf2john.exe

../run/rar2john.exe: symlink.c
	$(CC) symlink.c -o ../run/rar2john.exe
	strip ../run/rar2john.exe

../run/mozilla2john.exe: symlink.c
ifdef HAVE_NSS
	$(CC) symlink.c -o ../run/mozilla2john.exe
	strip ../run/mozilla2john.exe
endif

../run/racf2john.exe: symlink.c
	$(CC) symlink.c -o ../run/racf2john.exe
	strip ../run/racf2john.exe

../run/keychain2john.exe: symlink.c
	$(CC) symlink.c -o ../run/keychain2john.exe
	strip ../run/keychain2john.exe

../run/pwsafe2john.exe: symlink.c
	$(CC) symlink.c -o ../run/pwsafe2john.exe
	strip ../run/pwsafe2john.exe

../run/zip2john.exe: symlink.c
	$(CC) symlink.c -o ../run/zip2john.exe
	strip ../run/zip2john.exe

../run/hccap2john.exe: symlink.c
	$(CC) symlink.c -o ../run/hccap2john.exe
	strip ../run/hccap2john.exe

../run/unique.exe: symlink.c
	$(CC) symlink.c -o ../run/unique.exe
	strip ../run/unique.exe

../run/genmkvpwd: $(GENMKVPWD_OBJS)
	$(LD) $(GENMKVPWD_OBJS) $(LDFLAGS) -o ../run/genmkvpwd

../run/genmkvpwd.exe: $(GENMKVPWD_OBJS)
	$(LD) $(GENMKVPWD_OBJS) $(LDFLAGS_MKV) -o ../run/genmkvpwd.exe

../run/mkvcalcproba: mkvcalcproba.o
	$(LD) mkvcalcproba.o $(LDFLAGS) -o ../run/mkvcalcproba

../run/mkvcalcproba.exe: mkvcalcproba.o
	$(LD) mkvcalcproba.o $(LDFLAGS_MKV) -o ../run/mkvcalcproba.exe

../run/calc_stat: calc_stat.o
	$(LD) calc_stat.o $(LDFLAGS) -o ../run/calc_stat

../run/calc_stat.exe: calc_stat.o
	$(LD) calc_stat.o $(LDFLAGS_MKV) -o ../run/calc_stat.exe

../run/raw2dyna: raw2dyna.o
	$(LD) raw2dyna.o $(LDFLAGS) -o ../run/raw2dyna

../run/raw2dyna.exe: raw2dyna.o
	$(LD) raw2dyna.o $(LDFLAGS) -o ../run/raw2dyna.exe

SIPdump: SIPdump.o
	$(LD) SIPdump.o $(LDFLAGS) -lpcap -o ../run/SIPdump

vncpcap2john:
	g++ -Wall vncpcap2john.cpp -lpcap -o ../run/vncpcap2john

gpg2john:
	g++ -Wall gpg2john.cpp -lcrypto -o ../run/gpg2john

dmg2john:
	$(CC) -Wall dmg2john.c -lm -o ../run/dmg2john

office2john:
	$(CC) `xml2-config --cflags` `pkg-config --cflags libgsf-1` office2john.c common.o base64.o `pkg-config --libs libgsf-1` `xml2-config --libs` -o ../run/office2john

../run/tgtsnarf: tgtsnarf.o
	$(LD) tgtsnarf.o $(LDFLAGS) -o ../run/tgtsnarf

# Inlining the S-boxes produces faster code as long as they fit in the cache.
DES_bs_b.o: DES_bs_b.c sboxes.c nonstd.c sboxes-s.c
	$(CC) $(CFLAGS) $(OPT_INLINE) DES_bs_b.c

# This is for the BENCH build (to not depend upon unicode.o)
DES_bsg.o: DES_bs.c
	$(CC) $(CFLAGS) -DBENCH_BUILD DES_bs.c -o DES_bsg.o

# This is for the BENCH build (to not depend upon unicode.o)
config_g.o: config.c
	$(CC) $(CFLAGS) -DBENCH_BUILD config.c -o config_g.o

# This is for the BENCH build (to not depend upon options.o)
formats_g.o: formats.o
	$(CC) $(CFLAGS) -DBENCH_BUILD formats.c -o formats_g.o

miscnl.o: misc.c
	$(CC) $(CFLAGS) $(OPT_NORMAL) -D_JOHN_MISC_NO_LOG misc.c -o miscnl.o

bench-t.o: bench.c
	$(CC) $(CFLAGS) $(OPT_NORMAL) -D_JOHN_BENCH_TMP bench.c -o bench-t.o

fmt_externs.h: $(PLUGFORMATS_SRCS) Makefile
	LC_ALL=C $(SED) -n 's/^\(struct fmt_main [^ ]*\) =.*/extern \1;/p' *_fmt_plug.c > fmt_externs.h

fmt_registers.h: $(PLUGFORMATS_SRCS) Makefile
	LC_ALL=C $(SED) -n 's/^struct fmt_main \([^ ]*\) =.*/john_register_one(\&\1);/p' *_fmt_plug.c > fmt_registers.h

john.o: john.c fmt_externs.h fmt_registers.h
	$(CC) $(CFLAGS_MAIN) $(OPT_NORMAL) -O0 $*.c

.c.o:
	$(CC) $(CFLAGS) $(OPT_NORMAL) $*.c

.S.o:
	$(AS) $(ASFLAGS) $*.S

# We don't have any files with .s suffix, this is for compiling in DOS only
.s.o:
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

clean:
	$(RM) $(PROJ) $(PROJ_DOS) $(PROJ_WIN32) $(PROJ_WIN32_MINGW)
	$(RM) ../run/john.exe john-macosx-* *.o *.bak core
	$(RM) ../run/*.cl ../run/*.h ../run/office2john ../run/vncpcap2john
	$(RM) detect bench para-bench generic.h arch.h tmp.s
	$(RM) cuda/*.o cuda/*~ *~ ../run/SIPdump
	$(RM) fmt_registers.h fmt_externs.h john_build_rule.h
	$(CP) $(NULL) Makefile.dep

# For the time being, icc builds a better sse-intrinsics.S but this may
# change over time. NOTE that sse-intrinsics.S is never re-built unless you
# manually do a "make intrinsics".
intrinsics: clean-intrinsics sse-intrinsics-64.S sse-intrinsics-32.S

clean-intrinsics:
	$(RM) sse-intrinsics-64.S sse-intrinsics-32.S sse-intrinsics-win32.S

sse-intrinsics-64.S:
	$(LN) x86-64.h arch.h
	icc -S -o sse-intrinsics-64.S sse-intrinsics.c -O3 -fno-builtin -fno-verbose-asm -openmp -DUSING_ICC_S_FILE $(JOHN_CFLAGS) -Wall

sse-intrinsics-32.S:
	$(LN) x86-sse.h arch.h
	icc -m32 -S -o sse-intrinsics-32.S sse-intrinsics.c -O3 -fno-builtin -fno-verbose-asm -openmp -DUSING_ICC_S_FILE $(JOHN_CFLAGS) -Wall
	perl sse2i_winfix.pl sse-intrinsics-32.S sse-intrinsics-win32.S
	mv sse-intrinsics-win32.S sse-intrinsics-32.S

include Makefile.dep
