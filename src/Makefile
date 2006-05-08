#
# This file is part of John the Ripper password cracker,
# Copyright (c) 1996-2006 by Solar Designer
#

CPP = gcc
CC = gcc
AS = gcc
LD = gcc
CP = cp
LN = ln -sf
RM = rm -f
TR = tr
SED = sed
PERL = perl
NULL = /dev/null
CPPFLAGS = -E
CFLAGS = -c -Wall -O2 -fomit-frame-pointer
ASFLAGS = -c
LDFLAGS = -s
OPT_NORMAL = -funroll-loops
OPT_INLINE = -finline-functions

JOHN_OBJS_MINIMAL = \
	DES_fmt.o DES_std.o DES_bs.o \
	BSDI_fmt.o \
	MD5_fmt.o MD5_std.o \
	BF_fmt.o BF_std.o \
	AFS_fmt.o \
	LM_fmt.o \
	batch.o bench.o charset.o common.o compiler.o config.o cracker.o \
	crc32.o external.o formats.o getopt.o idle.o inc.o john.o list.o \
	loader.o logger.o math.o memory.o misc.o options.o params.o path.o \
	recovery.o rpp.o rules.o signals.o single.o status.o tty.o wordlist.o \
	unshadow.o \
	unafs.o \
	unique.o

JOHN_OBJS_ORIG = \
	$(JOHN_OBJS_MINIMAL) \
	DES_bs_b.o

JOHN_OBJS = \
	$(JOHN_OBJS_ORIG)

BENCH_DES_OBJS_ORIG = \
	DES_fmt.o DES_std.o

BENCH_DES_OBJS_DEPEND = \
	$(BENCH_DES_OBJS_ORIG)

BENCH_DES_BS_OBJS_DEPEND = \
	DES_bs_b.o

BENCH_MD5_OBJS_DEPEND = \
	MD5_fmt.o MD5_std.o

BENCH_BF_OBJS_DEPEND = \
	BF_std.o

BENCH_OBJS = \
	$(BENCH_DES_OBJS_DEPEND) \
	DES_bs.o $(BENCH_DES_BS_OBJS_DEPEND) \
	$(BENCH_MD5_OBJS_DEPEND) \
	BF_fmt.o $(BENCH_BF_OBJS_DEPEND) \
	bench.o best.o common.o config.o formats.o math.o memory.o miscnl.o \
	params.o path.o signals.o tty.o

PROJ = ../run/john ../run/unshadow ../run/unafs ../run/unique
PROJ_DOS = ../run/john.bin ../run/john.com \
	../run/unshadow.com ../run/unafs.com ../run/unique.com
PROJ_WIN32 = ../run/john.exe \
	../run/unshadow.exe ../run/unafs.exe ../run/unique.exe

default:
	@echo "To build John the Ripper, type:"
	@echo "	make clean SYSTEM"
	@echo "where SYSTEM can be one of the following:"
	@echo "linux-x86-mmx            Linux, x86 with MMX (best)"
	@echo "linux-x86-any            Linux, x86"
	@echo "linux-x86-any-a.out      Linux, x86, a.out binaries (obsolete)"
	@echo "linux-x86-64             Linux, AMD x86-64, 64-bit native"
	@echo "linux-x86-64-mmx         Linux, AMD x86-64, 32-bit with MMX"
	@echo "linux-alpha              Linux, Alpha"
	@echo "linux-sparc              Linux, SPARC 32-bit"
	@echo "linux-ppc32-altivec      Linux, PowerPC w/AltiVec (best)"
	@echo "linux-ppc32              Linux, PowerPC 32-bit"
#	@echo "linux-ppc64-altivec      Linux, PowerPC 64-bit w/AltiVec"
	@echo "linux-ppc64              Linux, PowerPC 64-bit"
	@echo "freebsd-x86-mmx          FreeBSD, x86 with MMX (best)"
	@echo "freebsd-x86-any          FreeBSD, x86"
	@echo "freebsd-x86-any-a.out    FreeBSD, x86, a.out binaries (obsolete)"
	@echo "freebsd-alpha            FreeBSD, Alpha"
	@echo "openbsd-x86-mmx          OpenBSD, x86 with MMX (best)"
	@echo "openbsd-x86-any          OpenBSD, x86"
	@echo "openbsd-x86-any-a.out    OpenBSD, x86, a.out binaries (obsolete)"
	@echo "openbsd-x86-64           OpenBSD, AMD x86-64"
	@echo "openbsd-alpha            OpenBSD, Alpha"
	@echo "openbsd-sparc64          OpenBSD, SPARC 64-bit (best)"
	@echo "openbsd-sparc            OpenBSD, SPARC 32-bit"
	@echo "openbsd-sparc-a.out      OpenBSD, SPARC 32-bit (obsolete)"
	@echo "openbsd-ppc32            OpenBSD, PowerPC 32-bit"
	@echo "openbsd-ppc64            OpenBSD, PowerPC 64-bit"
	@echo "openbsd-pa-risc          OpenBSD, PA-RISC"
	@echo "openbsd-vax              OpenBSD, VAX"
	@echo "netbsd-vax               NetBSD, VAX"
	@echo "solaris-sparc64-cc       Solaris, SPARC V9 64-bit, cc (best)"
	@echo "solaris-sparc64-gcc      Solaris, SPARC V9 64-bit, gcc"
	@echo "solaris-sparcv9-cc       Solaris, SPARC V9 32-bit, cc"
	@echo "solaris-sparcv8-cc       Solaris, SPARC V8 32-bit, cc"
	@echo "solaris-sparc-gcc        Solaris, SPARC 32-bit, gcc"
	@echo "solaris-x86-any          Solaris, x86, gcc"
	@echo "sco-x86-any-gcc          SCO, x86, gcc"
	@echo "sco-x86-any-cc           SCO, x86, cc"
	@echo "tru64-alpha              Tru64 (Digital UNIX, OSF/1), Alpha"
	@echo "aix-ppc32                AIX, PowerPC 32-bit"
	@echo "macosx-ppc32-altivec     Mac OS X, PowerPC w/AltiVec (best)"
	@echo "macosx-ppc32             Mac OS X, PowerPC 32-bit"
#	@echo "macosx-ppc64-altivec     Mac OS X, PowerPC 64-bit w/AltiVec"
	@echo "macosx-ppc64             Mac OS X 10.4+, PowerPC 64-bit"
	@echo "macosx-x86-mmx           Mac OS X, x86 with MMX"
	@echo "hpux-pa-risc-gcc         HP-UX, PA-RISC, gcc"
	@echo "hpux-pa-risc-cc          HP-UX, PA-RISC, ANSI cc"
	@echo "irix-mips64-r10k         IRIX, MIPS 64-bit (R10K) (best)"
	@echo "irix-mips64              IRIX, MIPS 64-bit"
	@echo "irix-mips32              IRIX, MIPS 32-bit"
	@echo "dos-djgpp-x86-mmx        DOS, DJGPP 2.x, x86 with MMX (best)"
	@echo "dos-djgpp-x86-any        DOS, DJGPP 2.x, x86"
	@echo "win32-cygwin-x86-mmx     Win32, Cygwin, x86 with MMX (best)"
	@echo "win32-cygwin-x86-any     Win32, Cygwin, x86"
	@echo "beos-x86-mmx             BeOS, x86 with MMX"
	@echo "beos-x86-any             BeOS, x86"
	@echo "generic                  Any other Unix-like system with gcc"

linux-x86-mmx:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS_MINIMAL) x86.o x86-mmx.o"

linux-x86-any:
	$(LN) x86-any.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o"

linux-x86-any-a.out:
	$(LN) x86-any.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DALIGN_LOG"

linux-x86-64:
	$(LN) x86-64.h arch.h
	$(MAKE) $(PROJ)

linux-x86-64-mmx:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS_MINIMAL) x86.o x86-mmx.o" \
		CFLAGS="$(CFLAGS) -m32" \
		ASFLAGS="$(ASFLAGS) -m32" \
		LDFLAGS="$(LDFLAGS) -m32"

linux-alpha:
	$(LN) alpha.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) alpha.o"

# This target is currently "undocumented" as ccc generates much slower
# code for the large unrolled loops in John; let's hope it gets fixed.
linux-alpha-ccc:
	$(LN) alpha.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) alpha.o" \
		CPP=ccc CC=ccc AS=ccc LD=ccc \
		CFLAGS="-c -Wf,-switch,noil_schedule" \
		OPT_NORMAL="-fast" \
		OPT_INLINE="-O2 -arch host"

linux-sparc:
	$(LN) sparc32.h arch.h
	$(MAKE) $(PROJ)

linux-ppc32-altivec:
	$(LN) ppc32alt.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) ppc-alti-linux.o" \
		OPT_INLINE="-finline-functions -finline-limit=4000"

linux-ppc32:
	$(LN) ppc32.h arch.h
	$(MAKE) $(PROJ)

# This is slightly slower than linux-ppc32-altivec for most hash types.
linux-ppc64-altivec:
	$(LN) ppc64alt.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) ppc-alti-linux.o" \
		CFLAGS="$(CFLAGS) -m64" \
		LDFLAGS="$(LDFLAGS) -m64" \
		OPT_INLINE="-finline-functions -finline-limit=4000"

linux-ppc64:
	$(LN) ppc64.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="$(CFLAGS) -m64" \
		LDFLAGS="$(LDFLAGS) -m64" \
		OPT_INLINE="-finline-functions -finline-limit=4000"

ppc-alti-linux.o: ppc-alti.c DES_bs_a.c
	$(CC) $(CFLAGS) $(OPT_INLINE) -maltivec ppc-alti.c -o $@

freebsd-x86-mmx:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS_MINIMAL) x86.o x86-mmx.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

freebsd-x86-any:
	$(LN) x86-any.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

freebsd-x86-any-a.out:
	$(LN) x86-any.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DALIGN_LOG -DBSD"

freebsd-alpha:
	$(LN) alpha.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) alpha.o"

openbsd-x86-mmx:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS_MINIMAL) x86.o x86-mmx.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

openbsd-x86-any:
	$(LN) x86-any.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		ASFLAGS="$(ASFLAGS) -DBSD"

openbsd-x86-any-a.out:
	$(LN) x86-any.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DALIGN_LOG -DBSD"

openbsd-x86-64:
	$(LN) x86-64.h arch.h
	$(MAKE) $(PROJ)

openbsd-alpha:
	$(LN) alpha.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) alpha.o"

openbsd-sparc64:
	$(LN) sparc64.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="$(CFLAGS) -m64 -mcpu=ultrasparc" \
		LDFLAGS="$(LDFLAGS) -m64"

openbsd-sparc:
	$(MAKE) use-openbsd-sparc HAMMER=use-openbsd-sparc NAIL=sparc.h
	$(LN) sparc.h arch.h
	$(MAKE) use-openbsd-sparc NAIL="$(PROJ)"

use-openbsd-sparc:
	$(MAKE) $(NAIL) \
		BENCH_DES_OBJS_DEPEND="$(BENCH_DES_OBJS_ORIG) sparc.o" \
		JOHN_OBJS="$(JOHN_OBJS_ORIG) sparc.o" \
		ASFLAGS="-c -DBSD"

openbsd-sparc-a.out:
	$(MAKE) use-openbsd-sparc-a.out \
		HAMMER=use-openbsd-sparc-a.out NAIL=sparc.h
	$(LN) sparc.h arch.h
	$(MAKE) use-openbsd-sparc-a.out NAIL="$(PROJ)"

use-openbsd-sparc-a.out:
	$(MAKE) $(NAIL) \
		BENCH_DES_OBJS_DEPEND="$(BENCH_DES_OBJS_ORIG) sparc.o" \
		JOHN_OBJS="$(JOHN_OBJS_ORIG) sparc.o" \
		ASFLAGS="-c -DUNDERSCORES -DBSD"

openbsd-ppc32:
	$(LN) ppc32.h arch.h
	$(MAKE) $(PROJ)

openbsd-ppc64:
	$(LN) ppc64.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="$(CFLAGS) -m64" \
		LDFLAGS="$(LDFLAGS) -m64" \
		OPT_INLINE="-finline-functions -finline-limit=4000"

openbsd-pa-risc:
	$(LN) pa-risc.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="-c -Wall -O3 -fomit-frame-pointer"

openbsd-vax:
	$(LN) vax.h arch.h
	$(MAKE) $(PROJ)

netbsd-vax:
	$(LN) vax.h arch.h
	$(MAKE) $(PROJ)

solaris-sparc64-cc:
	$(LN) sparc64.h arch.h
	$(MAKE) $(PROJ) \
		CPP=cc CC=cc AS=cc LD=cc \
		CFLAGS="-c -fast -xarch=native64" \
		LDFLAGS="-s -xarch=native64 -lc -lrt" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

solaris-sparc64-gcc:
	$(LN) sparc64.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="$(CFLAGS) -m64 -mcpu=ultrasparc" \
		LDFLAGS="$(LDFLAGS) -m64 -lrt"

solaris-sparc-any:
	$(MAKE) $(HAMMER) NAIL=sparc.h
	$(RM) arch.h
	ln -s sparc.h arch.h
	$(MAKE) $(HAMMER) NAIL="$(PROJ)"

solaris-sparcv9-cc:
	$(MAKE) solaris-sparc-any HAMMER=use-solaris-sparcv9-cc

solaris-sparcv8-cc:
	$(MAKE) solaris-sparc-any HAMMER=use-solaris-sparcv8-cc

solaris-sparc-gcc:
	$(MAKE) solaris-sparc-any HAMMER=use-solaris-sparc-gcc

use-solaris-sparcv9-cc:
	$(MAKE) $(NAIL) \
		BENCH_DES_OBJS_DEPEND="$(BENCH_DES_OBJS_ORIG) spro-sparc.o" \
		JOHN_OBJS="$(JOHN_OBJS_ORIG) spro-sparc.o" \
		CPP=cc CC=cc AS=cc LD=cc \
		CFLAGS="-c -xO4 -xarch=v8plusa -xchip=ultra" \
		LDFLAGS="-s -lc -lrt" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

use-solaris-sparcv8-cc:
	$(MAKE) $(NAIL) \
		BENCH_DES_OBJS_DEPEND="$(BENCH_DES_OBJS_ORIG) spro-sparc.o" \
		JOHN_OBJS="$(JOHN_OBJS_ORIG) spro-sparc.o" \
		CPP=cc CC=cc AS=cc LD=cc \
		CFLAGS="-c -xO4 -xarch=v8" \
		LDFLAGS="-s -lc -lrt" \
		OPT_NORMAL="" \
		OPT_INLINE="-xinline=s1,s2,s3,s4,s5,s6,s7,s8"

use-solaris-sparc-gcc:
	$(MAKE) $(NAIL) \
		BENCH_DES_OBJS_DEPEND="$(BENCH_DES_OBJS_ORIG) sparc.o" \
		JOHN_OBJS="$(JOHN_OBJS_ORIG) sparc.o" \
		LDFLAGS="$(LDFLAGS) -lrt"

sparc.h:
	$(RM) arch.h
	$(CC) $(CFLAGS) -DOS_TIMER -DOS_FLOCK -DDES_ASM detect.c
	$(LD) $(LDFLAGS) detect.o -o detect
	./sparc.sh "$(MAKE)" "$(HAMMER)" "$(BENCH_DES_OBJS_DEPEND)"

# Older versions of spro cc didn't support .S files directly
spro-sparc.o: sparc.S
	$(CPP) $(CPPFLAGS) sparc.S | $(SED) 's/% /%/g' > tmp.s
	$(AS) $(ASFLAGS) tmp.s -o spro-sparc.o
	$(RM) tmp.s

solaris-x86-any:
	$(RM) arch.h
	ln -s x86-any.h arch.h
	$(MAKE) $(PROJ) \
		SHELL=/bin/sh \
		JOHN_OBJS="$(JOHN_OBJS) solaris-x86.o" \
		LDFLAGS="$(LDFLAGS) -lc -lrt"

# Solaris x86 got a broken assembler, with line length restriction (and some
# other problems, that are worked around in x86.S)
solaris-x86.o: x86.S
	$(CPP) $(CPPFLAGS) -P -DDUMBAS x86.S | $(TR) \; \\n > tmp.s
	$(AS) $(ASFLAGS) tmp.s -o solaris-x86.o
	$(RM) tmp.s

sco-x86-any-gcc:
	$(RM) arch.h
	ln -s x86-any.h arch.h
	$(MAKE) $(PROJ) \
		SHELL=/bin/sh \
		JOHN_OBJS="$(JOHN_OBJS) sco-x86.o"

sco-x86-any-cc:
	$(RM) arch.h
	ln -s x86-any.h arch.h
	$(MAKE) $(PROJ) \
		SHELL=/bin/sh \
		JOHN_OBJS="$(JOHN_OBJS) sco-x86.o" \
		CPP=cc CC=cc AS=cc LD=cc \
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
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) digipaq-alpha.o" \
		CPP=cc CC=cc AS=cc LD=cc \
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
	$(MAKE) $(PROJ) \
		CPP=cc CC=cc AS=cc LD=cc \
		CFLAGS="-c -qunroll=2 -qarch=ppc -qchars=signed" \
		LDFLAGS="-s -lbsd" \
		OPT_NORMAL="-O2" \
		OPT_INLINE="-O3 -Q=99 -w"

macosx-ppc32-altivec:
	$(LN) ppc32alt.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) ppc-alti-macosx.o" \
		CPP=cc CC=cc AS=cc LD=cc \
		CFLAGS="-c -Wall -fomit-frame-pointer" \
		OPT_NORMAL="-fast -mcpu=7450" \
		OPT_INLINE="-fast -mcpu=7450 -finline-limit=4000"

macosx-ppc32:
	$(LN) ppc32.h arch.h
	$(MAKE) $(PROJ) \
		CPP=cc CC=cc AS=cc LD=cc \
		CFLAGS="-c -traditional-cpp" \
		OPT_NORMAL="-O2" \
		OPT_INLINE="-O3"

# This is slightly slower than macosx-ppc32-altivec for most hash types.
macosx-ppc64-altivec:
	$(LN) ppc64alt.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) ppc-alti-macosx.o" \
		CPP=cc CC=cc AS=cc LD=cc \
		CFLAGS="-c -m64 -Wall -fomit-frame-pointer" \
		LDFLAGS="-s -m64" \
		OPT_NORMAL="-fast" \
		OPT_INLINE="-fast -finline-limit=4000"

macosx-ppc64:
	$(LN) ppc64.h arch.h
	$(MAKE) $(PROJ) \
		CPP=cc CC=cc AS=cc LD=cc \
		CFLAGS="-c -Wall -fomit-frame-pointer -m64" \
		LDFLAGS="-s -m64" \
		OPT_NORMAL="-fast" \
		OPT_INLINE="-fast -finline-limit=4000"

ppc-alti-macosx.o: ppc-alti.c DES_bs_a.c
	$(CC) $(CFLAGS) $(OPT_INLINE) -faltivec -maltivec ppc-alti.c -o $@

macosx-x86-mmx:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o x86-mmx.o" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DBSD -DALIGN_LOG"
		CPP=cc CC=cc AS=cc LD=cc \
		CFLAGS="-c -traditional-cpp" \
		OPT_NORMAL="-O2" \
		OPT_INLINE="-O3"

hpux-pa-risc-gcc:
	$(LN) pa-risc.h arch.h
	$(MAKE) $(PROJ) \
		CFLAGS="-c -Wall -O3 -fomit-frame-pointer"

hpux-pa-risc-cc:
	$(LN) pa-risc.h arch.h
	$(MAKE) $(PROJ) \
		CPP=cc CC=cc AS=cc LD=cc \
		CFLAGS="-c -Aa -D_HPUX_SOURCE -DANSI_CPP" \
		LDFLAGS="-s" \
		OPT_NORMAL="+O2" \
		OPT_INLINE="+O3 +Oinline"

irix-mips64-r10k:
	$(LN) mips64.h arch.h
	$(MAKE) $(PROJ) \
		CPP=cc CC=cc AS=cc LD=cc \
		CFLAGS="-c -O2 -64 -mips4 -r10000 -signed" \
		LDFLAGS="-s -64 -mips4 -r10000" \
		OPT_NORMAL="-LNO:opt=1 -OPT:Olimit=2194" \
		OPT_INLINE="-INLINE:all"

irix-mips64:
	$(LN) mips64.h arch.h
	$(MAKE) $(PROJ) \
		CPP=cc CC=cc AS=cc LD=cc \
		CFLAGS="-c -O2 -64 -mips3 -signed" \
		LDFLAGS="-s -64 -mips3" \
		OPT_NORMAL="-LNO:opt=1 -OPT:Olimit=2194" \
		OPT_INLINE="-INLINE:all"

irix-mips32:
	$(LN) mips32.h arch.h
	$(MAKE) $(PROJ) \
		CPP=cc CC=cc AS=cc LD=cc \
		CFLAGS="-c -O2 -32 -signed" \
		LDFLAGS="-s -32" \
		OPT_NORMAL="-LNO:opt=1 -OPT:Olimit=2194" \
		OPT_INLINE="-INLINE:all"

dos-djgpp-x86-mmx:
	copy x86-mmx.h arch.h
	$(MAKE) $(PROJ_DOS) \
		JOHN_OBJS="$(JOHN_OBJS_MINIMAL) x86.o x86-mmx.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=2" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DALIGN_LOG"

dos-djgpp-x86-any:
	copy x86-any.h arch.h
	$(MAKE) $(PROJ_DOS) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=2" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES -DALIGN_LOG"

win32-cygwin-x86-mmx:
	$(CP) x86-mmx.h arch.h
	$(MAKE) $(PROJ_WIN32) \
		JOHN_OBJS="$(JOHN_OBJS_MINIMAL) x86.o x86-mmx.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=2" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES"

win32-cygwin-x86-any:
	$(CP) x86-any.h arch.h
	$(MAKE) $(PROJ_WIN32) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o" \
		CFLAGS="$(CFLAGS) -mpreferred-stack-boundary=2" \
		ASFLAGS="$(ASFLAGS) -DUNDERSCORES"

beos-x86-mmx:
	$(LN) x86-mmx.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS_MINIMAL) x86.o x86-mmx.o"

beos-x86-any:
	$(LN) x86-any.h arch.h
	$(MAKE) $(PROJ) \
		JOHN_OBJS="$(JOHN_OBJS) x86.o"

generic: generic.h
	$(RM) arch.h
	ln -s generic.h arch.h
	$(MAKE) $(PROJ)

generic.h:
	$(RM) arch.h
	$(CC) $(CFLAGS) detect.c
	$(LD) $(LDFLAGS) detect.o -o detect
	./best.sh "$(MAKE)" \
		"$(BENCH_DES_OBJS_DEPEND)" \
		"$(BENCH_DES_BS_OBJS_DEPEND)" \
		"$(BENCH_MD5_OBJS_DEPEND)" \
		"$(BENCH_BF_OBJS_DEPEND)"

bench: $(BENCH_OBJS)
	$(LD) $(LDFLAGS) $(BENCH_OBJS) -o bench

../run/john: $(JOHN_OBJS)
	$(LD) $(LDFLAGS) $(JOHN_OBJS) -o ../run/john

../run/unshadow: ../run/john
	$(RM) ../run/unshadow
	ln -s john ../run/unshadow

../run/unafs: ../run/john
	$(RM) ../run/unafs
	ln -s john ../run/unafs

../run/unique: ../run/john
	$(RM) ../run/unique
	ln -s john ../run/unique

../run/john.bin: $(JOHN_OBJS)
	$(LD) $(LDFLAGS) $(JOHN_OBJS) -o ../run/john.exe
	if exist ..\run\john.bin del ..\run\john.bin
	ren ..\run\john.exe john.bin

../run/john.com: john.com
	copy john.com ..\run\john.com

../run/unshadow.com: john.com
	copy john.com ..\run\unshadow.com

../run/unafs.com: john.com
	copy john.com ..\run\unafs.com

../run/unique.com: john.com
	copy john.com ..\run\unique.com

john.com: john.asm
	@echo Use Borland TASM/TLINK to make JOHN.COM

../run/john.exe: $(JOHN_OBJS)
	$(LD) $(JOHN_OBJS) -lkernel32 -o ../run/john.exe
	strip ../run/john.exe

../run/unshadow.exe: symlink.c
	$(CC) symlink.c -o ../run/unshadow.exe
	strip ../run/unshadow.exe

../run/unafs.exe: symlink.c
	$(CC) symlink.c -o ../run/unafs.exe
	strip ../run/unafs.exe

../run/unique.exe: symlink.c
	$(CC) symlink.c -o ../run/unique.exe
	strip ../run/unique.exe

# Inlining the S-boxes produces faster code, as long as they fit in the cache
# (that is, on RISC with at least 8 KB of L1 code cache).
DES_bs_b.o: DES_bs_b.c DES_bs_s.c DES_bs_n.c
	$(CC) $(CFLAGS) $(OPT_INLINE) DES_bs_b.c

# I prefer to distribute Matthew Kwan's S-box files unmodified...
DES_bs_s.c: sboxes.c
	$(SED) "s/unsigned long/ARCH_WORD/" sboxes.c > DES_bs_s.c

DES_bs_n.c: nonstd.c
	$(SED) "s/unsigned long/ARCH_WORD/" nonstd.c > DES_bs_n.c

DES_bs_a.c: nonstd.c ppc-alti.pl
	$(PERL) ppc-alti.pl nonstd.c > DES_bs_a.c

miscnl.o: misc.c
	$(CC) $(CFLAGS) $(OPT_NORMAL) -D_JOHN_MISC_NO_LOG misc.c -o miscnl.o

.c.o:
	$(CC) $(CFLAGS) $(OPT_NORMAL) $*.c

.S.o:
	$(AS) $(ASFLAGS) $*.S

# We don't have any files with .s suffix, this is for compiling in DOS only
.s.o:
	$(AS) $(ASFLAGS) $*.S

depend:
	makedepend -fMakefile.dep -Y *.c 2>> /dev/null

clean:
	$(RM) $(PROJ) $(PROJ_DOS) $(PROJ_WIN32)
	$(RM) ../run/john.exe *.o *.bak core
	$(RM) detect bench generic.h arch.h sparc.h tmp.s
	$(RM) DES_bs_s.c DES_bs_n.c DES_bs_a.c
	$(CP) $(NULL) Makefile.dep

include Makefile.dep
