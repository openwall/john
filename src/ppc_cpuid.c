/*
 * This software is Copyright (c) 2017 jfoug : jfoug AT cox dot net
 *  Parts (concept using get_caps_ppc funtion) taken from code previously written by:
 *    Thomas Capricelli and or  Konstantinos Margaritis
 *    from http://freevec.org/function/altivec_runtime_detection_linux
 *    from http://www.freehackers.org/thomas/2011/05/13/how-to-detect-altivec-availability-on-linuxppc-at-runtime/
 *    however, code has been 100% replaced, minus the information on how to process it.
 *
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 *  this program can be used stand alone, for dumping all capabilities of a
 *  PowerPC system.  Simply run the process (or use command switch -?) and
 *  a full human readable dump will be performed.
 *  The code was also written to function inside john's configure script.
 *  There are 3 flags we ask about.  The program will query
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#if !defined(__gnu_linux__)
// we do not have a CPUID for non linux. Simply return that we have all required switches.
// if the user runs this on a machine which the SIMD is there, but FAILS to be new enough
// then they will have to add the --disable-simd flag to configure.
int main(int argc, char **argv) {
	if (argc==2) {
		if (!strcmp(argv[1], "PPC_FEATURE_HAS_ALTIVEC") ||
		    !strcmp(argv[1], "PPC_FEATURE_HAS_VSX") ||
		    !strcmp(argv[1], "PPC_FEATURE2_ARCH_2_07"))
		    return !!printf ("1\n");
	}
	printf ("This program only returns meaningful data on a Linux system\n");
	return 0;
}

#else
// this code is know to only work on linux

/* magic constants for auxillary table id's (the AT_HWCAP type numbers) */
#include <linux/auxvec.h>
/* magic constants PowerPC specific! for CPU CAPACITY bits (the PPC_FEATURE_HAS_ALTIVEC bits) */
#include <asm/cputable.h>

#if !defined(PPC) && !defined(powerpc) && !defined(__PPC__) && !defined(__powerpc__)
#error program specifically written to deal with CPU information on the PowerPC
#endif

void print_cap(unsigned long cap, unsigned long feature_bit, const char *feature) {
    char buf[128], *cp;
	sprintf (buf, "%-36s", feature);
	cp = strchr(buf, ' ');
	while (*cp == ' ')
		*cp++ = '.';
	if (cap & feature_bit)
		printf ("%s Present\n", buf);
	else
		printf ("%s Absent\n", buf);
}

int dump_full_listing(unsigned long caps, unsigned long caps2) {
	/* simply dump out all flags */
	printf ("\nAT_HWCAP features\n");
	print_cap (caps, PPC_FEATURE_32, "PPC_FEATURE_32");
	print_cap (caps, PPC_FEATURE_64, "PPC_FEATURE_64");
	print_cap (caps, PPC_FEATURE_601_INSTR, "PPC_FEATURE_601_INSTR");
	print_cap (caps, PPC_FEATURE_HAS_ALTIVEC, "PPC_FEATURE_HAS_ALTIVEC");
	print_cap (caps, PPC_FEATURE_HAS_FPU, "PPC_FEATURE_HAS_FPU");
	print_cap (caps, PPC_FEATURE_HAS_MMU, "PPC_FEATURE_HAS_MMU");
	print_cap (caps, PPC_FEATURE_HAS_4xxMAC, "PPC_FEATURE_HAS_4xxMAC");
	print_cap (caps, PPC_FEATURE_UNIFIED_CACHE, "PPC_FEATURE_UNIFIED_CACHE");
	print_cap (caps, PPC_FEATURE_HAS_SPE, "PPC_FEATURE_HAS_SPE");
	print_cap (caps, PPC_FEATURE_HAS_EFP_SINGLE, "PPC_FEATURE_HAS_EFP_SINGLE");
	print_cap (caps, PPC_FEATURE_HAS_EFP_DOUBLE, "PPC_FEATURE_HAS_EFP_DOUBLE");
	print_cap (caps, PPC_FEATURE_NO_TB, "PPC_FEATURE_NO_TB");
	print_cap (caps, PPC_FEATURE_POWER4, "PPC_FEATURE_POWER4");
	print_cap (caps, PPC_FEATURE_POWER5, "PPC_FEATURE_POWER5");
	print_cap (caps, PPC_FEATURE_POWER5_PLUS, "PPC_FEATURE_POWER5_PLUS");
	print_cap (caps, PPC_FEATURE_CELL, "PPC_FEATURE_CELL");
	print_cap (caps, PPC_FEATURE_BOOKE, "PPC_FEATURE_BOOKE");
	print_cap (caps, PPC_FEATURE_SMT, "PPC_FEATURE_SMT");
	print_cap (caps, PPC_FEATURE_ICACHE_SNOOP, "PPC_FEATURE_ICACHE_SNOOP");
	print_cap (caps, PPC_FEATURE_ARCH_2_05, "PPC_FEATURE_ARCH_2_05");
	print_cap (caps, PPC_FEATURE_PA6T, "PPC_FEATURE_PA6T");
	print_cap (caps, PPC_FEATURE_HAS_DFP, "PPC_FEATURE_HAS_DFP");
	print_cap (caps, PPC_FEATURE_POWER6_EXT, "PPC_FEATURE_POWER6_EXT");
	print_cap (caps, PPC_FEATURE_ARCH_2_06, "PPC_FEATURE_ARCH_2_06");
	print_cap (caps, PPC_FEATURE_HAS_VSX, "PPC_FEATURE_HAS_VSX");
	print_cap (caps, PPC_FEATURE_PSERIES_PERFMON_COMPAT, "PPC_FEATURE_PSERIES_PERFMON_COMPAT");
	print_cap (caps, PPC_FEATURE_TRUE_LE, "PPC_FEATURE_TRUE_LE");
	print_cap (caps, PPC_FEATURE_PPC_LE, "PPC_FEATURE_PPC_LE");
	printf ("\nAT_HWCAP2 features\n");
	print_cap (caps2,PPC_FEATURE2_ARCH_2_07, "PPC_FEATURE2_ARCH_2_07");
	print_cap (caps2,PPC_FEATURE2_HTM, "PPC_FEATURE2_HTM");
	print_cap (caps2,PPC_FEATURE2_DSCR, "PPC_FEATURE2_DSCR");
	print_cap (caps2,PPC_FEATURE2_EBB, "PPC_FEATURE2_EBB");
	print_cap (caps2,PPC_FEATURE2_ISEL, "PPC_FEATURE2_ISEL");
	print_cap (caps2,PPC_FEATURE2_TAR, "PPC_FEATURE2_TAR");
	print_cap (caps2,PPC_FEATURE2_VEC_CRYPTO, "PPC_FEATURE2_VEC_CRYPTO");
	printf("\n");
	return 0;
}

void config_handle_cap(unsigned long cap, unsigned long feature_bit) {
	if (cap & feature_bit) {
		/*
		 * we set error code of 1, and stdout "1\n"
		 * Used in configure script to detect HW capability bits.
		 */
		printf ("1\n");
		exit(1);
	}
}

int main(int argc, char **argv, char **envp) {
	unsigned long caps=0, caps2=0, *auxv;
	int i;

	// skip past ENV, to the auxv array of longs.
	// NOTE, using 'long' data type works properly on either 32 or 64 bit builds.
	while (*envp++ != NULL);
	for (i = 0, auxv = (unsigned long*)envp; auxv[i] != AT_NULL ; i += 2) {
		/* find data for AT_HWCAP or AT_HWCAP2 depending upon how called. */
		if (auxv[i] == AT_HWCAP)
			caps = auxv[i+1];
		else if (auxv[i] == AT_HWCAP2)
			caps2 = auxv[i+1];
	}

	if (argc < 2 || (argc == 2 && !strcmp(argv[1], "?")))
		return dump_full_listing(caps, caps2);

	// ok, if arguments other than -? are set, we are being called from
	// configure so check for certain 'key' flags configure cares about.

	if (!strcmp(argv[1], "PPC_FEATURE_HAS_ALTIVEC"))
		config_handle_cap(caps, PPC_FEATURE_HAS_ALTIVEC);
	if (!strcmp(argv[1], "PPC_FEATURE_HAS_VSX"))
		config_handle_cap(caps, PPC_FEATURE_HAS_VSX);
	if (!strcmp(argv[1], "PPC_FEATURE2_ARCH_2_07"))
		config_handle_cap(caps2, PPC_FEATURE2_ARCH_2_07);
	printf ("Flag %s not handled\n", argv[1]);
	return 0;
}
#endif
