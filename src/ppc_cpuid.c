#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/auxvec.h>
#include <asm/cputable.h>
 
// from http://freevec.org/function/altivec_runtime_detection_linux
long get_caps_ppc(int caps2)
{
	int result = 0;
	unsigned long buf[64];
	size_t count;
	int fd, i;
 
	fd = open("/proc/self/auxv", O_RDONLY);
	if (fd < 0) { return 0; }
	// loop on reading
	do {
		count = read(fd, buf, sizeof(buf));
		if (count < 0)
			break;
		for (i=0; i < (count / sizeof(unsigned long)); i += 2) {
			if (!caps2 && buf[i] == AT_HWCAP) {
				result = buf[i+1];
				goto out_close;
			} else if (caps2 && buf[i] == AT_HWCAP2) {
				result = buf[i+1];
				goto out_close;
			} else if (buf[i] == AT_NULL)
				goto out_close;
		}
	} while (count == sizeof(buf));
out_close:
	close(fd);
	return result;
}

void print_cap(long cap, long feature_bit, const char *feature) {
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
int main(int argc, char **argv) {
	long caps = get_caps_ppc(0);
	long caps2 = get_caps_ppc(2);

	if (argc < 2) {
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
	
	// ok, if arguments are set, we are calling this from configure, so we check for certain 'key' flags.
	
	if (!strcmp(argv[1], "PPC_FEATURE_HAS_ALTIVEC"))
		return !! (caps & PPC_FEATURE_HAS_ALTIVEC);
	if (!strcmp(argv[1], "PPC_FEATURE_HAS_VSX"))
		return !! (caps & PPC_FEATURE_HAS_VSX);
	if (!strcmp(argv[1], "PPC_FEATURE2_ARCH_2_07"))
		return !! (caps2 & PPC_FEATURE2_ARCH_2_07);
	printf ("Flag %s not handled\n", argv[1]);
	return 0;
}
