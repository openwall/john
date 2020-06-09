/* racf2john utility for processing IBM RACF binary database files
 * into a format suitable for use with JtR. Written in March of 2012
 * by Dhiru Kholia.
 *
 * This software is Copyright (c) 2012, Dhiru Kholia <dhiru.kholia at gmail.com>
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Thanks to Nigel Pentland <nigel at nigelpentland.net>, author of CRACF for
 * providing algorithm details and sample code.
 *
 * Thanks to Main Framed <mainframed767 at gmail.com> for providing test
 * vectors, algorithm details, RACF sample database  and requesting the
 * RACF cracker in the first place.
 *
 * racfdump format => userid:$racf$*userid*deshash
 *
 ***********************************************************************************
 * update   4/10/16  BeS - added support to dump racf-kdfaes style password10      *
 * hashes, in addition to fixing the extraction of the old algorithm so that       *
 * only active profiles are dumped.                                                *
 *                                                                                 *
 *  TODO - add option to dump password history (could be useful) hashes as well    *
 *                                                                                 *
 * racfdump format(racf-kdfaes) => userid:$racf$*userid*racf-kdfaes                *
 ***********************************************************************************
 *
 */

#if AC_BUILT
#include "autoconfig.h"
#endif

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
// jumbo.h needs to be above sys/types.h and sys/stat.h for mingw, if -std=c99 used.
#include "jumbo.h"
#include <sys/types.h>
#include <sys/stat.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#include <stdint.h>
#include "memory.h"

#define T_EMPTY 0
#define T_DES 1
#define T_KDFAES 2
#define false 0
#define true 1

// table to convert EBCDIC to ASCII
static unsigned char e2a[256] = {
	0,  1,  2,  3,156,  9,134,127,151,141,142, 11, 12, 13, 14, 15,
	16, 17, 18, 19,157,133,  8,135, 24, 25,146,143, 28, 29, 30, 31,
	128,129,130,131,132, 10, 23, 27,136,137,138,139,140,  5,  6,  7,
	144,145, 22,147,148,149,150,  4,152,153,154,155, 20, 21,158, 26,
	32,160,161,162,163,164,165,166,167,168, 91, 46, 60, 40, 43, 33,
	38,169,170,171,172,173,174,175,176,177, 93, 36, 42, 41, 59, 94,
	45, 47,178,179,180,181,182,183,184,185,124, 44, 37, 95, 62, 63,
	186,187,188,189,190,191,192,193,194, 96, 58, 35, 64, 39, 61, 34,
	195, 97, 98, 99,100,101,102,103,104,105,196,197,198,199,200,201,
	202,106,107,108,109,110,111,112,113,114,203,204,205,206,207,208,
	209,126,115,116,117,118,119,120,121,122,210,211,212,213,214,215,
	216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,
	123, 65, 66, 67, 68, 69, 70, 71, 72, 73,232,233,234,235,236,237,
	125, 74, 75, 76, 77, 78, 79, 80, 81, 82,238,239,240,241,242,243,
	92,159, 83, 84, 85, 86, 87, 88, 89, 90,244,245,246,247,248,249,
	48, 49, 50, 51, 52, 53, 54, 55, 56, 57,250,251,252,253,254,255
};

// pretty hex printing of resulting hash
static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02X", str[i]);
}

// assumes ebcdic input and prints result as ascii
static void print_ebcdic(unsigned char *s, int len)
{
	int i;
	for (i = 0; s[i] != 0x02; i++)
		printf("%c", e2a[s[i]]);
}

// found a valid user record, search for a DES or KDFAES password hash (no passphrases at this point)
static void process_user_rec(unsigned char * up, uint16_t len, unsigned char * pn, uint8_t pnl) {
	char passf[2] = {12, 100};  // only finds passwords (not phrases) at this time; both DES and KDFAES
	char fn;
	uint16_t fl;
	uint16_t x = 0;
	int found = T_EMPTY;
	int rpt = false;
	unsigned char * h1 = NULL;
	uint8_t h1_len = 0;
	unsigned char * h2 = NULL;
	uint8_t h2_len = 0;

	while (x < len) {
		fn = up[x];
		fl = (uint8_t)up[x+1];

		if ((fl >> 7) == 1) {  // handles repeating fields
			fl = ((up[x+1] << 24 ) + (up[x+2] << 16) + (up[x+3] << 8) + (up[x+4]));
			rpt = true;
		}

		if (!rpt && fn == passf[0]) { // do we have a password field? (both hash types)
			if (fl == 8) {
				h1 = &up[x+2];
				h1_len = 8;
				found = T_DES;
			}
		} else if (!rpt && fn == passf[1]) { // do we have an extended pass field (kdfaes)
			if (fl == 40) {
				found = T_KDFAES;
				h2 = &up[x+2];
				h2_len = 40;
			}
		}

		if (rpt) {
			x = x + fl + 5;
			rpt = false;
		} else {
			x = x + fl + 2;
		}
	}
	if (found == T_DES) {
		found = T_EMPTY;
		print_ebcdic(pn, pnl);
		printf(":$racf$*");
		print_ebcdic(pn, pnl);
		printf("*");
		print_hex(h1, h1_len);
		printf("\n");
	} else if (found == T_KDFAES) {
		found = T_EMPTY;
		print_ebcdic(pn, pnl);
		printf(":$racf$*");
		print_ebcdic(pn, pnl);
		printf("*");
		print_hex(h2, h2_len);
		print_hex(h1, h1_len);
		printf("\n");
	}
}

// process raw racf database file (assumed downloaded binary from z/os)
static void process_file(const char *filename)
{
	FILE *fp = fopen(filename, "r");
	struct stat sb;
	unsigned char *buffer = NULL;
	off_t size;
	int i, count = 0;
	unsigned char *user_prof;
	uint32_t user_rec_addr = 0;
	uint16_t user_rec_len = 0;
	uint16_t header_len = 0;
	uint16_t profile_len = 0;
	uint8_t profile_name_len = 0;
	unsigned char *profile_name = 0;

	if (stat(filename, &sb) == -1) {
		perror("stat");
		exit(EXIT_FAILURE);
	}

	size = sb.st_size;
	if (size == 0)
		goto cleanup;

	buffer = (unsigned char *)malloc(size);
	if (!buffer) {
		fprintf(stderr, "malloc failed in process_file, aborting!\n");
		exit(-1);
	}
	count = fread(buffer, size, 1, fp);
	assert(count == 1);

	// our initial check below checks 7 char ahead of our i ctr, so start at i=7
	i = 7;

	// this brute force finds profiles, whether active or disabled and dumps their primary hashes
	while (i < size) {
		if (buffer[i-7] == 0xc2 && buffer[i-6] == 0xc1 &&               //"BA"
				buffer[i-5] == 0xe2 && buffer[i-4] == 0xc5 &&   //"SE"
				buffer[i-3] == 0x40 && buffer[i-2] == 0x40 &&   //"  "
				buffer[i-1] == 0x40 && buffer[i] == 0x40 &&     //"  "
				buffer[i+1] == 0 && buffer[i+2] < 9 &&          //null + total namelen < 9
				buffer[i+3] == 0 ) {                            //null

			user_rec_addr = i-16;
			user_rec_len = (((uint8_t)buffer[i-9]) << 8) + (uint8_t)buffer[i-8];
			profile_name_len = (uint8_t)buffer[i+2];
			profile_name = &buffer[i+4];
			header_len = (i + 4 + profile_name_len) - user_rec_addr;
			profile_len = user_rec_len - header_len;
			user_prof = &buffer[user_rec_addr + header_len];
			if (user_prof[0] == 0x02) {
				process_user_rec(user_prof, profile_len, profile_name, profile_name_len);
			}
		}
		i++;
	}

cleanup:
	// clean up and exit
	MEM_FREE(buffer);
	fclose(fp);
}

#ifdef HAVE_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int fd;
	char name[] = "/tmp/libFuzzer-XXXXXX";

	fd = mkstemp(name);
	if (fd < 0) {
		fprintf(stderr, "Problem detected while creating the input file, %s, aborting!\n", strerror(errno));
		exit(-1);
	}
	write(fd, data, size);
	close(fd);
	process_file(name);
	remove(name);

	return 0;
}
#else
int main(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		puts("Usage: racf2john [RACF binary files]");
		return -1;
	}
	for (i = 1; i < argc; i++)
		process_file(argv[i]);

	return 0;
}
#endif
