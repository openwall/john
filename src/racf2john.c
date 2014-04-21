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
 * racfdump format => userid:$racf$*userid*deshash  */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include "memory.h"
#include "memdbg.h"

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

static void print_hex(unsigned char *str, int len)
{
        int i;
        for (i = 0; i < len; ++i)
                printf("%02X", str[i]);
}

static void print_userid(unsigned char *s)
{
	int i;
	for(i = 0; s[i] != 0x02; i++)
		printf("%c", e2a[s[i]]);
}


static void process_file(const char *filename)
{
	FILE *fp = fopen(filename, "r");
	struct stat sb;
	unsigned char *buffer;
	off_t size;
	unsigned char userid[9];
	int i, j, count;
	int offset;

	if(stat(filename, &sb) == -1) {
		perror("stat");
		exit(EXIT_FAILURE);
	}

	size = sb.st_size;
	buffer = (unsigned char *)mem_alloc(size);
	count = fread(buffer, size, 1, fp);
	assert(count == 1);

	for(i = 7; i < size - 62; i++) {
		if (buffer[i-7] == 0xc2 && buffer[i-6] == 0xc1 &&
			buffer[i-5] == 0xe2 && buffer[i-4] == 0xc5 &&
			buffer[i-3] == 0x40 && buffer[i-2] == 0x40 &&
			buffer[i-1] == 0x40 && buffer[i] == 0x40 &&
			buffer[i+1] == 0 && buffer[i+2] < 9 &&
			buffer[i+3] == 0 ) {
			offset = buffer[i+2];

			if (buffer[i+offset+44] == 8 && buffer[i+offset+53] == 0xd) {
				/* userid begins at index i + 4 */
				int index = 0;
				for(j = i + 4; buffer[j] != 0x02 && index < 9; j++)
					userid[index++] = buffer[j];
				userid[index] = 0x02;
				print_userid(userid);
				printf(":$racf$*");
				print_userid(userid);
				printf("*");
				/* DES hash at index (i + offset + 44) */
				print_hex(&buffer[i+offset+45], 8);
				printf("\n");
			}
		}
	}
	MEM_FREE(buffer);
}

int racf2john(int argc, char **argv)
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

