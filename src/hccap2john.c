/*
* This software is Copyright (c) 2012 Lukas Odzioba <lukas dot odzioba at gmail dot com>
* and it is hereby released to the general public under the following terms:
* Redistribution and use in source and binary forms, with or without modification, are permitted.
*
* hccap2john processes input hccap files into a format suitable for use with JtR.
* hccap format was introduced by oclHashcat-plus, and it is described here: http://hashcat.net/wiki/hccap
 * racfdump format => $WPAPSK$essid#base64 encoded hccap_t
*/
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#include <errno.h>
#include <assert.h>
#include "common.h"

#define HCCAP_SIZE		392
typedef struct
{
  char          essid[36];
  unsigned char mac1[6];
  unsigned char mac2[6];
  unsigned char nonce1[32];
  unsigned char nonce2[32];
  unsigned char eapol[256];
  int           eapol_size;
  int           keyver;
  unsigned char keymic[16];
} hccap_t;

static void code_block(unsigned char *in, unsigned char b)
{
	putchar(itoa64[in[0] >> 2]);
	putchar(itoa64[((in[0] & 0x03) << 4) | (in[1] >> 4)]);
	if (b) {
		putchar(itoa64[((in[1] & 0x0f) << 2) | (in[2] >> 6)]);
		putchar(itoa64[in[2] & 0x3f]);
	} else
		putchar(itoa64[((in[1] & 0x0f) << 2)]);
}

static void print_hccap(hccap_t * cap)
{
	int i;
	unsigned char *w = (unsigned char *) cap;
	printf("$WPAPSK$%s#", cap->essid);
	for (i = 36; i + 3 < sizeof(hccap_t); i += 3)
		code_block(&w[i], 1);
	code_block(&w[i], 0);
	puts("");
}

static void process_file(const char *filename)
{
	hccap_t hccap;
	FILE *f;
	struct stat sb;

	f = fopen(filename, "r");
	if (stat(filename, &sb) == -1) {
		perror("stat");
		exit(EXIT_FAILURE);
	}
	if (sb.st_size != sizeof(hccap)) {
		puts("file has wrong size");
		exit(EXIT_FAILURE);
	}
	errno = 0;
	if (fread(&hccap, sizeof(hccap), 1, f) != 1) {
		if (ferror(f) && errno)
			perror("fread");
		else
			puts("file read error");
		exit(EXIT_FAILURE);
	}
	fclose(f);

	print_hccap(&hccap);
}

int hccap2john(int argc, char **argv)
{
	int i;

	assert(sizeof(hccap_t) == HCCAP_SIZE);

	if (argc < 2) {
		fprintf(stderr, "Usage: hccap2john [hccap format binary files]\n");
		return 1;
	}

	for (i = 1; i < argc; i++)
		process_file(argv[i]);

	return 0;
}
