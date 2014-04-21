/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall dot net>
 * and Copyright (c) 2012-2014 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * hccap2john processes hccap files into a format suitable for use with JtR.
 * hccap format was introduced by oclHashcat-plus, and it is described here:
 * http://hashcat.net/wiki/hccap
 *
 * hccap format => $WPAPSK$essid#base64 encoded hccap_t
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include "os.h"
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <errno.h>
#include <assert.h>
#include "common.h"
#include "memdbg.h"

#define HCCAP_SIZE		sizeof(hccap_t)
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

void to_dashed(char ssid[18], unsigned char *p)
{
	sprintf(ssid, "%02x-%02x-%02x-%02x-%02x-%02x",p[0],p[1],p[2],p[3],p[4],p[5]);
}

void to_compact(char ssid[18], unsigned char *p)
{
	sprintf(ssid, "%02x%02x%02x%02x%02x%02x",p[0],p[1],p[2],p[3],p[4],p[5]);
}

static void print_hccap(hccap_t * cap, const char *filename)
{
	int i;
	unsigned char *w = (unsigned char *)cap;
	char sta_mac[18], ap_mac[18], gecos[13];
	char *base;

	to_compact(gecos, cap->mac1);
	to_dashed(ap_mac, cap->mac1);
	to_dashed(sta_mac, cap->mac2);

	if ((base = strrchr(filename, '/')))
		filename = ++base;

	printf("%s:$WPAPSK$%s#", cap->essid, cap->essid);
	for (i = 36; i + 3 < sizeof(hccap_t); i += 3)
		code_block(&w[i], 1);
	code_block(&w[i], 0);
	printf(":%s:%s:%s::WPA", sta_mac, ap_mac, gecos);
	if (cap->keyver > 1)
		printf("%d", cap->keyver);
	printf(":%s\n", filename);
}

static int process_file(const char *filename)
{
	hccap_t hccap;
	FILE *f;
	struct stat sb;
	size_t size;

	f = fopen(filename, "r");
	if (stat(filename, &sb) == -1) {
		perror(filename);
		fprintf(stderr, "\n");
		return 0;
	}
	if (sb.st_size % sizeof(hccap)) {
		fprintf(stderr, "%s: file has wrong size\n\n", filename);
		return 0;
	}

	size = sb.st_size;

	do {
		errno = 0;
		if (fread(&hccap, sizeof(hccap), 1, f) != 1) {
			if (ferror(f) && errno) {
				perror(filename);
				fprintf(stderr, "\n");
			} else
				fprintf(stderr, "%s: file read error\n\n", filename);
			return 0;
		}
		print_hccap(&hccap, filename);
		fprintf(stderr, "\n");
		size -= sizeof(hccap);
	} while (size);

	fclose(f);

	return 1;
}

int hccap2john(int argc, char **argv)
{
	int i, ret = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <hccap file[s]>\n", argv[0]);
		return 1;
	}

	for (i = 1; i < argc; i++)
		ret |= process_file(argv[i]);

	return ret;
}
