/*
 * This software is Copyright (c) 2012 Lukas Odzioba <ukasz at openwall dot net>
 * and Copyright (c) 2012-2017 magnum
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * hccap2john processes hccap files into a format suitable for use with JtR.
 * hccap format was introduced by oclHashcat-plus (now renamed to hashcat),
 * and it is described here: https://hashcat.net/wiki/doku.php?id=hccap
 *
 * hccapx format is "version 2" of hccap and it is described here:
 * https://hashcat.net/wiki/doku.php?id=hccapx
 *
 * This tool handles both types.
 */
#if AC_BUILT
#include "autoconfig.h"
#endif

#include <stdio.h>
#include <stdlib.h>
// needs to be above sys/types.h and sys/stat.h for mingw, if -std=c99 used.
#include "jumbo.h"
#include <sys/types.h>
#include <string.h>
#include <sys/stat.h>
#include "os.h"
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#include <errno.h>
#include <assert.h>

#include "common.h"
#include "hccap.h"

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

void to_hex(char ssid[13], unsigned char *p)
{
	sprintf(ssid, "%02x%02x%02x%02x%02x%02x",p[0],p[1],p[2],p[3],p[4],p[5]);
}

static void print_hccap(hccap_t *cap, const char *filename)
{
	int i;
	unsigned char *w = (unsigned char *)cap;
	char sta_mac[18], ap_mac[18], gecos[13];
	char *base;

	to_hex(gecos, cap->mac1);
	to_hex(ap_mac, cap->mac1);
	to_hex(sta_mac, cap->mac2);

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
	hccapx_t hccapx;
	FILE *f;
	struct stat sb;
	size_t size, len;
	int is_x = 0;
	static int warn;

	f = fopen(filename, "r");
	if (stat(filename, &sb) == -1) {
		perror(filename);
		fprintf(stderr, "\n");
		fclose(f);
		return 0;
	}
	if (sb.st_size > 4) {
		char magic[5];

		if (fread(magic, 4, 1, f) != 1) {
			if (ferror(f) && errno) {
				perror(filename);
				fprintf(stderr, "\n");
			} else
				fprintf(stderr, "%s: file read error\n\n", filename);
			fclose(f);
			return 0;
		}
		magic[4] = 0;

		if (!strcmp(magic, "HCPX"))
			is_x = 1;

		fseek(f, 0, SEEK_SET);
	}

	if (is_x && sb.st_size % sizeof(hccapx) == 0) {
		size = sb.st_size;

		do {
			errno = 0;
			if (fread(&hccapx, sizeof(hccapx), 1, f) != 1) {
				if (ferror(f) && errno) {
					perror(filename);
					fprintf(stderr, "\n");
				} else
					fprintf(stderr, "%s: file read error\n\n", filename);
				fclose(f);
				return 0;
			}
			if (hccapx.signature != HCCAPC_MAGIC && !warn++)
				fprintf(stderr, "%s: Invalid hccapx magic seen\n", filename);

			memset(&hccap, 0, sizeof(hccap));
			len = MIN(hccapx.essid_len, 32);
			memcpy(hccap.essid, hccapx.essid, len);
			memcpy(hccap.mac1, hccapx.mac_ap, 6);
			memcpy(hccap.mac2, hccapx.mac_sta, 6);
			memcpy(hccap.nonce1, hccapx.nonce_sta, 32);
			memcpy(hccap.nonce2, hccapx.nonce_ap, 32);
			hccap.eapol_size = MIN(hccapx.eapol_len, sizeof(hccap.eapol));
			memcpy(hccap.eapol, hccapx.eapol, hccap.eapol_size);
			hccap.keyver = hccapx.keyver;
			memcpy(hccap.keymic, hccapx.keymic, 16);

			print_hccap(&hccap, filename);
			size -= sizeof(hccapx);
		} while (size);
	} else if (sb.st_size % sizeof(hccap) == 0) {
		size = sb.st_size;

		do {
			errno = 0;
			if (fread(&hccap, sizeof(hccap), 1, f) != 1) {
				if (ferror(f) && errno) {
					perror(filename);
					fprintf(stderr, "\n");
				} else
					fprintf(stderr, "%s: file read error\n\n", filename);
				fclose(f);
				return 0;
			}
			print_hccap(&hccap, filename);
			size -= sizeof(hccap);
		} while (size);
	} else {
		fprintf(stderr, "%s: file has wrong size%s\n\n", filename,
		        is_x ? " (hcapx magic found)" : "");
		fclose(f);
		return 0;
	}

	fclose(f);
	return 1;
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
	int i, ret = 0;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <hccap and/or hccapx file[s]>\n", argv[0]);
		return 1;
	}

	for (i = 1; i < argc; i++)
		ret |= process_file(argv[i]);

	return ret;
}
#endif
