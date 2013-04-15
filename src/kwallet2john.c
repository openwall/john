/*
 * This software is Copyright (c) 2013, Narendra Kangralkar <narendrakangralkar
 * at gmail.com> and Dhiru Kholia <dhiru at openwall.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * Output Format: $kwallet$encrypted_size$encrypted_data
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "stdint.h"
#include "misc.h"

#define KWMAGIC 			"KWALLET\n\r\0\r\n"
#define KWMAGIC_LEN 			12

#define KWALLET_VERSION_MAJOR           0
#define KWALLET_VERSION_MINOR           0

#define KWALLET_CIPHER_BLOWFISH_CBC     0
#define KWALLET_CIPHER_3DES_CBC         1	/* unsupported */

#define KWALLET_HASH_SHA1               0
#define KWALLET_HASH_MD5                1	/* unsupported */
#define N 				128
#define MIN(x,y) ((x) < (y) ? (x) : (y))

static int count;
static unsigned char encrypted[0x10000];
static long encrypted_size;


/* helper functions for byte order conversions, header values are stored
 * in big-endian byte order
 */
static uint32_t fget32_(FILE * fp)
{
	uint32_t v = fgetc(fp) << 24;
	v |= fgetc(fp) << 16;
	v |= fgetc(fp) << 8;
	v |= fgetc(fp);
	return v;
}


static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}


static void process_file(const char *fname)
{
	FILE *fp;
	unsigned char buf[1024];
	long size, offset = 0;
	size_t i, j;
	uint32_t n;
	const char *extension[]={".kwl"};
	char *bname;

	if (!(fp = fopen(fname, "rb"))) {
		fprintf(stderr, "%s : %s\n", fname, strerror(errno));
		return;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	fseek(fp, 0, SEEK_SET);

	count = fread(buf, KWMAGIC_LEN, 1, fp);
	if (memcmp(buf, KWMAGIC, KWMAGIC_LEN) != 0) {
		fprintf(stderr, "%s : Not a KDE KWallet file!\n", fname);
		exit(1);
	}

	offset += KWMAGIC_LEN;
	count = fread(buf, 4, 1, fp);
	offset += 4;

	/* First byte is major version, second byte is minor version */
	if (buf[0] != KWALLET_VERSION_MAJOR) {
		fprintf(stderr, "%s : Unknown version!\n", fname);
		exit(2);
	}

	if (buf[1] != KWALLET_VERSION_MINOR) {
		fprintf(stderr, "%s : Unknown version!\n", fname);
		exit(3);
	}

	if (buf[2] != KWALLET_CIPHER_BLOWFISH_CBC) {
		fprintf(stderr, "%s : Unsupported cipher\n", fname);
		exit(4);
	}

	if (buf[3] != KWALLET_HASH_SHA1) {
		fprintf(stderr, "%s : Unsupported hash\n", fname);
		exit(5);
	}

	/* Read in the hashes */
	n = fget32_(fp);
	if (n > 0xffff) {
		fprintf(stderr, "%s : sanity check failed!\n", fname);
		exit(6);
	}
	offset += 4;
	for (i = 0; i < n; ++i) {
		uint32_t fsz;

		count = fread(buf, 16, 1, fp);
		offset += 16;
		fsz = fget32_(fp);
		offset += 4;
		for (j = 0; j < fsz; ++j) {
			count = fread(buf, 16, 1, fp);
			offset += 16;

		}
	}

	/* Read in the rest of the file. */
	encrypted_size = size - offset;
	count = fread(encrypted, encrypted_size, 1, fp);

	if ((encrypted_size % 8) != 0) {
		fprintf(stderr, "%s : invalid file structure!\n", fname);
		exit(7);
	}

	bname = strip_suffixes(basename(fname), extension, 1);

	printf("%s:$kwallet$%ld$", bname, encrypted_size);
	print_hex(encrypted, encrypted_size);
	printf(":::::%s\n", fname);

	fclose(fp);
}


int kwallet2john(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s <.kwl file(s)>\n", argv[0]);
		exit(-1);
	}

	for (i = 1; i < argc; i++)
		process_file(argv[i]);

	return 0;
}
