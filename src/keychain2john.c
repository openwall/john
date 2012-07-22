/* keepchain2john processes input Mac OS X keychain files into a format suitable
 * for use with JtR.
 *
 * This software is Copyright © 2012, Dhiru Kholia <dhiru.kholia at gmail.com>,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted.
 *
 * (c) 2004 Matt Johnston <matt @ ucc asn au>
 * This code may be freely used and modified for any purpose.
 *
 * How it works:
 *
 * The parts of the keychain we're interested in are "blobs" (see ssblob.h in
 * Apple's code). There are two types - DbBlobs and KeyBlobs.
 *
 * Each blob starts with the magic hex string FA DE 07 11 - so we search for
 * that. There's only one DbBlob (at the end of the file), and that contains the
 * file encryption key (amongst other things), encrypted with the master key.
 * The master key is derived purely from the user's password, and a salt, also
 * found in the DbBlob. PKCS #5 2 pbkdf2 is used for deriving the master key.
 *
 * DbBlob format:
 *	The offsets from the start of the blob are as follows:
 *	0 0xfade0711 - magic number
 *	4 version
 *	8 crypto-offset - offset of the encryption and signing key
 *	12 total len
 *	16 signature (16 bytes)
 *	32 sequence
 *	36 idletimeout
 *	40 lockonsleep flag
 *	44 salt (20 bytes)
 *	64 iv (8 bytes)
 *	72 blob signature (20)
 *
 * Output Format: filename:$keychain$*salt*iv*ciphertext */

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>

#define SALTLEN 20
#define IVLEN 8
#define CTLEN 48

static unsigned char *magic = (unsigned char*)"\xfa\xde\x07\x11";

/* helper functions for byte order conversions, header values are stored
 * in big-endian byte order */
static uint32_t fget32(FILE * fp)
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

static void process_file(const char *filename)
{
	FILE *fp;
	unsigned char buf[4];
	unsigned char salt[SALTLEN];
	unsigned char iv[IVLEN];
	unsigned char ct[CTLEN];
	long pos, cipheroff;
	size_t bytes;

	if (!(fp = fopen(filename, "rb"))) {
		fprintf(stderr, "! %s: %s\n", filename, strerror(errno));
		return;
	}
	fseek(fp, -4, SEEK_END);

	while(1) {
		fseek(fp, -8, SEEK_CUR);
		if(fread(buf, 4, 1, fp) == 0) {
			fprintf(stderr, "%s : Couldn't find db key. Is it a keychain file?\n", filename);
			exit(1);
		}
		if(!memcmp(buf, magic, 4))
			break;
	}

	pos = ftell(fp) - 4;

	// ciphertext offset
	fseek(fp, pos + 8, SEEK_SET);
	cipheroff = fget32(fp);

	// salt
	fseek(fp, pos + 44, SEEK_SET);
	bytes = fread(salt, SALTLEN, 1, fp);
	if(bytes != SALTLEN){
		fprintf(stderr, "Something went wrong - fread(salt) error\n");
		exit(1);
	}
	// IV
	fseek(fp, pos + 64, SEEK_SET);
	bytes = fread(iv, IVLEN, 1, fp);
	if(bytes != IVLEN){
		fprintf(stderr, "Something went wrong - fread(iv) error\n");
		exit(1);
	}
	// ciphertext
	fseek(fp, pos + cipheroff, SEEK_SET);
	bytes = fread(ct, CTLEN, 1, fp);
	if(bytes != CTLEN){
		fprintf(stderr, "Something went wrong - fread(ct) error\n");
		exit(1);
	}
	// output
	printf("%s:$keychain$*", filename);
	print_hex(salt, SALTLEN);
	printf("*");
	print_hex(iv, IVLEN);
	printf("*");
	print_hex(ct, CTLEN);
	printf("\n");

	fclose(fp);
}

int keychain2john(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		puts("Usage: keychain2john [keychain files]");
		return -1;
	}
	for (i = 1; i < argc; i++)
		process_file(argv[i]);

	return 0;
}
