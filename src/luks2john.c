/* luks.c
 *
 * hashkill - a hash cracking tool
 * Copyright (C) 2010 Milen Rangelov <gat3way@gat3way.eu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * gcc luks2john.c jumbo.c -o luks2john -lcrypto
 */


#if AC_BUILT
#include "autoconfig.h"
#else
#define _LARGEFILE64_SOURCE 1
#endif
#include "jumbo.h" // large file support
#include <stdio.h>
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#include <string.h>
#include "stdint.h"
#include <stdlib.h>
#include <sys/types.h>
#if !AC_BUILT || HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if !AC_BUILT || HAVE_ARPA_INET_H
#include <arpa/inet.h>
#else
#include "johnswap.h"
#define ntohl JOHNSWAP
#endif
#include "params.h"
#include <openssl/bio.h>
#include <openssl/evp.h>

#define LUKS_MAGIC_L        6
#define LUKS_CIPHERNAME_L   32
#define LUKS_CIPHERMODE_L   32
#define LUKS_HASHSPEC_L     32
#define UUID_STRING_L       40
#define LUKS_DIGESTSIZE 20
#define LUKS_SALTSIZE 32
#define LUKS_NUMKEYS 8

static int inline_thr = MAX_INLINE_SIZE;
#define MAX_THR (LINE_BUFFER_SIZE / 2 - 2 * PLAINTEXT_BUFFER_SIZE)

/* taken from LUKS on disk format specification */
static struct luks_phdr {
	char magic[LUKS_MAGIC_L];
	uint16_t version;
	char cipherName[LUKS_CIPHERNAME_L];
	char cipherMode[LUKS_CIPHERMODE_L];
	char hashSpec[LUKS_HASHSPEC_L];
	uint32_t payloadOffset;
	uint32_t keyBytes;
	char mkDigest[LUKS_DIGESTSIZE];
	char mkDigestSalt[LUKS_SALTSIZE];
	uint32_t mkDigestIterations;
	char uuid[UUID_STRING_L];
	struct {
		uint32_t active;
		uint32_t passwordIterations;
		char passwordSalt[LUKS_SALTSIZE];
		uint32_t keyMaterialOffset;
		uint32_t stripes;
	} keyblock[LUKS_NUMKEYS];
} myphdr;

static unsigned char *cipherbuf;
static int afsize;
static unsigned int bestslot = 2000;


static int af_sectors(int blocksize, int blocknumbers)
{
	int af_size;

	af_size = blocksize * blocknumbers;
	af_size = (af_size + 511) / 512;
	af_size *= 512;
	return af_size;
}

static void print_hex(unsigned char *str, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

static int hash_plugin_parse_hash(char *filename)
{
	FILE *myfile;
	int cnt;
	int readbytes;
	unsigned int bestiter = 0xFFFFFFFF;

	myfile = jtr_fopen(filename, "rb");

	if (!myfile) {
		fprintf(stderr, "\n%s : %s!\n", filename, strerror(errno));
		return -1;
	}

	if (fread(&myphdr, sizeof(struct luks_phdr), 1, myfile) < 1) {
		fprintf(stderr, "%s : file opening problem!\n", filename);
		fclose(myfile);
		return -1;
	}

	if (strcmp(myphdr.magic, "LUKS\xba\xbe") != 0) {
		fprintf(stderr, "%s : not a LUKS file / disk\n", filename);
		fclose(myfile);
		return -2;
	}

	if (strcmp(myphdr.cipherName, "aes") != 0) {
		fprintf(stderr, "%s : Only AES cipher supported. Used cipher: %s\n",
			filename, myphdr.cipherName);
	}

	for (cnt = 0; cnt < LUKS_NUMKEYS; cnt++) {
		if ((ntohl(myphdr.keyblock[cnt].passwordIterations) < bestiter)
		    && (ntohl(myphdr.keyblock[cnt].passwordIterations) > 1) &&
		    (ntohl(myphdr.keyblock[cnt].active) == 0x00ac71f3)) {
			bestslot = cnt;
			bestiter =
			    ntohl(myphdr.keyblock[cnt].passwordIterations);
		}
	}
	if (bestslot == 2000)
		goto bad;

	afsize =
	    af_sectors(ntohl(myphdr.keyBytes),
	    ntohl(myphdr.keyblock[bestslot].stripes));

	fprintf(stderr, "Best keyslot [%d]: %d keyslot iterations, %d stripes, %d mkiterations\n", bestslot, ntohl(myphdr.keyblock[bestslot].passwordIterations),ntohl(myphdr.keyblock[bestslot].stripes),ntohl(myphdr.mkDigestIterations));
	fprintf(stderr, "Cipherbuf size: %d\n", afsize);

	/* common handling */
	cipherbuf = malloc(afsize);
	if (cipherbuf == NULL) {
		fprintf(stderr, "%s:%d: malloc failed\n", __FUNCTION__, __LINE__);
		exit(EXIT_FAILURE);
	}
	jtr_fseek64(myfile, ntohl(myphdr.keyblock[bestslot].keyMaterialOffset) * 512,
	SEEK_SET);
	readbytes = fread(cipherbuf, afsize, 1, myfile);
	if (readbytes < 0) {
		free(cipherbuf);
		fclose(myfile);
		goto bad;
	}

	if (afsize < inline_thr) {
		BIO *bio, *b64;
		fprintf(stderr, "Generating inlined hash!\n");
		printf("$luks$1$%zu$", sizeof(myphdr));
		print_hex((unsigned char *)&myphdr, sizeof(myphdr));
		printf("$%d$", afsize);
		/* base-64 encode cipherbuf */
		b64 = BIO_new(BIO_f_base64());
		bio = BIO_new_fp(stdout, BIO_NOCLOSE);
		bio = BIO_push(b64, bio);
		BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
		BIO_write(bio, cipherbuf, afsize);
		if(BIO_flush(bio) <= 0) {
			fprintf(stderr, "%s : BIO_flush failed ;(\n", filename);
			fclose(myfile);
			return -3;
		}
		BIO_free_all(bio);
		printf("$");
		print_hex((unsigned char *)myphdr.mkDigest, LUKS_DIGESTSIZE);
		printf("\n");
		free(cipherbuf);
		goto good;
	}
	else {
		FILE *fp = jtr_fopen("dump", "wb");  // XXX make me unpredictable!
		fprintf(stderr, "Generating inlined hash with attached dump!\n");
		printf("$luks$0$%zu$", sizeof(myphdr));
		print_hex((unsigned char *)&myphdr, sizeof(myphdr));
		printf("$%d$", afsize);

		printf("%s$%s$", filename, "dump");
		print_hex((unsigned char *)myphdr.mkDigest, LUKS_DIGESTSIZE);
		printf("\n");

		fwrite(cipherbuf, afsize, 1, fp);
		free(cipherbuf);
		fclose(fp);

		goto good;
	}

good:
	fclose(myfile);
	return 0;
bad:
	printf("%s : parsing failed\n", filename);
	fclose(myfile);
	return 1;
}

static int usage(char *name)
{
	fprintf(stderr, "Usage: %s [-i <inline threshold>] [LUKS file(s) / disk(s)]\n"
	        "Default threshold is %d bytes (files smaller than that will be inlined)\n",
	        name, MAX_INLINE_SIZE);

	return EXIT_FAILURE;
}

int main(int argc, char **argv)
{
	int c;

	/* Parse command line */
	while ((c = getopt(argc, argv, "i:")) != -1) {
		switch (c) {
		case 'i':
			inline_thr = (int)strtol(optarg, NULL, 0);
			if (inline_thr > MAX_THR) {
				fprintf(stderr, "%s error: threshold %d, can't"
				        " be larger than %d\n", argv[0],
				        inline_thr, MAX_THR);
				return EXIT_FAILURE;
			}
			break;
		case '?':
		default:
			return usage(argv[0]);
		}
	}
	argc -= optind;
	if(argc == 0)
		return usage(argv[0]);
	argv += optind;

	while (argc--)
		hash_plugin_parse_hash(*argv++);

	return EXIT_SUCCESS;
}
